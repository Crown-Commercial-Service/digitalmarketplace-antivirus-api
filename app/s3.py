import datetime
from itertools import chain
import logging
import re
import sys

from flask import current_app, request

from dmutils.email.dm_notify import DMNotifyClient
from dmutils.email.exceptions import EmailError
from dmutils.timing import logged_duration_for_external_request as log_external_request, logged_duration

from app.clam import get_clamd_socket, UnknownClamdError


_filename_re = re.compile(r'^\s*filename=("?)(.+?)\1\s*$')


def _filename_from_content_disposition(content_disposition):
    return next(
        (match.group(2) for match in (_filename_re.match(sect) for sect in content_disposition.split(";")) if match),
        None,
    )


def _prefixed_tag_values_from_tag_set(tag_set, prefix):
    return {tag["Key"]: tag["Value"] for tag in tag_set if tag["Key"].startswith(prefix)}


def _tag_set_omitting_prefixed(tag_set, prefix):
    return [tag for tag in tag_set if not tag["Key"].startswith(prefix)]


# See https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/allocation-tag-restrictions.html
_invalid_tag_chars_re = re.compile(r"[^-+=.:/\w\s]", flags=re.ASCII)


def _tag_set_updated_with_dict(tag_set, update_dict):
    return list(chain(
        (kv for kv in tag_set if kv["Key"] not in update_dict),
        ({"Key": k, "Value": _invalid_tag_chars_re.sub("_", v)} for k, v in update_dict.items()),
    ))


_nonhex_re = re.compile("[^0-9a-f]")


def _normalize_hex(value):
    return _nonhex_re.sub("", value.lower())


def scan_and_tag_s3_object(
    s3_client,
    s3_bucket_name,
    s3_object_key,
    s3_object_version,
    sns_message_id=None,
):
    with logged_duration(
        logger=current_app.logger,
        message=lambda _: (
            "Handled bucket {s3_bucket_name} key {s3_object_key} version {s3_object_version}"
            if sys.exc_info()[0] is None else
            # need to literally format() the exception into message as it's difficult to get it injected into extra
            "Failed handling {{s3_bucket_name}} key {{s3_object_key}} version {{s3_object_version}}: {!r}".format(
                sys.exc_info()[1]
            )
        ),
        log_level=logging.INFO,
        condition=True,
    ) as log_context:
        base_log_context = {
            "s3_bucket_name": s3_bucket_name,
            "s3_object_key": s3_object_key,
            "s3_object_version": s3_object_version,
        }
        log_context.update(base_log_context)

        # TODO abort if file too big?

        with log_external_request(
            "S3",
            "get object tagging [{s3_bucket_name}/{s3_object_key} versionId {s3_object_version}]",
            logger=current_app.logger,
        ) as log_context_s3:
            log_context_s3.update(base_log_context)
            tagging_tag_set = s3_client.get_object_tagging(
                Bucket=s3_bucket_name,
                Key=s3_object_key,
                VersionId=s3_object_version,
            )["TagSet"]

        av_status = _prefixed_tag_values_from_tag_set(tagging_tag_set, "avStatus.")

        if av_status.get("avStatus.result") is None:
            current_app.logger.info(
                "Object version {s3_object_version} has no 'avStatus.result' tag - will scan...",
                extra={
                    **base_log_context,
                    "av_status": av_status,
                },
            )
        else:
            current_app.logger.info(
                "Object version {s3_object_version} already has 'avStatus.result' "
                "tag: {existing_av_status_result!r}",
                extra={
                    **base_log_context,
                    "existing_av_status_result": av_status["avStatus.result"],
                    "existing_av_status": av_status,
                },
            )
            return av_status, False, None

        clamd_client = get_clamd_socket()
        # first check our clamd is available - there's no point in going and fetching the object if we can't do
        # anything with it. allow a raised exception to bubble up as a 500, which seems the most appropriate thing
        # in this case
        clamd_client.ping()

        # the following two requests (to S3 for the file contents and to clamd for scanning) don't really happen
        # sequentially as we're going to attempt to stream the data received from one into the other (by passing
        # the StreamingBody file-like object from this response into .instream(...)), so these logged_duration
        # sections do NOT *directly* correspond to the file being downloaded and then the file being scanned. The
        # two activities will overlap in time, something that isn't expressible with logged_duration
        with log_external_request(
            "S3",
            "initiate object download [{s3_bucket_name}/{s3_object_key} versionId {s3_object_version}]",
            logger=current_app.logger,
        ) as log_context_s3:
            log_context_s3.update(base_log_context)
            s3_object = s3_client.get_object(
                Bucket=s3_bucket_name,
                Key=s3_object_key,
                VersionId=s3_object_version,
            )

        file_name = _filename_from_content_disposition(s3_object.get("ContentDisposition") or "")

        with logged_duration(
            logger=current_app.logger,
            message=lambda _: (
                "Scanned {file_length}byte file '{file_name}', result {clamd_result}"
                if sys.exc_info()[0] is None else
                # need to literally format() exception into message as it's difficult to get it injected into extra
                "Failed scanning {{file_length}}byte file '{{file_name}}': {!r}".format(
                    sys.exc_info()[1]
                )
            ),
            log_level=logging.INFO,
            condition=True,
        ) as log_context_clamd:
            log_context_clamd.update({
                "file_length": s3_object["ContentLength"],
                "file_name": file_name or "<unknown>",
            })
            clamd_result = clamd_client.instream(s3_object["Body"])["stream"]
            log_context_clamd["clamd_result"] = clamd_result

        if clamd_result[0] == "ERROR":
            # let's hope this was a transient error and a later attempt may succeed. hard to know what else to do
            # in this case - tagging a file with "ERROR" would prevent further attempts.
            raise UnknownClamdError(f"clamd did not successfully scan file: {clamd_result!r}")

        with logged_duration(
            logger=current_app.logger,
            message=lambda _: (
                "Fetched clamd version string: {clamd_version}"
                if sys.exc_info()[0] is None else
                # need to literally format() exception into message as it's difficult to get it injected into extra
                "Failed fetching clamd version string: {!r}".format(
                    sys.exc_info()[1]
                )
            ),
            log_level=logging.DEBUG,
        ) as log_context_clamd:
            # hypothetically there is a race condition between the time of scanning the file and fetching the
            # version here when freshclam could give us a new definition file, making this information incorrect,
            # but it's a very small possibility
            clamd_version = clamd_client.version()
            log_context_clamd.update({"clamd_version": clamd_version})

        # we namespace all keys set as part of an avStatus update with an "avStatus." prefix, intending that all
        # of these keys are only ever set or removed together as they are all information about the same scanning
        # decision
        new_av_status = {
            "avStatus.result": "pass" if clamd_result[0] == "OK" else "fail",
            "avStatus.clamdVerStr": clamd_version,
            "avStatus.ts": datetime.datetime.utcnow().isoformat(),
        }

        # Now we briefly re-check the object's tags to ensure they weren't set by something else while we were
        # scanning. Note the impossibility of avoiding all possible race conditions as S3's API doesn't allow any
        # form of locking. What we *can* do is make the possible time period between check-tags and set-tags as
        # small as possible...
        with log_external_request(
            "S3",
            "get object tagging [{s3_bucket_name}/{s3_object_key} versionId {s3_object_version}]",
            logger=current_app.logger,
        ) as log_context_s3:
            log_context_s3.update(base_log_context)
            tagging_tag_set = s3_client.get_object_tagging(
                Bucket=s3_bucket_name,
                Key=s3_object_key,
                VersionId=s3_object_version,
            )["TagSet"]

        av_status = _prefixed_tag_values_from_tag_set(tagging_tag_set, "avStatus.")

        if av_status.get("avStatus.result") is not None:
            current_app.logger.warning(
                "Object was tagged with new 'avStatus.result' ({existing_av_status_result!r}) while we were "
                "scanning. Not applying our own 'avStatus' ({unapplied_av_status_result!r})",
                extra={
                    "existing_av_status_result": av_status["avStatus.result"],
                    "unapplied_av_status_result": new_av_status["avStatus.result"],
                    "existing_av_status": av_status,
                    "unapplied_av_status": new_av_status,
                },
            )
            return av_status, False, new_av_status

        tagging_tag_set = _tag_set_updated_with_dict(
            _tag_set_omitting_prefixed(tagging_tag_set, "avStatus."),
            new_av_status,
        )

        with log_external_request(
            "S3",
            "put object tagging [{s3_bucket_name}/{s3_object_key} versionId {s3_object_version}]",
            logger=current_app.logger,
        ) as log_context_s3:
            log_context_s3.update(base_log_context)
            s3_client.put_object_tagging(
                Bucket=s3_bucket_name,
                Key=s3_object_key,
                VersionId=s3_object_version,
                Tagging={"TagSet": tagging_tag_set},
            )

        if clamd_result[0] != "OK":
            # TODO? attempt to rectify the situation:
            # TODO? if this is (still) current version of object:
            # TODO?     S3: find most recent version of object which is tagged "good"
            # TODO?     if there is no such version:
            # TODO?         S3: upload fail whale?
            # TODO?     else copy that version to become new "current" ver for this key, ensuring to copy its tags
            # TODO?         note the impossibility of doing this without some race conditions

            notify_client = DMNotifyClient(current_app.config["DM_NOTIFY_API_KEY"])

            if (
                len(clamd_result) >= 2 and
                clamd_result[1].lower() in map(str.lower, current_app.config["DM_EICAR_TEST_SIGNATURE_RESULT_STRINGS"])
            ):
                notify_kwargs = {
                    # we'll use the s3 ETag of the file as the notify ref - it will be the only piece of information
                    # that will be shared knowledge between a functional test and the application yet also allow the
                    # test to differentiate the results of its different test runs, allowing it to easily check for
                    # the message being sent
                    "reference": "eicar-found-{}-{}".format(
                        _normalize_hex(s3_object["ETag"]),
                        current_app.config["DM_ENVIRONMENT"],
                    ),
                    "to_email_address": current_app.config["DM_EICAR_TEST_SIGNATURE_VIRUS_ALERT_EMAIL"],
                }
            else:
                notify_kwargs = {
                    "to_email_address": current_app.config["DM_DEVELOPER_VIRUS_ALERT_EMAIL"],
                }

            try:
                notify_client.send_email(
                    template_name_or_id="developer_virus_alert",
                    personalisation={
                        "bucket_name": s3_bucket_name,
                        "object_key": s3_object_key,
                        "object_version": s3_object_version,
                        "file_name": file_name or "<unknown>",
                        "clamd_output": ", ".join(clamd_result),
                        "sns_message_id": sns_message_id or "<N/A>",
                        "dm_trace_id": getattr(request, "trace_id", None) or "<unknown>",
                    },
                    **notify_kwargs,
                )
            except EmailError as e:
                current_app.logger.error(
                    "Failed to send developer_virus_alert email after scanning "
                    "{s3_bucket_name}/{s3_object_key} versionId {s3_object_version}: {e}",
                    extra={
                        **base_log_context,
                        "e": str(e),
                    },
                )
                # however we probably don't want this to cause a 500 because the main task has been completed - retrying
                # it won't work and e.g. we eill want to signify to SNS that it should not attempt to re-send this
                # message

        return av_status, True, new_av_status
