import datetime
from functools import lru_cache
from itertools import chain
import json
import logging
import re
import sys

import boto3
from flask import abort, jsonify, current_app, request
from lxml.etree import fromstring as etree_fromstring, ParseError
import requests

import validatesns

from dmutils.email.dm_notify import DMNotifyClient
from dmutils.email.exceptions import EmailError
from dmutils.timing import logged_duration_for_external_request as log_external_request, logged_duration

from app.callbacks import callbacks
from app.clam import get_clamd_socket


@callbacks.route('/')
@callbacks.route('')
def callbacks_root():
    return jsonify(status='ok'), 200


def _get_request_body_json():
    if request.content_type.split(";")[0] not in (  # allowing for an encoding following the semicolon
        "application/json",
        "text/plain",
    ):
        abort(400, "Unexpected Content-Type, expecting 'application/json' or 'text/plain'")

    data = request.get_json(force=True)

    if data is None:
        abort(400, "Invalid JSON; must be a valid JSON object")

    return data


def _handle_subscription_confirmation(body_json, supported_topic_name):
    topic_arn = body_json["TopicArn"]
    topic_name = topic_arn.split(":")[-1]
    # check it's for the right topic
    if topic_name != supported_topic_name:
        current_app.logger.warning(
            "Received SubscriptionConfirmation request for unrecognized topic name {topic_name} in {topic_arn}",
            extra={
                "topic_name": topic_name,
                "topic_arn": topic_arn,
            },
        )
        abort(400, f"Unrecognized topic name {topic_name!r}")

    # send a request to provided url, ensuring sufficient logging
    try:
        with logged_duration(
            logger=current_app.logger,
            message=lambda _: (
                "Made GET request to {target_url} to confirm subscription to topic {topic_arn}"
                if sys.exc_info()[0] is None else
                # need to literally format() exception into message as it's difficult to get it injected into extra
                "Failed to make GET request to {{target_url}} to confirm subscription to {{topic_arn}}: {!r}".format(
                    sys.exc_info()[1]
                )
            ),
            log_level=logging.INFO,
            condition=True,
        ) as log_context:
            confirmation_url = body_json["SubscribeURL"]
            log_context.update({
                "target_url": confirmation_url,
                "topic_arn": topic_arn,
            })
            confirmation_response = requests.get(confirmation_url)
            confirmation_response.raise_for_status()
    except requests.exceptions.RequestException:
        abort(400, f"SubscriptionConfirmation request to {confirmation_url!r} failed")

    # check we received what we expected from url
    subscription_arn = confirmation_request_id = None
    try:
        confirmation_etree = etree_fromstring(confirmation_response.content)
        # though the xml is (hopefully) supplied with an xmlns, we want to be quite lenient with what we accept. but
        # lxml/xpath doesn't like us omitting the namespace if one is specified, so I'm simply assigning the toplevel
        # namespace (.nsmap(None)) to a short label `n` to allow us to specify xpath expressions with as much brevity
        # as possible.
        namespaces = {"n": confirmation_etree.nsmap[None]}
        subscription_arn = confirmation_etree.xpath(
            "normalize-space(string(/n:ConfirmSubscriptionResponse/n:ConfirmSubscriptionResult/n:SubscriptionArn))",
            namespaces=namespaces,
        )
        confirmation_request_id = confirmation_etree.xpath(
            "normalize-space(string(/n:ConfirmSubscriptionResponse/n:ResponseMetadata/n:RequestId))",
            namespaces=namespaces,
        )
    except ParseError as e:
        current_app.logger.warning(e)

    if not subscription_arn:
        current_app.logger.warning("SubscriptionConfirmation response parsing failed")
        abort(400, f"SubscriptionConfirmation request to {confirmation_url!r}: response parsing failed")
    else:
        current_app.logger.info(
            "SubscriptionConfirmation succeeded for subscription {subscription_arn}",
            extra={
                "subscription_arn": subscription_arn,
                "confirmation_request_id": confirmation_request_id,
            },
        )

    return jsonify(status='ok'), 200


@lru_cache()
def _get_certificate(url):
    with logged_duration(
        logger=current_app.logger,
        message=lambda _: (
            "Fetched certificate for SNS signature validation from {target_url}"
            if sys.exc_info()[0] is None else
            # need to literally format() the exception into the message as it's difficult to get it injected into extra
            "Failed to fetch certificate for SNS signature validation from {{target_url}}: {!r}".format(
                sys.exc_info()[1]
            )
        ),
        log_level=logging.INFO,
        condition=True,
    ) as log_context:
        log_context.update({"target_url": url})
        response = requests.get(url)
        response.raise_for_status()
        return response.content


# deliberately omitting the optional trailing .cn that's included in validatesns's default regex
VALIDATION_CERTIFICATE_URL_REGEX = r"^https://[-a-z0-9.]+\.amazonaws\.com/"
# give request extra headroom of a minute here over the "maximum possible" age of an hour - let's not get bitten just
# because of a bit of clock skew
VALIDATION_MAX_AGE = datetime.timedelta(hours=1, minutes=1)


_filename_re = re.compile(r'^\s*filename=("?)(.+?)\1\s*$')


def _filename_from_content_disposition(content_disposition):
    return next(
        (match.group(2) for match in (_filename_re.match(sect) for sect in content_disposition.split(";")) if match),
        None,
    )


def _tag_value_from_tag_set(tag_set, tag_key):
    return next((tag["Value"] for tag in tag_set if tag["Key"] == tag_key), None)


def _tag_set_updated_with_value(tag_set, tag_key, tag_value):
    return list(chain(
        (kv for kv in tag_set if kv["Key"] != tag_key),
        ({"Key": tag_key, "Value": tag_value},),
    ))


class UnknownClamdError(Exception):
    pass


@callbacks.route("/sns/s3/uploaded", methods=['POST'])
def handle_s3_sns():
    body_dict = _get_request_body_json()

    # check SNS signature authenticity
    try:
        validatesns.validate(
            body_dict,
            get_certificate=_get_certificate,
            certificate_url_regex=VALIDATION_CERTIFICATE_URL_REGEX,
            max_age=VALIDATION_MAX_AGE,
        )
    except (validatesns.ValidationError, requests.exceptions.RequestException) as e:
        current_app.logger.warning("SNS request body failed signature validation: {validation_error}", extra={
            "validation_error": e,
        })
        abort(400, "SNS request body failed signature validation")

    supported_topic_name = f"s3_file_upload_notification_{current_app.config['DM_ENVIRONMENT']}"

    if body_dict["Type"] == "SubscriptionConfirmation":
        # SNS starts out sending us a SubscriptionConfirmation message when the Topic is initially subscribed to an URL.
        # We need to handle this in a specific way to "confirm" that we do actually want these notification messages
        # sent here.
        return _handle_subscription_confirmation(body_dict, supported_topic_name)
    elif body_dict["Type"] != "Notification":
        current_app.logger.warning("Unrecognized request type {request_type}", extra={
            "request_type": body_dict["Type"],
        })
        abort(400, f"Unrecognized request type {body_dict['Type']}")

    current_app.logger.info(
        "Processing message id {message_id} for subscription {subscription_arn}",
        extra={
            "message_id": body_dict["MessageId"],
            "subscription_arn": request.headers.get("x-amz-sns-subscription-arn"),
        },
    )

    try:
        records = json.loads(body_dict["Message"])["Records"]
    except (ValueError, KeyError, TypeError):
        current_app.logger.warning("Message contents didn't match expected format: {message_contents!r}", extra={
            "message_contents": body_dict.get("Message"),
        })
        abort(400, f"Message contents didn't match expected format")

    for record in records:
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
            s3_bucket_name = record["s3"]["bucket"]["name"]
            s3_object_key = record["s3"]["object"]["key"]
            s3_object_version = record["s3"]["object"]["versionId"]
            base_log_context = {
                "s3_bucket_name": s3_bucket_name,
                "s3_object_key": s3_object_key,
                "s3_object_version": s3_object_version,
            }
            log_context.update(base_log_context)

            # TODO abort if file too big?

            s3_client = boto3.client("s3", region_name=record["awsRegion"])

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

            av_status_json = _tag_value_from_tag_set(tagging_tag_set, "avStatus")

            if av_status_json is None:
                current_app.logger.info(
                    "Object version {s3_object_version} has no 'avStatus' tag - will scan...",
                    extra={
                        **base_log_context,
                        "av_status": av_status_json,
                    },
                )
            else:
                current_app.logger.info(
                    "Object version {s3_object_version} already has 'avStatus' tag: {av_status}",
                    extra={
                        **base_log_context,
                        "av_status": av_status_json,
                    },
                )
                continue

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

            file_name = _filename_from_content_disposition(s3_object["ContentDisposition"] or "")

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

            # keep in mind we only have 256 chars to play with here, so keep it brief
            new_av_status = {
                "result": "pass" if clamd_result[0] == "OK" else "fail",
                "clamdVerStr": clamd_version,
                "ts": datetime.datetime.utcnow().isoformat(),
            }
            new_av_status_json = json.dumps(new_av_status, separators=(',', ':'))

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

            av_status_json = _tag_value_from_tag_set(tagging_tag_set, "avStatus")

            if av_status_json is not None:
                current_app.logger.warning(
                    "Object was tagged with new 'avStatus' ({existing_av_status}) while we were scanning. "
                    "Not applying our own 'avStatus' result ({unapplied_av_status})",
                    extra={
                        "existing_av_status": av_status_json,
                        "unapplied_av_status": new_av_status_json,
                    },
                )
                continue

            tagging_tag_set = _tag_set_updated_with_value(tagging_tag_set, "avStatus", new_av_status_json)

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
                try:
                    notify_client.send_email(
                        current_app.config["DM_DEVELOPER_VIRUS_ALERT_EMAIL"],
                        template_name_or_id="developer_virus_alert",
                        personalisation={
                            "region_name": record["awsRegion"],
                            "bucket_name": s3_bucket_name,
                            "object_key": s3_object_key,
                            "object_version": s3_object_version,
                            "file_name": file_name,
                            "clamd_output": ", ".join(clamd_result),
                            "sns_message_id": body_dict["MessageId"],
                            "dm_trace_id": request.trace_id,
                        },
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
                    # however we still want this request to return a successful status to signify to SNS that it
                    # should not attempt to re-send this message

    return jsonify(status="ok", dmTraceId=request.trace_id), 200
