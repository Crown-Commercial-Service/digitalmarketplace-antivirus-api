import logging

import boto3
from freezegun import freeze_time
import mock
import pytest

from dmtestutils.comparisons import AnySupersetOf, AnyStringMatching, RestrictedAny

from app.clam import UnknownClamdError
from app.s3 import _filename_from_content_disposition, scan_and_tag_s3_object

from .helpers import (
    BaseApplicationTest,
    tagset_from_dict,
    dict_from_tagset,
    null_context_manager,
)


pytestmark = pytest.mark.usefixtures("force_all_logged_duration")


@pytest.mark.parametrize("cd_string,expected_output", (
    ("a", None,),
    ("attachment; filename=abcd3_ .pdf ", "abcd3_ .pdf",),
    ('bla; bla; filename="things...other...things.PNG";', "things...other...things.PNG",),
    (';filename= 8765432', " 8765432",),
))
def test_filename_from_content_disposition(cd_string, expected_output):
    assert _filename_from_content_disposition(cd_string) == expected_output


class TestScanAndTagS3Object(BaseApplicationTest):
    @pytest.mark.parametrize(
        (
            "initial_tagset",
            "concurrent_new_tagset",
            "clamd_instream_retval",
            "expected_retval",
            "expected_log_calls",
            "expected_notify_calls",
            "expected_tagset",
        ),
        (
            (
                # initial_tagset
                {
                    "existing": "tag123",
                    "avStatus.irrelevant": "who is here",
                },
                # concurrent_new_tagset
                {"surprise": "tag234"},
                # clamd_instream_retval
                {"stream": ("OK", "dénouement sufficient",)},
                # expected_retval
                (
                    {},
                    True,
                    {
                        "avStatus.clamdVerStr": "ClamAV 567; first watch",
                        "avStatus.result": "pass",
                        "avStatus.ts": "2010-09-08T07:06:05.040302",
                    },
                ),
                # expected_log_calls
                (
                    (
                        (logging.DEBUG, AnyStringMatching(r"Call to S3 \(get object tagging"), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "s3_bucket_name": "spade",
                            "s3_object_key": "sandman/+4321 billy-winks☾.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                    (
                        (logging.INFO, AnyStringMatching(r"Object version .* has no .avStatus\.result. tag "), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "av_status": {"avStatus.irrelevant": "who is here"},
                            "s3_bucket_name": "spade",
                            "s3_object_key": "sandman/+4321 billy-winks☾.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                    (
                        (logging.DEBUG, AnyStringMatching(r"Call to S3 \(initiate object download"), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "s3_bucket_name": "spade",
                            "s3_object_key": "sandman/+4321 billy-winks☾.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                    (
                        (logging.INFO, AnyStringMatching(r"Scanned "), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "file_length": 12,
                            "file_name": "too ducky.puddeny-pie.pdf",
                            "clamd_result": ("OK", "dénouement sufficient"),
                        })}),
                    ),
                    (
                        (logging.DEBUG, AnyStringMatching(r"Fetched clamd version "), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "clamd_version": "ClamAV 567; first watch",
                        })}),
                    ),
                    (
                        (logging.DEBUG, AnyStringMatching(r"Call to S3 \(get object tagging"), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "s3_bucket_name": "spade",
                            "s3_object_key": "sandman/+4321 billy-winks☾.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                    (
                        (logging.DEBUG, AnyStringMatching(r"Call to S3 \(put object tagging"), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "s3_bucket_name": "spade",
                            "s3_object_key": "sandman/+4321 billy-winks☾.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                    (
                        (logging.INFO, AnyStringMatching(r"Handled bucket "), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "s3_bucket_name": "spade",
                            "s3_object_key": "sandman/+4321 billy-winks☾.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                ),
                # expected_notify_calls
                (),
                # expected_tagset
                {
                    "avStatus.result": "pass",
                    "avStatus.clamdVerStr": "ClamAV 567_ first watch",
                    "avStatus.ts": "2010-09-08T07:06:05.040302",
                    "surprise": "tag234",
                },
            ),
            (
                # initial_tagset
                {"existing": "tag123"},
                # concurrent_new_tagset
                {"surprise": "tag234"},
                # clamd_instream_retval
                {"stream": ("FOUND", "After him, Garry!",)},
                # expected_retval
                (
                    {},
                    True,
                    {
                        "avStatus.clamdVerStr": "ClamAV 567; first watch",
                        "avStatus.result": "fail",
                        "avStatus.ts": "2010-09-08T07:06:05.040302",
                    },
                ),
                # expected_log_calls
                (
                    (
                        (logging.DEBUG, AnyStringMatching(r"Call to S3 \(get object tagging"), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "s3_bucket_name": "spade",
                            "s3_object_key": "sandman/+4321 billy-winks☾.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                    (
                        (logging.INFO, AnyStringMatching(r"Object version .* has no .avStatus\.result. tag "), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "av_status": {},
                            "s3_bucket_name": "spade",
                            "s3_object_key": "sandman/+4321 billy-winks☾.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                    (
                        (logging.DEBUG, AnyStringMatching(r"Call to S3 \(initiate object download"), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "s3_bucket_name": "spade",
                            "s3_object_key": "sandman/+4321 billy-winks☾.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                    (
                        (logging.INFO, AnyStringMatching(r"Scanned "), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "file_length": 12,
                            "file_name": "too ducky.puddeny-pie.pdf",
                            "clamd_result": ("FOUND", "After him, Garry!"),
                        })}),
                    ),
                    (
                        (logging.DEBUG, AnyStringMatching(r"Fetched clamd version "), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "clamd_version": "ClamAV 567; first watch",
                        })}),
                    ),
                    (
                        (logging.DEBUG, AnyStringMatching(r"Call to S3 \(get object tagging"), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "s3_bucket_name": "spade",
                            "s3_object_key": "sandman/+4321 billy-winks☾.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                    (
                        (logging.DEBUG, AnyStringMatching(r"Call to S3 \(put object tagging"), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "s3_bucket_name": "spade",
                            "s3_object_key": "sandman/+4321 billy-winks☾.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                    (
                        (logging.INFO, AnyStringMatching(r"Handled bucket "), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "s3_bucket_name": "spade",
                            "s3_object_key": "sandman/+4321 billy-winks☾.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                ),
                # expected_notify_calls
                (
                    mock.call("not_a_real_key-00000000-fake-uuid-0000-000000000000"),
                    mock.call().send_email(
                        to_email_address="developer-virus-alert@example.com",
                        personalisation={
                            "bucket_name": "spade",
                            "clamd_output": "FOUND, After him, Garry!",
                            "dm_trace_id": mock.ANY,
                            "file_name": "too ducky.puddeny-pie.pdf",
                            "object_key": "sandman/+4321 billy-winks☾.pdf",
                            "object_version": "0",
                            "sns_message_id": "<N/A>",
                        },
                        template_name_or_id="developer_virus_alert",
                    ),
                ),
                # expected_tagset
                {
                    "avStatus.result": "fail",
                    "avStatus.clamdVerStr": "ClamAV 567_ first watch",
                    "avStatus.ts": "2010-09-08T07:06:05.040302",
                    "surprise": "tag234",
                }
            ),
            (
                # initial_tagset
                {"existing": "tag123"},
                # concurrent_new_tagset
                None,
                # clamd_instream_retval
                {"stream": ("FOUND", "eicar-test-signature",)},
                # expected_retval
                (
                    {},
                    True,
                    {
                        "avStatus.clamdVerStr": "ClamAV 567; first watch",
                        "avStatus.result": "fail",
                        "avStatus.ts": "2010-09-08T07:06:05.040302",
                    },
                ),
                # expected_log_calls
                (
                    (
                        (logging.DEBUG, AnyStringMatching(r"Call to S3 \(get object tagging"), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "s3_bucket_name": "spade",
                            "s3_object_key": "sandman/+4321 billy-winks☾.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                    (
                        (logging.INFO, AnyStringMatching(r"Object version .* has no .avStatus\.result. tag "), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "av_status": {},
                            "s3_bucket_name": "spade",
                            "s3_object_key": "sandman/+4321 billy-winks☾.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                    (
                        (logging.DEBUG, AnyStringMatching(r"Call to S3 \(initiate object download"), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "s3_bucket_name": "spade",
                            "s3_object_key": "sandman/+4321 billy-winks☾.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                    (
                        (logging.INFO, AnyStringMatching(r"Scanned "), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "file_length": 12,
                            "file_name": "too ducky.puddeny-pie.pdf",
                            "clamd_result": ("FOUND", "eicar-test-signature"),
                        })}),
                    ),
                    (
                        (logging.DEBUG, AnyStringMatching(r"Fetched clamd version "), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "clamd_version": "ClamAV 567; first watch",
                        })}),
                    ),
                    (
                        (logging.DEBUG, AnyStringMatching(r"Call to S3 \(get object tagging"), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "s3_bucket_name": "spade",
                            "s3_object_key": "sandman/+4321 billy-winks☾.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                    (
                        (logging.DEBUG, AnyStringMatching(r"Call to S3 \(put object tagging"), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "s3_bucket_name": "spade",
                            "s3_object_key": "sandman/+4321 billy-winks☾.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                    (
                        (logging.INFO, AnyStringMatching(r"Handled bucket "), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "s3_bucket_name": "spade",
                            "s3_object_key": "sandman/+4321 billy-winks☾.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                ),
                # expected_notify_calls
                (
                    mock.call("not_a_real_key-00000000-fake-uuid-0000-000000000000"),
                    mock.call().send_email(
                        to_email_address="eicar-found@example.gov.uk",
                        personalisation={
                            "bucket_name": "spade",
                            "clamd_output": "FOUND, eicar-test-signature",
                            "dm_trace_id": mock.ANY,
                            "file_name": "too ducky.puddeny-pie.pdf",
                            "object_key": "sandman/+4321 billy-winks☾.pdf",
                            "object_version": "0",
                            "sns_message_id": "<N/A>",
                        },
                        template_name_or_id="developer_virus_alert",
                        reference="eicar-found-4d3daeeb3ea3d90d4d6e7a20a5b483a9-development",
                    ),
                ),
                # expected_tagset
                {
                    "avStatus.result": "fail",
                    "avStatus.clamdVerStr": "ClamAV 567_ first watch",
                    "avStatus.ts": "2010-09-08T07:06:05.040302",
                    "existing": "tag123",
                }
            ),
            (
                # initial_tagset
                {"existing": "tag123"},
                # concurrent_new_tagset
                {
                    "surprise": "tag234",
                    "avStatus.ts": "2010-09-08T07:06:05.040302",
                },
                # clamd_instream_retval
                {"stream": ("ERROR", " Some trouble is on here",)},
                # expected_retval
                UnknownClamdError,
                # expected_log_calls
                (
                    (
                        (logging.DEBUG, AnyStringMatching(r"Call to S3 \(get object tagging"), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "s3_bucket_name": "spade",
                            "s3_object_key": "sandman/+4321 billy-winks☾.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                    (
                        (logging.INFO, AnyStringMatching(r"Object version .* has no .avStatus\.result. tag "), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "av_status": {},
                            "s3_bucket_name": "spade",
                            "s3_object_key": "sandman/+4321 billy-winks☾.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                    (
                        (logging.DEBUG, AnyStringMatching(r"Call to S3 \(initiate object download"), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "s3_bucket_name": "spade",
                            "s3_object_key": "sandman/+4321 billy-winks☾.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                    (
                        (logging.INFO, AnyStringMatching(r"Scanned "), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "file_length": 12,
                            "file_name": "too ducky.puddeny-pie.pdf",
                            "clamd_result": ("ERROR", " Some trouble is on here",),
                        })}),
                    ),
                    (
                        (logging.INFO, AnyStringMatching(r"Failed handling.*UnknownClamdError.*"), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "s3_bucket_name": "spade",
                            "s3_object_key": "sandman/+4321 billy-winks☾.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                ),
                # expected_notify_calls
                (),
                # expected_tagset
                {
                    "surprise": "tag234",
                    "avStatus.ts": "2010-09-08T07:06:05.040302",
                },
            ),
            (
                # initial_tagset
                {"existing": "tag123"},
                # concurrent_new_tagset
                {
                    "avStatus.result": "fail",
                    "avStatus.ts": "2010-09-08T07:06:04.010101",
                    "avStatus.irrelevant": "who is here",
                },
                # clamd_instream_retval
                {"stream": ("OK", "Egg two demolished",)},
                # expected_retval
                (
                    {
                        "avStatus.result": "fail",
                        "avStatus.ts": "2010-09-08T07:06:04.010101",
                        "avStatus.irrelevant": "who is here",
                    },
                    False,
                    {
                        "avStatus.clamdVerStr": "ClamAV 567; first watch",
                        "avStatus.result": "pass",
                        "avStatus.ts": "2010-09-08T07:06:05.040302",
                    },
                ),
                # expected_log_calls
                (
                    (
                        (logging.DEBUG, AnyStringMatching(r"Call to S3 \(get object tagging"), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "s3_bucket_name": "spade",
                            "s3_object_key": "sandman/+4321 billy-winks☾.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                    (
                        (logging.INFO, AnyStringMatching(r"Object version .* has no .avStatus\.result. tag "), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "av_status": {},
                            "s3_bucket_name": "spade",
                            "s3_object_key": "sandman/+4321 billy-winks☾.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                    (
                        (logging.DEBUG, AnyStringMatching(r"Call to S3 \(initiate object download"), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "s3_bucket_name": "spade",
                            "s3_object_key": "sandman/+4321 billy-winks☾.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                    (
                        (logging.INFO, AnyStringMatching(r"Scanned "), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "file_length": 12,
                            "file_name": "too ducky.puddeny-pie.pdf",
                            "clamd_result": ("OK", "Egg two demolished"),
                        })}),
                    ),
                    (
                        (logging.DEBUG, AnyStringMatching(r"Fetched clamd version "), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "clamd_version": "ClamAV 567; first watch",
                        })}),
                    ),
                    (
                        (logging.DEBUG, AnyStringMatching(r"Call to S3 \(get object tagging"), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "s3_bucket_name": "spade",
                            "s3_object_key": "sandman/+4321 billy-winks☾.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                    (
                        (
                            logging.WARNING,
                            AnyStringMatching(r"Object was tagged.*existing.*unapplied.*"),
                            (),
                        ),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "existing_av_status": {
                                "avStatus.result": "fail",
                                "avStatus.ts": "2010-09-08T07:06:04.010101",
                                "avStatus.irrelevant": "who is here",
                            },
                            "existing_av_status_result": "fail",
                            "unapplied_av_status": {
                                "avStatus.result": "pass",
                                "avStatus.clamdVerStr": "ClamAV 567; first watch",
                                "avStatus.ts": "2010-09-08T07:06:05.040302",
                            },
                            "unapplied_av_status_result": "pass",
                        })}),
                    ),
                    (
                        (logging.INFO, AnyStringMatching(r"Handled bucket "), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "s3_bucket_name": "spade",
                            "s3_object_key": "sandman/+4321 billy-winks☾.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                ),
                # expected_notify_calls
                (),
                # expected_tagset
                {
                    "avStatus.result": "fail",
                    "avStatus.ts": "2010-09-08T07:06:04.010101",
                    "avStatus.irrelevant": "who is here",
                },
            ),
            (
                # initial_tagset
                {"existing": "tag123"},
                # concurrent_new_tagset
                {
                    "avStatus.result": "pass",
                    "avStatus.ts": "2010-09-08T07:06:04.010101",
                    "avStatus.clamdVerStr": "4321_ 7654",
                    "surprise": "789+789",
                },
                # clamd_instream_retval
                {"stream": ("FOUND", "After him, boy!",)},
                # expected_retval
                (
                    {
                        "avStatus.result": "pass",
                        "avStatus.ts": "2010-09-08T07:06:04.010101",
                        "avStatus.clamdVerStr": "4321_ 7654",
                    },
                    False,
                    {
                        "avStatus.clamdVerStr": "ClamAV 567; first watch",
                        "avStatus.result": "fail",
                        "avStatus.ts": "2010-09-08T07:06:05.040302",
                    },
                ),
                # expected_log_calls
                (
                    (
                        (logging.DEBUG, AnyStringMatching(r"Call to S3 \(get object tagging"), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "s3_bucket_name": "spade",
                            "s3_object_key": "sandman/+4321 billy-winks☾.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                    (
                        (logging.INFO, AnyStringMatching(r"Object version .* has no .avStatus\.result. tag "), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "av_status": {},
                            "s3_bucket_name": "spade",
                            "s3_object_key": "sandman/+4321 billy-winks☾.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                    (
                        (logging.DEBUG, AnyStringMatching(r"Call to S3 \(initiate object download"), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "s3_bucket_name": "spade",
                            "s3_object_key": "sandman/+4321 billy-winks☾.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                    (
                        (logging.INFO, AnyStringMatching(r"Scanned "), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "file_length": 12,
                            "file_name": "too ducky.puddeny-pie.pdf",
                            "clamd_result": ("FOUND", "After him, boy!"),
                        })}),
                    ),
                    (
                        (logging.DEBUG, AnyStringMatching(r"Fetched clamd version "), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "clamd_version": "ClamAV 567; first watch",
                        })}),
                    ),
                    (
                        (logging.DEBUG, AnyStringMatching(r"Call to S3 \(get object tagging"), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "s3_bucket_name": "spade",
                            "s3_object_key": "sandman/+4321 billy-winks☾.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                    (
                        (
                            logging.WARNING,
                            AnyStringMatching(r"Object was tagged.*existing.*unapplied.*"),
                            (),
                        ),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "existing_av_status": {
                                "avStatus.result": "pass",
                                "avStatus.ts": "2010-09-08T07:06:04.010101",
                                "avStatus.clamdVerStr": "4321_ 7654",
                            },
                            "existing_av_status_result": "pass",
                            "unapplied_av_status": {
                                "avStatus.result": "fail",
                                "avStatus.clamdVerStr": "ClamAV 567; first watch",
                                "avStatus.ts": "2010-09-08T07:06:05.040302",
                            },
                            "unapplied_av_status_result": "fail",
                        })}),
                    ),
                    (
                        (logging.INFO, AnyStringMatching(r"Handled bucket "), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "s3_bucket_name": "spade",
                            "s3_object_key": "sandman/+4321 billy-winks☾.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                ),
                # expected_notify_calls
                (),
                # expected_tagset
                {
                    "avStatus.result": "pass",
                    "avStatus.ts": "2010-09-08T07:06:04.010101",
                    "avStatus.clamdVerStr": "4321_ 7654",
                    "surprise": "789+789",
                },
            ),
            (
                # initial_tagset
                {
                    "avStatus.result": "pass",
                    "avStatus.ts": "2010-09-08T07:06:04.010101",
                },
                # concurrent_new_tagset
                None,
                # clamd_instream_retval
                None,
                # expected_retval
                (
                    {
                        "avStatus.result": "pass",
                        "avStatus.ts": "2010-09-08T07:06:04.010101",
                    },
                    False,
                    None,
                ),
                # expected_log_calls
                (
                    (
                        (logging.DEBUG, AnyStringMatching(r"Call to S3 \(get object tagging"), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "s3_bucket_name": "spade",
                            "s3_object_key": "sandman/+4321 billy-winks☾.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                    (
                        (logging.INFO, AnyStringMatching(r"Object version.*already.*avStatus\.result.*tag.+"), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "existing_av_status": {
                                "avStatus.result": "pass",
                                "avStatus.ts": "2010-09-08T07:06:04.010101",
                            },
                            "existing_av_status_result": "pass",
                            "s3_bucket_name": "spade",
                            "s3_object_key": "sandman/+4321 billy-winks☾.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                    (
                        (logging.INFO, AnyStringMatching(r"Handled bucket "), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "s3_bucket_name": "spade",
                            "s3_object_key": "sandman/+4321 billy-winks☾.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                ),
                # expected_notify_calls
                (),
                # expected_tagset
                {
                    "avStatus.result": "pass",
                    "avStatus.ts": "2010-09-08T07:06:04.010101",
                },
            ),
            (
                # initial_tagset
                {
                    "avStatus.result": "fail",
                    "avStatus.ts": "2010-09-08T07:06:04.010101",
                },
                # concurrent_new_tagset
                None,
                # clamd_instream_retval
                None,
                # expected_retval
                (
                    {
                        "avStatus.result": "fail",
                        "avStatus.ts": "2010-09-08T07:06:04.010101",
                    },
                    False,
                    None,
                ),
                # expected_log_calls
                (
                    (
                        (logging.DEBUG, AnyStringMatching(r"Call to S3 \(get object tagging"), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "s3_bucket_name": "spade",
                            "s3_object_key": "sandman/+4321 billy-winks☾.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                    (
                        (logging.INFO, AnyStringMatching(r"Object version.*already.*avStatus\.result.*tag.+"), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "existing_av_status": {
                                "avStatus.result": "fail",
                                "avStatus.ts": "2010-09-08T07:06:04.010101",
                            },
                            "existing_av_status_result": "fail",
                            "s3_bucket_name": "spade",
                            "s3_object_key": "sandman/+4321 billy-winks☾.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                    (
                        (logging.INFO, AnyStringMatching(r"Handled bucket "), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "s3_bucket_name": "spade",
                            "s3_object_key": "sandman/+4321 billy-winks☾.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                ),
                # expected_notify_calls
                (),
                # expected_tagset
                {
                    "avStatus.result": "fail",
                    "avStatus.ts": "2010-09-08T07:06:04.010101",
                },
            ),
        ),
    )
    @freeze_time("2010-09-08T07:06:05.040302")
    @mock.patch("app.s3.DMNotifyClient", autospec=True)
    def test_scan_and_tag_s3_object(
        self,
        mock_notify_client,
        bucket_with_file,
        mock_clamd,
        initial_tagset,
        concurrent_new_tagset,
        clamd_instream_retval,
        expected_retval,
        expected_log_calls,
        expected_notify_calls,
        expected_tagset,
    ):
        """
        :param initial_tagset:        tagset (dict) that file in bucket will appear to have initially
        :param concurrent_new_tagset: a tagset (dict) that coincidentally gets set "while" the clam instream process
                                      is running, None to skip this update
        :param clamd_instream_retval: value to return from mock clamd instream(...) call, None to expect no call to
                                      take place
        :param expected_retval:       return value to expect from call, or, if a subclass of Exception, expect to raise
                                      this exception type
        :param expected_log_calls:    sequence of expected mock.call()s to have been made to app logger
        :param expected_notify_calls: sequence of expected mock.call()s to have been made to mock DMNotifyClient
        :param expected_tagset:       tagset (dict) to expect file to have after the request processing has finished
        """
        bucket, objver = bucket_with_file
        s3_client = boto3.client("s3", region_name="howth-west-2")

        if initial_tagset is not None:
            s3_client.put_object_tagging(
                Bucket=bucket.name,
                Key=objver.Object().key,
                VersionId=objver.id,
                Tagging={"TagSet": tagset_from_dict(initial_tagset)},
            )

        def clamd_instream_func(*args, **kwargs):
            # if clamd_instream_retval *is* None, we'd be expecting "instream" not to be called at all
            assert clamd_instream_retval is not None

            assert args == (RestrictedAny(lambda x: x.read() == b"123412341234"),)
            assert kwargs == {}

            if concurrent_new_tagset is not None:
                # a very literal "side effect" here - simulating a modification to the object's tags while scanning...
                s3_client.put_object_tagging(
                    Bucket=bucket.name,
                    Key=objver.Object().key,
                    VersionId=objver.id,
                    Tagging={"TagSet": tagset_from_dict(concurrent_new_tagset)},
                )

            return clamd_instream_retval

        mock_clamd.instream.side_effect = clamd_instream_func
        mock_clamd.version.return_value = "ClamAV 567; first watch"

        with self.mocked_app_logger_log() as mock_app_log:
            with pytest.raises(expected_retval) if (
                isinstance(expected_retval, type)
                and issubclass(expected_retval, Exception)
            ) else null_context_manager():
                with self.app.test_request_context():
                    retval = scan_and_tag_s3_object(
                        s3_client,
                        bucket.name,
                        objver.Object().key,
                        objver.id,
                    )

            if not (isinstance(expected_retval, type) and issubclass(expected_retval, Exception)):
                assert retval == expected_retval

            assert mock_app_log.call_args_list == list(expected_log_calls)
            assert mock_notify_client.mock_calls == list(expected_notify_calls)

            assert dict_from_tagset(
                s3_client.get_object_tagging(
                    Bucket=bucket.name,
                    Key=objver.Object().key,
                    VersionId=objver.id,
                )["TagSet"]
            ) == expected_tagset
