import base64
import contextlib
from functools import partial
from itertools import chain
import json
import logging

import boto3
from freezegun import freeze_time
from flask.wrappers import Response
from lxml.etree import ParseError
import mock
from moto.s3 import mock_s3
import pytest
import requests
import requests_mock
import validatesns
import werkzeug

from dmutils.timing import logged_duration

from dmtestutils.comparisons import AnySupersetOf, AnyStringMatching, RestrictedAny

from app.callbacks.views.sns import (
    _filename_from_content_disposition,
    _get_certificate,
    _handle_subscription_confirmation,
    UnknownClamdError,
)

from ..helpers import BaseCallbackApplicationTest


_aws_region = "howth-west-2"


@pytest.fixture(autouse=True)
def clear_get_certificate_cache():
    # reset the lru_cache both before and after test in case there is an unaware test before or after it that also
    # hits _get_certificate()
    _get_certificate.cache_clear()
    yield
    _get_certificate.cache_clear()


@pytest.fixture(autouse=True)
def force_all_logged_duration():
    # this looks more complicated than it is - it simply forces the kwarg condition=True on all calls to logged_duration
    def logged_duration_wrapper(*args, **kwargs):
        return logged_duration(
            *args,
            **{**kwargs, "condition": True},
        )

    # apply this mock in multiple places
    with mock.patch("app.callbacks.views.sns.logged_duration", autospec=True) as mock_sns_logged_duration:
        mock_sns_logged_duration.side_effect = logged_duration_wrapper
        with mock.patch("dmutils.timing.logged_duration", autospec=True) as mock_timing_logged_duration:
            mock_timing_logged_duration.side_effect = logged_duration_wrapper
            yield


@pytest.fixture
def s3_mock(request, os_environ):
    # we don't want any real aws credentials this environment might have used in the tests
    os_environ.update({
        "AWS_ACCESS_KEY_ID": "AKIAIABCDABCDABCDABC",
        "AWS_SECRET_ACCESS_KEY": "foobarfoobarfoobarfoobarfoobarfoobarfoob",
    })

    m = mock_s3()
    m.start()
    yield m
    m.stop()


@pytest.fixture
def empty_bucket(request, s3_mock):
    s3_res = boto3.resource("s3", region_name=_aws_region)
    bucket = s3_res.Bucket("spade")
    bucket.create()
    bucket.Versioning().enable()
    yield bucket


@pytest.fixture
def bucket_with_file(request, empty_bucket):
    bucket = empty_bucket
    obj = empty_bucket.Object("sandman/4321-billy-winks.pdf")
    obj.put(
        Body=b"123412341234",
        Metadata={
            "timestamp": "2005-04-03T02:01:00.12345Z",
        },
        ContentType="application/pdf",
        ContentDisposition='attachment; filename="too ducky.puddeny-pie.pdf"',
    )
    yield bucket, obj.Version(obj.version_id)


@contextlib.contextmanager
def null_context_manager():
    yield


def _json_norm_compare(other, x):
    try:
        return json.loads(x) == other
    except ValueError:
        return False


class AnyJsonEq(RestrictedAny):
    def __init__(self, other):
        super().__init__(partial(_json_norm_compare, other))


def _b64_norm_compare(other, x):
    try:
        return base64.b64decode(x.encode("ascii")).decode("utf-8") == other
    except (TypeError, ValueError, UnicodeDecodeError, UnicodeEncodeError):
        # if it wasn't valid base64 in one way or another, the answer is False
        return False


class AnyB64Eq(RestrictedAny):
    def __init__(self, other):
        super().__init__(partial(_b64_norm_compare, other))


def _dict_from_tagset(tagset_seq):
    return {k_v["Key"]: k_v["Value"] for k_v in tagset_seq}


def _tagset_from_dict(input_dict):
    return [{"Key": k, "Value": v} for k, v in input_dict.items()]


def _b64e(value):
    return base64.b64encode(value.encode("utf-8")).decode("ascii")


@pytest.mark.parametrize("cd_string,expected_output", (
    ("a", None,),
    ("attachment; filename=abcd3_ .pdf ", "abcd3_ .pdf",),
    ('bla; bla; filename="things...other...things.PNG";', "things...other...things.PNG",),
    (';filename= 8765432', " 8765432",),
))
def test_filename_from_content_disposition(cd_string, expected_output):
    assert _filename_from_content_disposition(cd_string) == expected_output


class TestGetCertificate(BaseCallbackApplicationTest):
    @pytest.mark.parametrize("call_params_seq", (
        (
            (
                "https://bendollard.net/cert.pem",
                {"status_code": 200, "text": "Six sharps? F sharp major"},
                b"Six sharps? F sharp major",
                True,
            ),
            (
                "https://bendollard.net/cert.pem",
                {"status_code": 200, "text": "Six sharps? D sharp minor"},
                b"Six sharps? F sharp major",
                False,
            ),
        ),
        (
            (
                "http://twopence.tip/deaf?bothered",
                {"status_code": 210, "text": "Ships 💡 lanterns"},
                b"Ships \xf0\x9f\x92\xa1 lanterns",
                True,
            ),
            (
                "https://twopence.tip/deaf?bothered",
                {"status_code": 200, "text": "Rosiny ➰ ropes"},
                b"Rosiny \xe2\x9e\xb0 ropes",
                True,
            ),
            (
                "http://twopence.tip/deaf?bothered",
                {"status_code": 200, "text": "Ships 💡 lanterns"},
                b"Ships \xf0\x9f\x92\xa1 lanterns",
                False,
            ),
            (
                "https://conductors.legs.com/2/3/4/",
                {"status_code": 404, "text": "Lost in thought"},
                requests.exceptions.HTTPError,
                True,
            ),
            (
                "https://twopence.tip/deaf?bothered",
                {"status_code": 400, "text": "Failed to the tune of ten thousand pounds"},
                b"Rosiny \xe2\x9e\xb0 ropes",
                False,
            ),
        ),
        (
            (
                "https://trilling-trilling.douce.org/cert123.pem",
                {"status_code": 500, "text": "Take no notice"},
                requests.exceptions.HTTPError,
                True,
            ),
            (
                "https://kennedy.giggling.peal/gathering/figs",
                {"exc": requests.exceptions.ConnectTimeout},
                requests.exceptions.ConnectTimeout,
                True,
            ),
            (
                "https://trilling-trilling.douce.org/cert123.pem",
                {"status_code": 200, "text": "The tuner was in today"},
                b"The tuner was in today",
                True,
            ),
            (
                "https://kennedy.giggling.peal/gathering/figs",
                {"status_code": 201, "content": b"\x02\xa3\xf9\x88"},
                b"\x02\xa3\xf9\x88",
                True,
            ),
            (
                "https://trilling-trilling.douce.org/cert123.pem",
                {"exc": requests.exceptions.ConnectTimeout},
                b"The tuner was in today",
                False,
            ),
        ),
    ))
    @pytest.mark.parametrize("single_flask_request", (False, True,))
    def test_get_certificate(self, call_params_seq, single_flask_request):
        """
        :param call_params_seq: a sequence of tuples, each representing a call to make to _get_certificate and
            including information about the context it should be called in and the call's expected result. each
            tuple consists of the parameters:
            (
                url,                    # the url to set up with register_uri() and then pass as _get_certificate's
                                        # argument
                rmock_response_kwargs,  # kwargs to pass to register_uri specifying how requests_mock should respond to
                                        # such a request
                expected_output,        # either an Exception class to expect _get_certificate's invocation to raise
                                        # or the value to compare _get_certificate's return value with
                expect_request_made,    # whether an actual (intercepted) http request should have been made to the url
            )
        :param single_flask_request: whether all requests of ``call_params_seq`` should be performed in a single test
            flask request. otherwise a separate flask test request is used per call
        """
        with self.mocked_app_logger_log() as mock_app_log:
            with self.app.test_request_context() if single_flask_request else null_context_manager():
                for url, rmock_response_kwargs, expected_output, expect_request_made in call_params_seq:
                    mock_app_log.reset_mock()
                    with null_context_manager() if single_flask_request else self.app.test_request_context():
                        with requests_mock.Mocker() as rmock:
                            rmock.register_uri("GET", url, **rmock_response_kwargs)

                            expect_exception = isinstance(expected_output, type) and \
                                issubclass(expected_output, Exception)
                            with pytest.raises(expected_output) if expect_exception else null_context_manager():
                                out = _get_certificate(url)

                            if not expect_exception:
                                assert out == expected_output

                            assert rmock.called is expect_request_made
                            # TODO more complete logging testing
                            assert mock_app_log.call_args_list == ([] if not expect_request_made else [
                                (
                                    (logging.INFO, AnyStringMatching("Failed" if expect_exception else "Fetched"), ()),
                                    AnySupersetOf({"extra": AnySupersetOf({"target_url": url})}),
                                ),
                            ])


class TestHandleSubscriptionConfirmation(BaseCallbackApplicationTest):
    @pytest.mark.parametrize(
        (
            "body_dict",
            "supported_topic_name",
            "rmock_response_kwargs",
            "expected_output",
            "expect_request_made",
            "expected_log_calls",
        ),
        tuple(chain.from_iterable((
            (
                (
                    # body_dict
                    {"SubscribeURL": "https://amz.net", "TopicArn": f"arn:aws:sns:{_aws_region}:123456789012:Drawers"},
                    # supported_topic_name
                    "Drawers",
                    # rmock_response_kwargs
                    {"text": f"""<ConfirmSubscriptionResponse xmlns="http://brazenfaced.things">
                        <ConfirmSubscriptionResult><SubscriptionArn>
                            arn:aws:sns:{_aws_region}:123456789012:Drawers:bicycles
                        </SubscriptionArn></ConfirmSubscriptionResult>
                        <ResponseMetadata><RequestId>
                            always-skeezing
                        </RequestId></ResponseMetadata>
                    </ConfirmSubscriptionResponse>"""},
                    # expected_output
                    (RestrictedAny(lambda x: isinstance(x, Response)), 200),
                    # expect_request_made
                    True,
                    # expected_log_calls
                    (
                        (
                            (logging.INFO, AnyStringMatching("Made GET "), ()),
                            AnySupersetOf({
                                "extra": AnySupersetOf({
                                    "target_url": "https://amz.net",
                                    "topic_arn": f"arn:aws:sns:{_aws_region}:123456789012:Drawers",
                                }),
                            }),
                        ),
                        (
                            (logging.INFO, AnyStringMatching("SubscriptionConfirmation succeeded "), ()),
                            AnySupersetOf({
                                "extra": AnySupersetOf({
                                    "subscription_arn": f"arn:aws:sns:{_aws_region}:123456789012:Drawers:bicycles",
                                    "confirmation_request_id": "always-skeezing",
                                }),
                            }),
                        ),
                    ),
                ),
                (
                    # body_dict
                    {"SubscribeURL": "https://butt.bridge", "TopicArn": "premature:decay"},
                    # supported_topic_name
                    "BrilliantFellows",
                    # rmock_response_kwargs
                    {"text": "dummy"},
                    # expected_output
                    werkzeug.exceptions.BadRequest,
                    # expect_request_made
                    False,
                    # expected_log_calls
                    (
                        (
                            (logging.WARNING, AnyStringMatching(r".*unrecognized topic.*"), ()),
                            AnySupersetOf({
                                "extra": AnySupersetOf({
                                    "topic_name": "decay",
                                    "topic_arn": "premature:decay",
                                }),
                            }),
                        ),
                    ),
                ),
                (
                    # body_dict
                    {"SubscribeURL": "https://sister.island.co.uk", "TopicArn": "100M:Played:Out:CoalSeams"},
                    # supported_topic_name
                    "CoalSeams",
                    # rmock_response_kwargs
                    {"text": """<ConfirmSubscriptionResponse xmlns="http://neighbours-across.the/channel">
                        <ConfirmSubscriptionResult><SubscriptionArn>
                            unrelated:naming:scheme
                        </SubscriptionArn></ConfirmSubscriptionResult>
                    </ConfirmSubscriptionResponse>""", "status_code": 210},
                    # expected_output
                    (RestrictedAny(lambda x: isinstance(x, Response)), 200),
                    # expect_request_made
                    True,
                    # expected_log_calls
                    (
                        (
                            (logging.INFO, AnyStringMatching("Made GET "), ()),
                            AnySupersetOf({
                                "extra": AnySupersetOf({
                                    "target_url": "https://sister.island.co.uk",
                                    "topic_arn": "100M:Played:Out:CoalSeams",
                                }),
                            }),
                        ),
                        (
                            (logging.INFO, AnyStringMatching("SubscriptionConfirmation succeeded "), ()),
                            AnySupersetOf({
                                "extra": AnySupersetOf({
                                    "subscription_arn": "unrelated:naming:scheme",
                                }),
                            }),
                        ),
                    ),
                ),
                (
                    # body_dict
                    {"SubscribeURL": "https://disorder.ly.hous.es", "TopicArn": "nice:mixup"},
                    # supported_topic_name
                    "mixup",
                    # rmock_response_kwargs
                    {"text": "<Second drink<does it<"},
                    # expected_output
                    werkzeug.exceptions.BadRequest,
                    # expect_request_made
                    True,
                    # expected_log_calls
                    (
                        (
                            (logging.INFO, AnyStringMatching("Made GET "), ()),
                            AnySupersetOf({
                                "extra": AnySupersetOf({
                                    "target_url": "https://disorder.ly.hous.es",
                                    "topic_arn": "nice:mixup",
                                }),
                            }),
                        ),
                        (
                            (logging.WARNING, RestrictedAny(lambda x: isinstance(x, ParseError)), ()),
                            AnySupersetOf({}),
                        ),
                        (
                            (logging.WARNING, "SubscriptionConfirmation response parsing failed", ()),
                            AnySupersetOf({}),
                        ),
                    ),
                ),
            ),
            (
                # the following case should basically have the same results for all request errors, so testing many
                # of these cases
                (
                    # body_dict
                    {"SubscribeURL": "https://wildgoose.chase/this", "TopicArn": "first-class:third:ticket"},
                    # supported_topic_name
                    "ticket",
                    # rmock_response_kwargs
                    rmock_response_kwargs,
                    # expected_output
                    werkzeug.exceptions.BadRequest,
                    # expect_request_made
                    True,
                    # expected_log_calls
                    (
                        (
                            (logging.INFO, AnyStringMatching("Failed to make GET "), ()),
                            AnySupersetOf({
                                "extra": AnySupersetOf({
                                    "target_url": "https://wildgoose.chase/this",
                                    "topic_arn": "first-class:third:ticket",
                                }),
                            }),
                        ),
                    ),
                ) for rmock_response_kwargs in (
                    {"status_code": 404, "text": "where?"},
                    {"status_code": 500, "text": "what?"},
                    {"status_code": 403, "text": "who?"},
                    {"status_code": 400, "text": "no"},
                    {"exc": requests.exceptions.ConnectTimeout},
                    {"exc": requests.exceptions.SSLError},
                )
            ),
        ))),
    )
    def test_handle_subscription_confirmation(
        self,
        body_dict,
        supported_topic_name,
        rmock_response_kwargs,
        expected_output,
        expect_request_made,
        expected_log_calls,
    ):
        """
        :param body_dict:             request body_dict to pass directly to _handle_subscription_confirmation
        :param supported_topic_name:  supported_topic_name to pass directly to _handle_subscription_confirmation
        :param rmock_response_kwargs: kwargs to pass to register_uri specifying how requests_mock should respond to
                                      a request to the "subscribe" url
        :param expected_output:       either an Exception subclass to expect to be raised or the expected return value
                                      of _handle_subscription_confirmation
        :param expect_request_made:   whether to expect a request to have been made to the "subscribe" url
        :param expected_log_calls:    sequence of expected mock.call()s to have been made to app logger
        """
        with self.mocked_app_logger_log() as mock_app_log:
            with self.app.test_request_context():
                with requests_mock.Mocker() as rmock:
                    rmock.register_uri("GET", body_dict["SubscribeURL"], **rmock_response_kwargs)

                    expect_exception = isinstance(expected_output, type) and issubclass(expected_output, Exception)
                    with pytest.raises(expected_output) if expect_exception else null_context_manager():
                        out = _handle_subscription_confirmation(body_dict, supported_topic_name)

                    if not expect_exception:
                        assert out == expected_output

                    assert rmock.called is expect_request_made
                    assert mock_app_log.call_args_list == list(expected_log_calls)


class TestHandleS3Sns(BaseCallbackApplicationTest):
    _basic_subscription_confirmation_body = {
        "Type": "SubscriptionConfirmation",
        "TopicArn": "54321:cattleTrade",
        "Token": "314159b",
        "Timestamp": "2018-05-05T11:00:01.12345Z",
        "SubscribeURL": "https://laissez.faire/doctrine",
        "MessageId": "abc123",
    }
    _basic_notification_body = {
        "Type": "Notification",
        "TopicArn": "65432:oldIndustries",
        "Timestamp": "2018-05-05T11:00:01.12345Z",
        "MessageId": "424344def",
        "Message": "The way thereof",
    }

    @pytest.mark.parametrize("base_body_dict", (_basic_subscription_confirmation_body, _basic_notification_body,))
    @freeze_time("2018-05-05T10:00")
    @mock.patch("app.callbacks.views.sns._handle_subscription_confirmation", autospec=True)
    def test_handle_s3_sns_unfetchable_cert(self, mock_handle_subscription_confirmation, base_body_dict):
        with self.mocked_app_logger_log() as mock_app_log:
            with requests_mock.Mocker() as rmock:
                rmock.register_uri("GET", "https://nowhere.amazonaws.com/cert.pem", status_code=404)

                client = self.get_authorized_client()
                res = client.post("/callbacks/sns/s3/uploaded", data=json.dumps({
                    **base_body_dict,
                    "Signature": "should_be_irrelevant",
                    "SigningCertURL": "https://nowhere.amazonaws.com/cert.pem",
                }), content_type="application/json")

                assert res.status_code == 400
                assert mock_app_log.call_args_list == [
                    (
                        (logging.INFO, AnyStringMatching(r"Failed to fetch certificate .*404"), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "target_url": "https://nowhere.amazonaws.com/cert.pem",
                        })}),
                    ),
                    (
                        (logging.WARNING, AnyStringMatching(r"SNS request body failed "), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "validation_error": RestrictedAny(lambda x: isinstance(x, requests.exceptions.HTTPError)),
                        })}),
                    ),
                    (mock.ANY, AnySupersetOf({"extra": AnySupersetOf({"status": 400})}))
                ]
                assert rmock.request_history == [
                    RestrictedAny(lambda r: r.url == "https://nowhere.amazonaws.com/cert.pem")
                ]
                assert mock_handle_subscription_confirmation.called is False

    @pytest.mark.parametrize("base_body_dict", (_basic_subscription_confirmation_body, _basic_notification_body,))
    @mock.patch("validatesns.validate", autospec=True)
    @mock.patch("app.callbacks.views.sns._handle_subscription_confirmation", autospec=True)
    def test_handle_s3_sns_bad_signature(self, mock_handle_subscription_confirmation, mock_validate, base_body_dict):
        mock_validate.side_effect = validatesns.ValidationError
        with self.mocked_app_logger_log() as mock_app_log:
            with requests_mock.Mocker() as rmock:
                client = self.get_authorized_client()
                res = client.post(
                    "/callbacks/sns/s3/uploaded",
                    data=json.dumps(base_body_dict),
                    content_type="application/json",
                )

                assert res.status_code == 400
                assert mock_app_log.call_args_list == [
                    (
                        (logging.WARNING, AnyStringMatching(r".*failed signature validation"), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "validation_error": RestrictedAny(lambda x: isinstance(x, validatesns.ValidationError)),
                        })}),
                    ),
                    (mock.ANY, AnySupersetOf({"extra": AnySupersetOf({"status": 400})}))
                ]
                assert not rmock.request_history
                assert mock_validate.call_args_list == [((base_body_dict,), AnySupersetOf({}))]
                assert mock_handle_subscription_confirmation.called is False

    @mock.patch("validatesns.validate", autospec=True)
    @mock.patch("app.callbacks.views.sns._handle_subscription_confirmation", autospec=True)
    def test_handle_s3_sns_weird_request_type(self, mock_handle_subscription_confirmation, mock_validate):
        with self.mocked_app_logger_log() as mock_app_log:
            with requests_mock.Mocker() as rmock:
                client = self.get_authorized_client()
                weird_body_dict = {
                    "MessageId": "1234321",
                    "Type": "EuropeanConflagration",
                }
                res = client.post(
                    "/callbacks/sns/s3/uploaded",
                    data=json.dumps(weird_body_dict),
                    content_type="application/json",
                )

                assert res.status_code == 400
                assert mock_app_log.call_args_list == [
                    (
                        (logging.WARNING, AnyStringMatching(r"Unrecognized request type "), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "request_type": "EuropeanConflagration",
                        })}),
                    ),
                    (mock.ANY, AnySupersetOf({"extra": AnySupersetOf({"status": 400})}))
                ]
                assert not rmock.request_history
                assert mock_validate.call_args_list == [((weird_body_dict,), AnySupersetOf({}))]
                assert mock_handle_subscription_confirmation.called is False

    @pytest.mark.parametrize("message", ("mangiD", 123, None, "", "{}",))
    @mock.patch("validatesns.validate", autospec=True)
    @mock.patch("app.callbacks.views.sns._handle_subscription_confirmation", autospec=True)
    def test_handle_s3_sns_unexpected_message(self, mock_handle_subscription_confirmation, mock_validate, message):
        with self.mocked_app_logger_log() as mock_app_log:
            with requests_mock.Mocker() as rmock:
                client = self.get_authorized_client()
                body_dict = {
                    "MessageId": "1234321",
                    "Type": "Notification",
                    "Message": message,
                }
                res = client.post(
                    "/callbacks/sns/s3/uploaded",
                    data=json.dumps(body_dict),
                    content_type="application/json",
                    headers={"X-Amz-Sns-Subscription-Arn": "kcirtaP"},
                )

                assert res.status_code == 400
                assert mock_app_log.call_args_list == [
                    (
                        (logging.INFO, AnyStringMatching(r"Processing message "), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "message_id": "1234321",
                            "subscription_arn": "kcirtaP",
                        })}),
                    ),
                    (
                        (logging.WARNING, AnyStringMatching(r"Message contents didn't match "), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "message_contents": message,
                        })}),
                    ),
                    (mock.ANY, AnySupersetOf({"extra": AnySupersetOf({"status": 400})}))
                ]
                assert not rmock.request_history
                assert mock_validate.call_args_list == [((body_dict,), AnySupersetOf({}))]
                assert mock_handle_subscription_confirmation.called is False

    @pytest.mark.parametrize("content_type", ("application/json", "text/plain",))
    @mock.patch("validatesns.validate", autospec=True)
    @mock.patch("app.callbacks.views.sns._handle_subscription_confirmation", autospec=True)
    def test_handle_s3_sns_subscription_confirmation(
        self,
        mock_handle_subscription_confirmation,
        mock_validate,
        content_type,
    ):
        # arbitrary sentinel Response
        mock_handle_subscription_confirmation.return_value = Response("Grain supplies"), 200

        with self.mocked_app_logger_log() as mock_app_log:
            with requests_mock.Mocker() as rmock:
                client = self.get_authorized_client()
                res = client.post(
                    "/callbacks/sns/s3/uploaded",
                    data=json.dumps(self._basic_subscription_confirmation_body),
                    content_type=content_type,
                )

                assert res.status_code == 200
                assert res.get_data() == b"Grain supplies"
                assert mock_app_log.call_args_list == [
                    (mock.ANY, AnySupersetOf({"extra": AnySupersetOf({"status": 200})}))
                ]
                assert not rmock.request_history
                assert mock_validate.call_args_list == [
                    ((self._basic_subscription_confirmation_body,), AnySupersetOf({}))
                ]
                assert mock_handle_subscription_confirmation.call_args_list == [
                    ((self._basic_subscription_confirmation_body, "s3_file_upload_notification_development",), {})
                ]

    @pytest.mark.parametrize(
        (
            "initial_tagset",
            "concurrent_new_tagset",
            "clamd_instream_retval",
            "expected_exception",
            "expected_log_calls",
            "expected_notify_calls",
            "expected_tagset",
        ),
        (
            (
                # initial_tagset
                {"existing": "tag123"},
                # concurrent_new_tagset
                {"surprise": "tag234"},
                # clamd_instream_retval
                {"stream": ("OK", "dénouement sufficient",)},
                # expected_exception
                None,
                # expected_log_calls
                (
                    (
                        (logging.INFO, AnyStringMatching(r"Processing message "), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "message_id": "424344def",
                            "subscription_arn": "bull:by:the:horns:123:s3_file_upload_notification_development:314159",
                        })}),
                    ),
                    (
                        (logging.DEBUG, AnyStringMatching(r"Call to S3 \(get object tagging"), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "s3_bucket_name": "spade",
                            "s3_object_key": "sandman/4321-billy-winks.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                    (
                        (logging.INFO, AnyStringMatching(r"Object version .* has no .avStatus. tag "), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "s3_bucket_name": "spade",
                            "s3_object_key": "sandman/4321-billy-winks.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                    (
                        (logging.DEBUG, AnyStringMatching(r"Call to S3 \(initiate object download"), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "s3_bucket_name": "spade",
                            "s3_object_key": "sandman/4321-billy-winks.pdf",
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
                            "s3_object_key": "sandman/4321-billy-winks.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                    (
                        (logging.DEBUG, AnyStringMatching(r"Call to S3 \(put object tagging"), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "s3_bucket_name": "spade",
                            "s3_object_key": "sandman/4321-billy-winks.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                    (
                        (logging.INFO, AnyStringMatching(r"Handled bucket "), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "s3_bucket_name": "spade",
                            "s3_object_key": "sandman/4321-billy-winks.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                    (mock.ANY, AnySupersetOf({"extra": AnySupersetOf({"status": 200})})),
                ),
                # expected_notify_calls
                (),
                # expected_tagset
                {
                    "avStatus": AnyB64Eq(AnyJsonEq({
                        "result": "pass",
                        "clamdVerStr": "ClamAV 567; first watch",
                        "ts": "2010-09-08T07:06:05.040302",
                    })),
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
                # expected_exception
                None,
                # expected_log_calls
                (
                    (
                        (logging.INFO, AnyStringMatching(r"Processing message "), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "message_id": "424344def",
                            "subscription_arn": "bull:by:the:horns:123:s3_file_upload_notification_development:314159",
                        })}),
                    ),
                    (
                        (logging.DEBUG, AnyStringMatching(r"Call to S3 \(get object tagging"), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "s3_bucket_name": "spade",
                            "s3_object_key": "sandman/4321-billy-winks.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                    (
                        (logging.INFO, AnyStringMatching(r"Object version .* has no .avStatus. tag "), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "s3_bucket_name": "spade",
                            "s3_object_key": "sandman/4321-billy-winks.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                    (
                        (logging.DEBUG, AnyStringMatching(r"Call to S3 \(initiate object download"), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "s3_bucket_name": "spade",
                            "s3_object_key": "sandman/4321-billy-winks.pdf",
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
                            "s3_object_key": "sandman/4321-billy-winks.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                    (
                        (logging.DEBUG, AnyStringMatching(r"Call to S3 \(put object tagging"), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "s3_bucket_name": "spade",
                            "s3_object_key": "sandman/4321-billy-winks.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                    (
                        (logging.INFO, AnyStringMatching(r"Handled bucket "), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "s3_bucket_name": "spade",
                            "s3_object_key": "sandman/4321-billy-winks.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                    (mock.ANY, AnySupersetOf({"extra": AnySupersetOf({"status": 200})})),
                ),
                # expected_notify_calls
                (
                    mock.call("not_a_real_key-00000000-fake-uuid-0000-000000000000"),
                    mock.call().send_email(
                        "developer-virus-alert@example.com",
                        personalisation={
                            "bucket_name": "spade",
                            "clamd_output": "FOUND, After him, Garry!",
                            "dm_trace_id": mock.ANY,
                            "file_name": "too ducky.puddeny-pie.pdf",
                            "object_key": "sandman/4321-billy-winks.pdf",
                            "object_version": "0",
                            "region_name": "howth-west-2",
                            "sns_message_id": "424344def",
                        },
                        template_name_or_id="developer_virus_alert",
                    ),
                ),
                # expected_tagset
                {
                    "avStatus": AnyB64Eq(AnyJsonEq({
                        "result": "fail",
                        "clamdVerStr": "ClamAV 567; first watch",
                        "ts": "2010-09-08T07:06:05.040302",
                    })),
                    "surprise": "tag234",
                }
            ),
            (
                # initial_tagset
                {"existing": "tag123"},
                # concurrent_new_tagset
                {"surprise": "tag234"},
                # clamd_instream_retval
                {"stream": ("ERROR", " Some trouble is on here",)},
                # expected_exception
                UnknownClamdError,
                # expected_log_calls
                (
                    (
                        (logging.INFO, AnyStringMatching(r"Processing message "), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "message_id": "424344def",
                            "subscription_arn": "bull:by:the:horns:123:s3_file_upload_notification_development:314159",
                        })}),
                    ),
                    (
                        (logging.DEBUG, AnyStringMatching(r"Call to S3 \(get object tagging"), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "s3_bucket_name": "spade",
                            "s3_object_key": "sandman/4321-billy-winks.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                    (
                        (logging.INFO, AnyStringMatching(r"Object version .* has no .avStatus. tag "), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "s3_bucket_name": "spade",
                            "s3_object_key": "sandman/4321-billy-winks.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                    (
                        (logging.DEBUG, AnyStringMatching(r"Call to S3 \(initiate object download"), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "s3_bucket_name": "spade",
                            "s3_object_key": "sandman/4321-billy-winks.pdf",
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
                            "s3_object_key": "sandman/4321-billy-winks.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                ),
                # expected_notify_calls
                (),
                # expected_tagset
                {"surprise": "tag234"},
            ),
            (
                # initial_tagset
                {"existing": "tag123"},
                # concurrent_new_tagset
                {"avStatus": _b64e('{"result":"fail","ts":"2010-09-08T07:06:04.010101"}')},
                # clamd_instream_retval
                {"stream": ("OK", "Egg two demolished",)},
                # expected_exception
                None,
                # expected_log_calls
                (
                    (
                        (logging.INFO, AnyStringMatching(r"Processing message "), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "message_id": "424344def",
                            "subscription_arn": "bull:by:the:horns:123:s3_file_upload_notification_development:314159",
                        })}),
                    ),
                    (
                        (logging.DEBUG, AnyStringMatching(r"Call to S3 \(get object tagging"), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "s3_bucket_name": "spade",
                            "s3_object_key": "sandman/4321-billy-winks.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                    (
                        (logging.INFO, AnyStringMatching(r"Object version .* has no .avStatus. tag "), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "s3_bucket_name": "spade",
                            "s3_object_key": "sandman/4321-billy-winks.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                    (
                        (logging.DEBUG, AnyStringMatching(r"Call to S3 \(initiate object download"), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "s3_bucket_name": "spade",
                            "s3_object_key": "sandman/4321-billy-winks.pdf",
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
                            "s3_object_key": "sandman/4321-billy-winks.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                    (
                        (
                            logging.WARNING,
                            AnyStringMatching(r"Object was tagged.*existing_av_status.*unapplied_av_status.*"),
                            (),
                        ),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "existing_av_status": '{"result":"fail","ts":"2010-09-08T07:06:04.010101"}',
                            "existing_av_status_raw": _b64e('{"result":"fail","ts":"2010-09-08T07:06:04.010101"}'),
                            "unapplied_av_status": AnyJsonEq({
                                "result": "pass",
                                "clamdVerStr": "ClamAV 567; first watch",
                                "ts": "2010-09-08T07:06:05.040302",
                            }),
                            "unapplied_av_status_raw": AnyB64Eq(AnyJsonEq({
                                "result": "pass",
                                "clamdVerStr": "ClamAV 567; first watch",
                                "ts": "2010-09-08T07:06:05.040302",
                            })),
                        })}),
                    ),
                    (
                        (logging.INFO, AnyStringMatching(r"Handled bucket "), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "s3_bucket_name": "spade",
                            "s3_object_key": "sandman/4321-billy-winks.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                    (mock.ANY, AnySupersetOf({"extra": AnySupersetOf({"status": 200})})),
                ),
                # expected_notify_calls
                (),
                # expected_tagset
                {"avStatus": _b64e('{"result":"fail","ts":"2010-09-08T07:06:04.010101"}')},
            ),
            (
                # initial_tagset
                {"existing": "tag123"},
                # concurrent_new_tagset
                {"avStatus": _b64e('{"result":"pass","ts":"2010-09-08T07:06:04.010101","mead":"Übermensch"}')},
                # clamd_instream_retval
                {"stream": ("FOUND", "After him, boy!",)},
                # expected_exception
                None,
                # expected_log_calls
                (
                    (
                        (logging.INFO, AnyStringMatching(r"Processing message "), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "message_id": "424344def",
                            "subscription_arn": "bull:by:the:horns:123:s3_file_upload_notification_development:314159",
                        })}),
                    ),
                    (
                        (logging.DEBUG, AnyStringMatching(r"Call to S3 \(get object tagging"), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "s3_bucket_name": "spade",
                            "s3_object_key": "sandman/4321-billy-winks.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                    (
                        (logging.INFO, AnyStringMatching(r"Object version .* has no .avStatus. tag "), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "s3_bucket_name": "spade",
                            "s3_object_key": "sandman/4321-billy-winks.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                    (
                        (logging.DEBUG, AnyStringMatching(r"Call to S3 \(initiate object download"), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "s3_bucket_name": "spade",
                            "s3_object_key": "sandman/4321-billy-winks.pdf",
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
                            "s3_object_key": "sandman/4321-billy-winks.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                    (
                        (
                            logging.WARNING,
                            AnyStringMatching(r"Object was tagged.*existing_av_status.*unapplied_av_status.*"),
                            (),
                        ),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "existing_av_status": '{"result":"pass","ts":"2010-09-08T07:06:04.010101"'
                                                  ',"mead":"Übermensch"}',
                            "existing_av_status_raw": _b64e(
                                '{"result":"pass","ts":"2010-09-08T07:06:04.010101","mead":"Übermensch"}'
                            ),
                            "unapplied_av_status": AnyJsonEq({
                                "result": "fail",
                                "clamdVerStr": "ClamAV 567; first watch",
                                "ts": "2010-09-08T07:06:05.040302",
                            }),
                            "unapplied_av_status_raw": AnyB64Eq(AnyJsonEq({
                                "result": "fail",
                                "clamdVerStr": "ClamAV 567; first watch",
                                "ts": "2010-09-08T07:06:05.040302",
                            })),
                        })}),
                    ),
                    (
                        (logging.INFO, AnyStringMatching(r"Handled bucket "), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "s3_bucket_name": "spade",
                            "s3_object_key": "sandman/4321-billy-winks.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                    (mock.ANY, AnySupersetOf({"extra": AnySupersetOf({"status": 200})})),
                ),
                # expected_notify_calls
                (),
                # expected_tagset
                {"avStatus": _b64e('{"result":"pass","ts":"2010-09-08T07:06:04.010101","mead":"Übermensch"}')},
            ),
            (
                # initial_tagset
                {"avStatus": _b64e('{"result":"pass","ts":"2010-09-08T07:06:04.010101"}')},
                # concurrent_new_tagset
                None,
                # clamd_instream_retval
                None,
                # expected_exception
                None,
                # expected_log_calls
                (
                    (
                        (logging.INFO, AnyStringMatching(r"Processing message "), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "message_id": "424344def",
                            "subscription_arn": "bull:by:the:horns:123:s3_file_upload_notification_development:314159",
                        })}),
                    ),
                    (
                        (logging.DEBUG, AnyStringMatching(r"Call to S3 \(get object tagging"), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "s3_bucket_name": "spade",
                            "s3_object_key": "sandman/4321-billy-winks.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                    (
                        (logging.INFO, AnyStringMatching(r"Object version.*already.*avStatus.*tag.+"), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "existing_av_status": '{"result":"pass","ts":"2010-09-08T07:06:04.010101"}',
                            "existing_av_status_raw": _b64e('{"result":"pass","ts":"2010-09-08T07:06:04.010101"}'),
                            "s3_bucket_name": "spade",
                            "s3_object_key": "sandman/4321-billy-winks.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                    (
                        (logging.INFO, AnyStringMatching(r"Handled bucket "), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "s3_bucket_name": "spade",
                            "s3_object_key": "sandman/4321-billy-winks.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                    (mock.ANY, AnySupersetOf({"extra": AnySupersetOf({"status": 200})})),
                ),
                # expected_notify_calls
                (),
                # expected_tagset
                {"avStatus": _b64e('{"result":"pass","ts":"2010-09-08T07:06:04.010101"}')},
            ),
            (
                # initial_tagset
                {"avStatus": _b64e('{"result":"fail","ts":"2010-09-08T07:06:04.010101"}')},
                # concurrent_new_tagset
                None,
                # clamd_instream_retval
                None,
                # expected_exception
                None,
                # expected_log_calls
                (
                    (
                        (logging.INFO, AnyStringMatching(r"Processing message "), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "message_id": "424344def",
                            "subscription_arn": "bull:by:the:horns:123:s3_file_upload_notification_development:314159",
                        })}),
                    ),
                    (
                        (logging.DEBUG, AnyStringMatching(r"Call to S3 \(get object tagging"), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "s3_bucket_name": "spade",
                            "s3_object_key": "sandman/4321-billy-winks.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                    (
                        (logging.INFO, AnyStringMatching(r"Object version.*already.*avStatus.*tag.+"), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "existing_av_status": '{"result":"fail","ts":"2010-09-08T07:06:04.010101"}',
                            "existing_av_status_raw": _b64e('{"result":"fail","ts":"2010-09-08T07:06:04.010101"}'),
                            "s3_bucket_name": "spade",
                            "s3_object_key": "sandman/4321-billy-winks.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                    (
                        (logging.INFO, AnyStringMatching(r"Handled bucket "), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "s3_bucket_name": "spade",
                            "s3_object_key": "sandman/4321-billy-winks.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                    (mock.ANY, AnySupersetOf({"extra": AnySupersetOf({"status": 200})})),
                ),
                # expected_notify_calls
                (),
                # expected_tagset
                {"avStatus": _b64e('{"result":"fail","ts":"2010-09-08T07:06:04.010101"}')},
            ),
            (
                # initial_tagset
                {
                    "avStatus": ":not valid base64:",
                    "existing": "123tag",
                },
                # concurrent_new_tagset
                None,
                # clamd_instream_retval
                None,
                # expected_exception
                None,
                # expected_log_calls
                (
                    (
                        (logging.INFO, AnyStringMatching(r"Processing message "), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "message_id": "424344def",
                            "subscription_arn": "bull:by:the:horns:123:s3_file_upload_notification_development:314159",
                        })}),
                    ),
                    (
                        (logging.DEBUG, AnyStringMatching(r"Call to S3 \(get object tagging"), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "s3_bucket_name": "spade",
                            "s3_object_key": "sandman/4321-billy-winks.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                    (
                        (logging.INFO, AnyStringMatching(r"Object version.*already.*avStatus.*tag.+"), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "existing_av_status": None,
                            "existing_av_status_raw": ':not valid base64:',
                            "s3_bucket_name": "spade",
                            "s3_object_key": "sandman/4321-billy-winks.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                    (
                        (logging.INFO, AnyStringMatching(r"Handled bucket "), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "s3_bucket_name": "spade",
                            "s3_object_key": "sandman/4321-billy-winks.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                    (mock.ANY, AnySupersetOf({"extra": AnySupersetOf({"status": 200})})),
                ),
                # expected_notify_calls
                (),
                # expected_tagset
                {
                    "avStatus": ":not valid base64:",
                    "existing": "123tag",
                },
            ),
            (
                # initial_tagset
                None,
                # concurrent_new_tagset
                {"avStatus": ":not/valid/base64:"},
                # clamd_instream_retval
                {"stream": ("OK", "Ormond Bar",)},
                # expected_exception
                None,
                # expected_log_calls
                (
                    (
                        (logging.INFO, AnyStringMatching(r"Processing message "), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "message_id": "424344def",
                            "subscription_arn": "bull:by:the:horns:123:s3_file_upload_notification_development:314159",
                        })}),
                    ),
                    (
                        (logging.DEBUG, AnyStringMatching(r"Call to S3 \(get object tagging"), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "s3_bucket_name": "spade",
                            "s3_object_key": "sandman/4321-billy-winks.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                    (
                        (logging.INFO, AnyStringMatching(r"Object version .* has no .avStatus. tag "), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "s3_bucket_name": "spade",
                            "s3_object_key": "sandman/4321-billy-winks.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                    (
                        (logging.DEBUG, AnyStringMatching(r"Call to S3 \(initiate object download"), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "s3_bucket_name": "spade",
                            "s3_object_key": "sandman/4321-billy-winks.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                    (
                        (logging.INFO, AnyStringMatching(r"Scanned "), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "file_length": 12,
                            "file_name": "too ducky.puddeny-pie.pdf",
                            "clamd_result": ("OK", "Ormond Bar"),
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
                            "s3_object_key": "sandman/4321-billy-winks.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                    (
                        (
                            logging.WARNING,
                            AnyStringMatching(r"Object was tagged.*existing_av_status.*unapplied_av_status.*"),
                            (),
                        ),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "existing_av_status": None,
                            "existing_av_status_raw": ":not/valid/base64:",
                            "unapplied_av_status": AnyJsonEq({
                                "result": "pass",
                                "clamdVerStr": "ClamAV 567; first watch",
                                "ts": "2010-09-08T07:06:05.040302",
                            }),
                            "unapplied_av_status_raw": AnyB64Eq(AnyJsonEq({
                                "result": "pass",
                                "clamdVerStr": "ClamAV 567; first watch",
                                "ts": "2010-09-08T07:06:05.040302",
                            })),
                        })}),
                    ),
                    (
                        (logging.INFO, AnyStringMatching(r"Handled bucket "), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "s3_bucket_name": "spade",
                            "s3_object_key": "sandman/4321-billy-winks.pdf",
                            "s3_object_version": "0",
                        })}),
                    ),
                    (mock.ANY, AnySupersetOf({"extra": AnySupersetOf({"status": 200})})),
                ),
                # expected_notify_calls
                (),
                # expected_tagset
                {"avStatus": ":not/valid/base64:"},
            ),
        ),
    )
    @freeze_time("2010-09-08T07:06:05.040302")
    @mock.patch("validatesns.validate", autospec=True)
    @mock.patch("app.callbacks.views.sns._handle_subscription_confirmation", autospec=True)
    @mock.patch("app.callbacks.views.sns.DMNotifyClient", autospec=True)
    def test_handle_s3_sns_notification(
        self,
        mock_notify_client,
        mock_handle_subscription_confirmation,
        mock_validate,
        bucket_with_file,
        mock_clamd,
        initial_tagset,
        concurrent_new_tagset,
        clamd_instream_retval,
        expected_exception,
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
        :param expected_exception:    Exception subclass to expect to be raised by request, None to expect a successful
                                      (status 200) response
        :param expected_log_calls:    sequence of expected mock.call()s to have been made to app logger
        :param expected_notify_calls: sequence of expected mock.call()s to have been made to mock DMNotifyClient
        :param expected_tagset:       tagset (dict) to expect file to have after the request processing has finished
        """
        bucket, objver = bucket_with_file
        s3_client = boto3.client("s3", region_name=_aws_region)

        if initial_tagset is not None:
            s3_client.put_object_tagging(
                Bucket=bucket.name,
                Key=objver.Object().key,
                VersionId=objver.id,
                Tagging={"TagSet": _tagset_from_dict(initial_tagset)},
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
                    Tagging={"TagSet": _tagset_from_dict(concurrent_new_tagset)},
                )

            return clamd_instream_retval

        mock_clamd.instream.side_effect = clamd_instream_func
        mock_clamd.version.return_value = "ClamAV 567; first watch"
        with self.mocked_app_logger_log() as mock_app_log:
            client = self.get_authorized_client()
            body_dict = {
                **self._basic_notification_body,
                "TopicArn": "bull:by:the:horns:123:s3_file_upload_notification_development",
                "Subject": "Someone uploaded a file, yeah?",
                "Message": json.dumps({
                    "Records": [
                        {
                            "s3": {
                                "bucket": {
                                    "name": bucket.name,
                                },
                                "object": {
                                    "key": objver.Object().key,
                                    "versionId": objver.id,
                                },
                            },
                            "awsRegion": _aws_region,
                        },
                    ],
                }),
            }
            subscription_arn = f"{body_dict['TopicArn']}:314159"

            with pytest.raises(expected_exception) if expected_exception else null_context_manager():
                res = client.post(
                    "/callbacks/sns/s3/uploaded",
                    data=json.dumps(body_dict),
                    content_type="application/json",
                    headers={"X-Amz-Sns-Subscription-Arn": subscription_arn},
                )

            if not expected_exception:
                assert res.status_code == 200

            assert mock_app_log.call_args_list == list(expected_log_calls)
            assert mock_notify_client.mock_calls == list(expected_notify_calls)

            assert _dict_from_tagset(
                s3_client.get_object_tagging(
                    Bucket=bucket.name,
                    Key=objver.Object().key,
                    VersionId=objver.id,
                )["TagSet"]
            ) == expected_tagset
