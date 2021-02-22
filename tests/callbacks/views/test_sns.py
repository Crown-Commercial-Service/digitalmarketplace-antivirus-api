from itertools import chain
import json
import logging
from urllib.parse import quote_plus

from freezegun import freeze_time
from flask.wrappers import Response
from defusedxml.ElementTree import ParseError
import mock
import pytest
import requests
import requests_mock
import validatesns
from werkzeug.exceptions import BadRequest

from dmtestutils.comparisons import AnySupersetOf, AnyStringMatching, RestrictedAny

from app.callbacks.views.sns import (
    _get_certificate,
    _handle_subscription_confirmation,
)

from ..helpers import BaseCallbackApplicationTest
from ...helpers import null_context_manager


pytestmark = pytest.mark.usefixtures("force_all_logged_duration")


@pytest.fixture(autouse=True)
def clear_get_certificate_cache():
    # reset the lru_cache both before and after test in case there is an unaware test before or after it that also
    # hits _get_certificate()
    _get_certificate.cache_clear()
    yield
    _get_certificate.cache_clear()


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
                    {"SubscribeURL": "https://amz.net", "TopicArn": f"arn:aws:sns:howth-west-2:123456789012:Drawers"},
                    # supported_topic_name
                    "Drawers",
                    # rmock_response_kwargs
                    {"text": f"""<ConfirmSubscriptionResponse xmlns="http://brazenfaced.things">
                        <ConfirmSubscriptionResult><SubscriptionArn>
                            arn:aws:sns:howth-west-2:123456789012:Drawers:bicycles
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
                                    "topic_arn": f"arn:aws:sns:howth-west-2:123456789012:Drawers",
                                }),
                            }),
                        ),
                        (
                            (logging.INFO, AnyStringMatching("SubscriptionConfirmation succeeded "), ()),
                            AnySupersetOf({
                                "extra": AnySupersetOf({
                                    "subscription_arn": f"arn:aws:sns:howth-west-2:123456789012:Drawers:bicycles",
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
                    BadRequest,
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
                    BadRequest,
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
                    BadRequest,
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

    _test_handle_s3_sns_unexpected_message_contents_didnt_match_log_args = lambda message: (  # noqa
        (logging.WARNING, AnyStringMatching(r"Message contents didn't match "), ()),
        AnySupersetOf({"extra": AnySupersetOf({
            "message_contents": message,
        })}),
    )
    _test_handle_s3_sns_unexpected_message_unrecognized_message_format_log_args = lambda message: (  # noqa
        (logging.WARNING, AnyStringMatching(r"Unrecognized message format "), ()),
        AnySupersetOf({"extra": AnySupersetOf({
            "body_message": message,
        })}),
    )

    @pytest.mark.parametrize(
        "message,expected_warning_log_call",
        (
            ("mangiD", _test_handle_s3_sns_unexpected_message_contents_didnt_match_log_args("mangiD"),),
            (123, _test_handle_s3_sns_unexpected_message_contents_didnt_match_log_args(123),),
            (None, _test_handle_s3_sns_unexpected_message_contents_didnt_match_log_args(None),),
            ("", _test_handle_s3_sns_unexpected_message_contents_didnt_match_log_args(""),),
            ('{"a":"b"}', _test_handle_s3_sns_unexpected_message_unrecognized_message_format_log_args({"a": "b"}),),
        ),
    )
    @mock.patch("validatesns.validate", autospec=True)
    @mock.patch("app.callbacks.views.sns._handle_subscription_confirmation", autospec=True)
    def test_handle_s3_sns_unexpected_message(
        self,
        mock_handle_subscription_confirmation,
        mock_validate,
        message,
        expected_warning_log_call,
    ):
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
                    expected_warning_log_call,
                    (mock.ANY, AnySupersetOf({"extra": AnySupersetOf({"status": 400})}))
                ]
                assert not rmock.request_history
                assert mock_validate.call_args_list == [((body_dict,), AnySupersetOf({}))]
                assert mock_handle_subscription_confirmation.called is False

    @mock.patch("validatesns.validate", autospec=True)
    @mock.patch("app.callbacks.views.sns._handle_subscription_confirmation", autospec=True)
    def test_handle_s3_sns_test_event(
        self,
        mock_handle_subscription_confirmation,
        mock_validate,
    ):
        with self.mocked_app_logger_log() as mock_app_log:
            with requests_mock.Mocker() as rmock:
                client = self.get_authorized_client()
                body_dict = {
                    "MessageId": "1234321",
                    "Type": "Notification",
                    "Message": '{"Event":"s3:TestEvent","nut":"shell"}',
                }
                res = client.post(
                    "/callbacks/sns/s3/uploaded",
                    data=json.dumps(body_dict),
                    content_type="application/json",
                    headers={"X-Amz-Sns-Subscription-Arn": "kcirtaP"},
                )

                assert res.status_code == 200
                assert mock_app_log.call_args_list == [
                    (
                        (logging.INFO, AnyStringMatching(r"Processing message "), ()),
                        AnySupersetOf({"extra": AnySupersetOf({
                            "message_id": "1234321",
                            "subscription_arn": "kcirtaP",
                        })}),
                    ),
                    (
                        (logging.INFO, "Received S3 test event", ()),
                        {},
                    ),
                    (mock.ANY, AnySupersetOf({"extra": AnySupersetOf({"status": 200})}))
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

    @pytest.mark.parametrize("content_type", ("application/json", "text/plain",))
    @mock.patch("app.callbacks.views.sns.scan_and_tag_s3_object", autospec=True)
    @mock.patch("validatesns.validate", autospec=True)
    def test_handle_s3_sns_notification(
        self,
        mock_validate,
        mock_scan_and_tag_s3_object,
        content_type,
        bucket_with_file,
    ):
        bucket, objver = bucket_with_file

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
                                    "key": quote_plus(objver.Object().key),
                                    "versionId": objver.id,
                                },
                            },
                            "awsRegion": "howth-west-2",
                        },
                    ],
                }),
            }
            subscription_arn = f"{body_dict['TopicArn']}:314159"

            res = client.post(
                "/callbacks/sns/s3/uploaded",
                data=json.dumps(body_dict),
                content_type=content_type,
                headers={"X-Amz-Sns-Subscription-Arn": subscription_arn},
            )

            assert res.status_code == 200
            assert mock_app_log.call_args_list == [
                (
                    (logging.INFO, AnyStringMatching(r"Processing message "), ()),
                    AnySupersetOf({"extra": AnySupersetOf({
                        "message_id": "424344def",
                        "subscription_arn": "bull:by:the:horns:123:s3_file_upload_notification_development:314159",
                    })}),
                ),
                (mock.ANY, AnySupersetOf({"extra": AnySupersetOf({"status": 200})})),
            ]
            assert mock_validate.call_args_list == [
                ((body_dict,), AnySupersetOf({}))
            ]
            assert mock_scan_and_tag_s3_object.call_args_list == [
                mock.call(
                    s3_client=mock.ANY,
                    s3_bucket_name=bucket.name,
                    s3_object_key=objver.Object().key,
                    s3_object_version=objver.id,
                    sns_message_id="424344def",
                ),
            ]
