import datetime
from functools import lru_cache
import json
import logging
import sys

from flask import abort, jsonify, current_app, request
from lxml.etree import fromstring as etree_fromstring, ParseError
import requests

import validatesns

from dmutils.timing import logged_duration

from app.callbacks import callbacks
from app.s3 import scan_s3_object


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
        scan_s3_object(
            aws_region=record["awsRegion"],
            s3_bucket_name=record["s3"]["bucket"]["name"],
            s3_object_key=record["s3"]["object"]["key"],
            s3_object_version=record["s3"]["object"]["versionId"],
            sns_message_id=body_dict["MessageId"],
        )

    return jsonify(status="ok", dmTraceId=request.trace_id), 200
