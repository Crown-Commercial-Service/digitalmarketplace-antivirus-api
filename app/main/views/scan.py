from io import BytesIO

import boto3
import clamd
from flask import abort, jsonify, request, current_app

from dmutils.timing import logged_duration_for_external_request as log_external_request

from app.clam import get_clamd_socket
from app.decorators import json_payload_view, require_json_keys
from app.main import main
from app.s3 import scan_and_tag_s3_object


@main.route('/scan/direct', methods=['POST'])
def scan_direct():
    if 'document' not in request.files:
        abort(400, 'The file for scanning should be uploaded under the name `document`.')

    file = request.files['document']

    try:
        client = get_clamd_socket()

        with log_external_request(service='ClamAV', description='instream scan via unix socket'):
            scan_result = client.instream(BytesIO(file.stream.read()))['stream']

    except clamd.ClamdError as e:
        current_app.logger.error(f'Unable to scan file: {str(e)}')
        return abort(500)

    response_json = {
        'infectionFound': False if scan_result[0] == 'OK' else True,
        'details': scan_result[1:]
    }

    return jsonify(response_json), 200


@main.route('/scan/s3-object', methods=["PUT", "POST"])
@json_payload_view()
@require_json_keys(("bucketName", "objectKey", "objectVersionId",))
def scan_s3_object(body_dict):
    s3_client = boto3.client("s3", region_name=current_app.config["DM_DEFAULT_AWS_REGION"])

    # it's easier to pre-check the existence of the s3 object and generate error messages from the results than to
    # attempt to catch & interpret various errors bubbling up from scan_and_tag_s3_object when we run into them there
    try:
        with log_external_request(
            "S3",
            "get object tagging [{s3_bucket_name}/{s3_object_key} versionId {s3_object_version}]",
            logger=current_app.logger,
        ) as log_context_s3:
            log_context_s3.update({
                "s3_bucket_name": body_dict["bucketName"],
                "s3_object_key": body_dict["objectKey"],
                "s3_object_version": body_dict["objectVersionId"],
            })
            s3_client.head_object(
                Bucket=body_dict["bucketName"],
                Key=body_dict["objectKey"],
                VersionId=body_dict["objectVersionId"],
            )
    except s3_client.exceptions.NoSuchBucket:
        abort(400, f"Bucket {body_dict['bucketName']!r} not found")
    except s3_client.exceptions.ClientError as e:
        if e.response.get("Error", {}).get("Code") == "404":
            # it doesn't appear to be easily discernable whether a 404 is due to a missing version id or missing key
            # altogether, so an all-in-one error message
            abort(
                400,
                f"Object with key {body_dict['objectKey']!r} and version {body_dict['objectVersionId']!r} not found in "
                f"bucket {body_dict['bucketName']!r}",
            )
        elif e.response.get("Error", {}).get("Code") == "403":
            current_app.logger.warning(e)
            abort(
                400,
                f"Access to key {body_dict['objectKey']!r} version {body_dict['objectVersionId']!r} in bucket "
                f"{body_dict['bucketName']!r} forbidden",
            )
        # unexpected ClientError, we should probably know about this so re-raise
        raise

    old_av_status, applied, new_av_status = scan_and_tag_s3_object(
        s3_client=s3_client,
        s3_bucket_name=body_dict["bucketName"],
        s3_object_key=body_dict["objectKey"],
        s3_object_version=body_dict["objectVersionId"],
    )

    return jsonify(
        # any avStatus.* tags the object already had or were added while we were busy scanning
        existingAvStatus=old_av_status,
        # the newly-calculated avStatus, if scanning was performed
        newAvStatus=new_av_status,
        # whether the new avStatus was actually applied to the s3 object tags
        avStatusApplied=applied,
    ), 200
