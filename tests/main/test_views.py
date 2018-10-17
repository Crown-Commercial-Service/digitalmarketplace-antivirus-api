import json
import mock

import pytest

from ..helpers import BaseApplicationTest


@pytest.mark.parametrize("method", ("PUT", "POST",))
class TestScanS3Object(BaseApplicationTest):
    @mock.patch("app.main.views.scan.scan_and_tag_s3_object", autospec=True)
    def test_missing_json_keys(self, mock_scan_and_tag_s3_object, method):
        client = self.get_authorized_client()
        res = client.open(
            "/scan/s3-object",
            method=method,
            data=json.dumps({
                "bucketName": "defense-duriner",
                "objectVersionId": "abcdef54321wxyz",
            }),
            content_type="application/json",
        )

        assert res.status_code == 400
        assert res.content_type == "application/json"
        assert json.loads(res.get_data()) == {
            "error": "Expected top-level JSON keys: ['objectKey']",
        }

        assert mock_scan_and_tag_s3_object.called is False

    @mock.patch("app.main.views.scan.scan_and_tag_s3_object", autospec=True)
    def test_json_not_obj(self, mock_scan_and_tag_s3_object, method):
        client = self.get_authorized_client()
        res = client.open(
            "/scan/s3-object",
            method=method,
            data=json.dumps(54321),
            content_type="application/json",
        )

        assert res.status_code == 400
        assert res.content_type == "application/json"
        assert json.loads(res.get_data()) == {
            "error": "Expected content to be JSON object",
        }

        assert mock_scan_and_tag_s3_object.called is False

    @mock.patch("app.main.views.scan.scan_and_tag_s3_object", autospec=True)
    def test_nonexistent_bucket(self, mock_scan_and_tag_s3_object, s3_mock, method):
        client = self.get_authorized_client()
        res = client.open(
            "/scan/s3-object",
            method=method,
            data=json.dumps({
                "bucketName": "defense-duriner",
                "objectKey": "sublime-mason.odt",
                "objectVersionId": "abcdef54321wxyz",
            }),
            content_type="application/json",
        )

        assert res.status_code == 400
        assert res.content_type == "application/json"
        assert json.loads(res.get_data()) == {
            "error": "Bucket 'defense-duriner' not found",
        }

        assert mock_scan_and_tag_s3_object.called is False

    @mock.patch("app.main.views.scan.scan_and_tag_s3_object", autospec=True)
    def test_nonexistent_object(self, mock_scan_and_tag_s3_object, empty_bucket, method):
        client = self.get_authorized_client()
        res = client.open(
            "/scan/s3-object",
            method=method,
            data=json.dumps({
                "bucketName": empty_bucket.name,
                "objectKey": "sublime-mason.odt",
                "objectVersionId": "abcdef54321wxyz",
            }),
            content_type="application/json",
        )

        assert res.status_code == 400
        assert res.content_type == "application/json"
        assert json.loads(res.get_data()) == {
            "error": "Object with key 'sublime-mason.odt' and version 'abcdef54321wxyz' not found in bucket 'spade'",
        }

        assert mock_scan_and_tag_s3_object.called is False

    @mock.patch("app.main.views.scan.scan_and_tag_s3_object", autospec=True)
    def test_nonexistent_version(self, mock_scan_and_tag_s3_object, bucket_with_file, method):
        bucket, objver = bucket_with_file
        client = self.get_authorized_client()
        res = client.open(
            "/scan/s3-object",
            method=method,
            data=json.dumps({
                "bucketName": bucket.name,
                "objectKey": objver.Object().key,
                "objectVersionId": "abcdef54321wxyz",
            }),
            content_type="application/json",
        )

        assert res.status_code == 400
        assert res.content_type == "application/json"
        assert json.loads(res.get_data()) == {
            "error": (
                "Object with key 'sandman/4321-billy-winks.pdf' and version 'abcdef54321wxyz' not found in "
                "bucket 'spade'"
            ),
        }

        assert mock_scan_and_tag_s3_object.called is False

    @mock.patch("app.main.views.scan.scan_and_tag_s3_object", autospec=True)
    def test_correct_passthrough(self, mock_scan_and_tag_s3_object, bucket_with_file, method):
        bucket, objver = bucket_with_file
        client = self.get_authorized_client()
        mock_scan_and_tag_s3_object.return_value = {"delectable": "swig"}, True, {"gurgling": "noise"}
        res = client.open(
            "/scan/s3-object",
            method=method,
            data=json.dumps({
                "bucketName": bucket.name,
                "objectKey": objver.Object().key,
                "objectVersionId": objver.id,
            }),
            content_type="application/json",
        )

        assert res.status_code == 200
        assert res.content_type == "application/json"
        assert json.loads(res.get_data()) == {
            "existingAvStatus": {"delectable": "swig"},
            "avStatusApplied": True,
            "newAvStatus": {"gurgling": "noise"},
        }

        assert mock_scan_and_tag_s3_object.call_args_list == [
            mock.call(
                s3_client=mock.ANY,
                s3_bucket_name=bucket.name,
                s3_object_key=objver.Object().key,
                s3_object_version=objver.id,
            )
        ]
