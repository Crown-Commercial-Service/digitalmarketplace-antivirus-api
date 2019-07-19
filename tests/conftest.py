import mock

import boto3
import clamd

from moto.s3 import mock_s3
import pytest

from dmutils.timing import logged_duration


_aws_region = "howth-west-2"


@pytest.fixture()
def mock_clamd():
    with mock.patch(
        "app.clam._get_clamd_socket_inner",
        autospec=True,
        return_value=mock.create_autospec(clamd.ClamdUnixSocket, instance=True, spec_set=True),
    ) as mock_get_clamd_socket:
        yield mock_get_clamd_socket.return_value


@pytest.fixture
def os_environ(request):
    with mock.patch('os.environ', {}) as mock_os_environ:
        yield mock_os_environ


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
    obj = empty_bucket.Object("sandman/+4321 billy-winks☾.pdf")
    obj.put(
        Body=b"123412341234",
        Metadata={
            "timestamp": "2005-04-03T02:01:00.12345Z",
        },
        ContentType="application/pdf",
        ContentDisposition='attachment; filename="too ducky.puddeny-pie.pdf"',
    )
    yield bucket, obj.Version(obj.version_id)


@pytest.fixture
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
            with mock.patch("app.s3.logged_duration", autospec=True) as mock_s3_logged_duration:
                mock_s3_logged_duration.side_effect = logged_duration_wrapper
                yield
