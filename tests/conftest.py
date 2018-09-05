import mock

import clamd

import pytest


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
    env_patch = mock.patch('os.environ', {})
    request.addfinalizer(env_patch.stop)

    return env_patch.start()
