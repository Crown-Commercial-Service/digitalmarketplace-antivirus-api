from flask import current_app

import clamd


# the only reason this exists as two functions is to allow for easy mocking. it is likely modules will take a reference
# to the "public" get_clamd_socket through imports early in initialization, making it hard to mock globally. if the
# mocker instead targets _get_clamd_socket_inner, it should be able to catch all calls thereor as it's only ever
# accessed as a module-local reference
def _get_clamd_socket_inner():
    return clamd.ClamdUnixSocket(path=current_app.config["DM_CLAMD_UNIX_SOCKET_PATH"])


def get_clamd_socket():
    return _get_clamd_socket_inner()


class UnknownClamdError(Exception):
    pass
