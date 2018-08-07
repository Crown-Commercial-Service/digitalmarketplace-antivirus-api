from flask import current_app

import clamd


def get_clamd_socket():
    return clamd.ClamdUnixSocket(path=current_app.config["DM_CLAMD_UNIX_SOCKET_PATH"])
