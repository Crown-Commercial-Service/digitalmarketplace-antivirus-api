import clamd
from flask import current_app, request
from psutil import net_connections

from . import status
from ..clam import get_clamd_socket
from dmutils.status import get_app_status, StatusError


def get_clamd_status():
    if clamd_net_addr := current_app.config.get("DM_CLAMD_NET_ADDR"):
        _check_net_clamd_status(clamd_net_addr)
    else:
        _check_socket_clamd_status(current_app.config["DM_CLAMD_UNIX_SOCKET_PATH"])

    return {
        'clamd': {
            'process': 'alive',
        },
    }


def _check_net_clamd_status(net_addr):
    if not any(
            conn.raddr == net_addr
            for conn in net_connections(kind="inet4")
    ):
        raise StatusError(f'No connection found matching ${net_addr}')


def _check_socket_clamd_status(socket_path):
    """
        This "additional checks" function performs a very relaxed (but fast!) test to get an idea whether the clamd
        server is running or not FSVO "running". By that we mean that there is a process listening on
        DM_CLAMD_UNIX_SOCKET_PATH. We can't unfortunately find out much more about that process with the permissions
        that a webserver process has in production.
    """
    if not any(
            conn.laddr == socket_path
            for conn in net_connections(kind="unix")
    ):
        raise StatusError(f'No connection found matching ${socket_path}')


def get_clamd_status_extended():
    """
        More thorough tests of clamd's operational state for when the request doesn't have such tight time constraints
    """
    client = get_clamd_socket()

    try:
        if client.ping() == 'PONG':
            return {
                'clamd.extended': {
                    'ping': 'OK',
                    'stats': client.stats(),
                },
            }

    except clamd.ClamdError as e:
        raise StatusError(str(e))

    raise StatusError('Unknown error')


@status.route('/_status')
def status():
    return get_app_status(
        ignore_dependencies='ignore-dependencies' in request.args,
        additional_checks=[get_clamd_status],
        additional_checks_extended=[get_clamd_status_extended],
    )
