import clamd
from flask import current_app, request
from psutil import net_connections, Process

from . import status
from ..clam import get_clamd_socket
from dmutils.status import get_app_status, StatusError


def get_clamd_status():
    """
        This "additional checks" function performs a very relaxed (but fast!) test to get an idea whether the clamd
        server is running or not FSVO "running". By that we mean that there is a process listening on
        DM_CLAMD_UNIX_SOCKET_PATH and that process is able to respond to signals (not stuck in an "uninterruptible"
        state). PaaS healthcheck requests have tight time constraints and it would seem that any more thorough clamd
        status checks can't reliably return within a second.
    """
    try:
        pid = next(
            conn.pid
            for conn in net_connections(kind="unix")
            if conn.laddr == current_app.config["DM_CLAMD_UNIX_SOCKET_PATH"]
        )
    except StopIteration:
        raise StatusError('No connection found matching DM_CLAMD_UNIX_SOCKET_PATH')

    if not pid:
        # insufficient permissions?
        raise StatusError("Unable to determine pid of process connected to DM_CLAMD_UNIX_SOCKET_PATH")

    process = Process(pid)
    process.send_signal(0)

    return {
        'clamd': {
            'process': 'alive',
        },
    }


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
        additional_checks=[get_clamd_status_extended],
        additional_checks_internal=[get_clamd_status],
    )
