import clamd
from flask import request

from . import status
from ..clam import get_clamd_socket
from dmutils.status import get_app_status, StatusError


def get_clamd_stats():
    client = get_clamd_socket()

    try:
        return {
            'clamd.extended': {
                'stats': client.stats(),
            },
        }

    except clamd.ClamdError as e:
        raise StatusError(str(e))

    raise StatusError('Unknown error')


def get_clamd_status():
    client = get_clamd_socket()

    try:
        if client.ping() == 'PONG':
            return {
                'clamd': {
                    'status': 'OK',
                },
            }

    except clamd.ClamdError as e:
        raise StatusError(str(e))

    raise StatusError('Unknown error')


@status.route('/_status')
def status():
    return get_app_status(
        ignore_dependencies='ignore-dependencies' in request.args,
        additional_checks=[get_clamd_stats],
        additional_checks_internal=[get_clamd_status],
    )
