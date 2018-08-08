from io import BytesIO

import clamd
from flask import abort, jsonify, request, current_app

from dmutils.timing import logged_duration_for_external_request

from app.main import main
from app.clam import get_clamd_socket


@main.route('/scan', methods=['POST'])
def scan():
    if 'document' not in request.files:
        abort(400, 'The file for scanning should be uploaded under the name `document`.')

    file = request.files['document']

    try:
        client = get_clamd_socket()

        with logged_duration_for_external_request(service='ClamAV', description='instream scan via unix socket'):
            scan_result = client.instream(BytesIO(file.stream.read()))['stream']

    except clamd.ClamdError as e:
        current_app.logger.error(f'Unable to scan file: {str(e)}')
        return abort(500)

    response_json = {
        'infectionFound': False if scan_result[0] == 'OK' else True,
        'details': scan_result[1:]
    }

    return jsonify(response_json), 200
