import json

from flask import current_app, jsonify
from werkzeug.exceptions import default_exceptions

from .main import main


class ValidationError(ValueError):
    def __init__(self, message):
        self.message = message


@main.app_errorhandler(ValidationError)
def validation_error(e):
    return jsonify(error=e.message), 400


def generic_error_handler(e):
    try:
        # initially we'll try and assume this is an HTTPException of some sort.  for the most part, the default
        # HTTPExceptions render themselves in the desired way if returned as a response. the only change we want to
        # make is to enclose the error description in json.
        response = e.get_response()
        response.set_data(json.dumps({"error": e.description}))
        response.mimetype = current_app.config["JSONIFY_MIMETYPE"]

        return response
    except Exception:
        # either e wasn't an HTTPException or something went wrong in trying to jsonify it
        return jsonify(error="Internal error"), 500


for code in range(400, 599):
    if code in default_exceptions:  # flask complains if we attempt to register a handler for status code its unaware of
        main.app_errorhandler(code)(generic_error_handler)
