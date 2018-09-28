from collections.abc import Mapping
from functools import wraps

from flask import abort, request


def json_payload_view(acceptable_content_types=("application/json",)):
    def _decorator(func):
        @wraps(func)
        def _inner(*args, **kwargs):
            if request.content_type.split(";")[0] not in acceptable_content_types:
                abort(400, f"Unexpected Content-Type: expecting one of {sorted(acceptable_content_types)}")

            # using force= parameter because we've already performed the content-type checking
            body_dict = request.get_json(force=True)

            if not isinstance(body_dict, Mapping):
                abort(400, "Expected content to be JSON object")

            return func(*args, **kwargs, body_dict=body_dict)
        return _inner

    return _decorator


def require_json_keys(keys):
    def _decorator(func):
        @wraps(func)
        def _inner(*args, body_dict, **kwargs):
            missing_keys = frozenset(keys) - body_dict.keys()
            if missing_keys:
                abort(400, f"Expected top-level JSON keys: {sorted(missing_keys)}")
            return func(*args, **kwargs, body_dict=body_dict)

        return _inner

    return _decorator
