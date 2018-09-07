from flask import current_app, abort, request
from werkzeug.exceptions import Unauthorized


class UnauthorizedWWWAuthenticate(Unauthorized):
    """
    This is a near verbatim copy of an improvement to an as-yet-unreleased upstream version of werkzeug that allows
    us to specify a www_authenticate argument containing the contents of that field. We should get rid of this once
    we're able to upgrade past that version.

    From werkzeug 8ed5b3f9a285eca756c3ab33f8c370a88eab3842
    """
    def __init__(self, www_authenticate=None, description=None):
        super().__init__(description=description)
        if not isinstance(www_authenticate, (tuple, list)):
            www_authenticate = (www_authenticate,)
        self.www_authenticate = www_authenticate

    def get_headers(self, environ=None):
        headers = super().get_headers(environ)
        if self.www_authenticate:
            headers.append((
                'WWW-Authenticate',
                ', '.join([str(x) for x in self.www_authenticate])
            ))
        return headers


def requires_authentication(module='main', scheme='Bearer'):
    if current_app.config['AUTH_REQUIRED']:
        incoming_token = get_token_from_headers(request.headers, scheme=scheme)

        if not incoming_token:
            raise UnauthorizedWWWAuthenticate(www_authenticate=f"{scheme} realm={module}")
        if not token_is_valid(incoming_token, module=module):
            abort(403, f"Forbidden; invalid token provided {incoming_token}")


def token_is_valid(incoming_token, module):
    return incoming_token in get_allowed_tokens_from_config(current_app.config, module=module)


def get_allowed_tokens_from_config(config, module='main'):
    """Return a list of allowed auth tokens from the application config"""
    env_variable_name = ""

    if module == "main":
        env_variable_name = 'DM_ANTIVIRUS_API_AUTH_TOKENS'
    elif module == 'callbacks':
        # though SNS uses the "Basic" auth scheme, we can treat the payload section of the header as a single opaque
        # token set in DM_ANTIVIRUS_API_CALLBACK_AUTH_TOKENS like any normal "Bearer" tokens.
        env_variable_name = 'DM_ANTIVIRUS_API_CALLBACK_AUTH_TOKENS'

    return [token for token in config.get(env_variable_name, '').split(':') if token]


def get_token_from_headers(headers, scheme="Bearer"):
    auth_header = headers.get('Authorization', '')
    if auth_header[:len(scheme) + 1] != scheme + " ":
        return None
    return auth_header[len(scheme) + 1:]
