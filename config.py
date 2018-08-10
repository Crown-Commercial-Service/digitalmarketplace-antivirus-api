import base64
import os
from dmutils.status import get_version_label


class Config:

    VERSION = get_version_label(
        os.path.abspath(os.path.dirname(__file__))
    )
    DM_ANTIVIRUS_AUTH_TOKENS = None
    AUTH_REQUIRED = True
    DM_HTTP_PROTO = 'http'
    # Logging
    DM_LOG_LEVEL = 'DEBUG'
    DM_PLAIN_TEXT_LOGS = False
    DM_LOG_PATH = None
    DM_APP_NAME = 'antivirus-api'

    DM_CLAMD_UNIX_SOCKET_PATH = "/var/run/clamav/clamd.ctl"

    VCAP_SERVICES = None


class Test(Config):
    SERVER_NAME = '127.0.0.1:5008'
    DEBUG = True
    DM_PLAIN_TEXT_LOGS = True
    DM_LOG_LEVEL = 'CRITICAL'

    DM_ANTIVIRUS_API_AUTH_TOKENS = 'valid-token'
    DM_ANTIVIRUS_API_CALLBACK_AUTH_TOKENS = base64.standard_b64encode(b'valid:callback-token')


class Development(Config):
    DEBUG = True
    DM_PLAIN_TEXT_LOGS = True

    DM_ANTIVIRUS_API_AUTH_TOKENS = 'myToken'
    DM_ANTIVIRUS_API_CALLBACK_AUTH_TOKENS = base64.standard_b64encode(b'my:callbackToken')


class Live(Config):
    """Base config for deployed environments"""
    DEBUG = False
    DM_HTTP_PROTO = 'https'
    DM_LOG_PATH = '/var/log/digitalmarketplace/application.log'


class Preview(Live):
    pass


class Staging(Live):
    pass


class Production(Live):
    pass


configs = {
    'development': Development,
    'test': Test,

    'preview': Preview,
    'staging': Staging,
    'production': Production,
}
