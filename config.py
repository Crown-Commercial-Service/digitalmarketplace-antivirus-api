import base64
import os
from dmutils.status import get_version_label


class Config:

    VERSION = get_version_label(
        os.path.abspath(os.path.dirname(__file__))
    )
    DM_ANTIVIRUS_API_AUTH_TOKENS = None
    DM_ANTIVIRUS_API_CALLBACK_AUTH_TOKENS = None
    AUTH_REQUIRED = True
    DM_HTTP_PROTO = 'http'
    # Logging
    DM_LOG_LEVEL = 'DEBUG'
    DM_PLAIN_TEXT_LOGS = False
    DM_LOG_PATH = None
    DM_APP_NAME = 'antivirus-api'

    DM_CLAMD_UNIX_SOCKET_PATH = "/var/run/clamav/clamd.ctl"

    DM_NOTIFY_API_KEY = None

    # only used as a surrogate where it doesn't actually matter (e.g. for s3)
    DM_DEFAULT_AWS_REGION = "eu-west-1"

    DM_EICAR_TEST_SIGNATURE_RESULT_STRINGS = [
        "Clamav.Test.File-7",
        "Eicar-Test-Signature",
        "Eicar-Test-Signature.UNOFFICIAL",  # if from our custom virus definition
    ]
    DM_EICAR_TEST_SIGNATURE_VIRUS_ALERT_EMAIL = "eicar-found@example.gov.uk"
    DM_DEVELOPER_VIRUS_ALERT_EMAIL = "developer-virus-alert@example.com"
    NOTIFY_TEMPLATES = {
        "developer_virus_alert": "70986093-4f54-4b2e-883e-d88456455385",
    }

    VCAP_SERVICES = None


class Test(Config):
    SERVER_NAME = '127.0.0.1:5008'
    DEBUG = True
    DM_PLAIN_TEXT_LOGS = True
    DM_LOG_LEVEL = 'CRITICAL'

    DM_NOTIFY_API_KEY = "not_a_real_key-00000000-fake-uuid-0000-000000000000"

    DM_ANTIVIRUS_API_AUTH_TOKENS = 'valid-token'
    DM_ANTIVIRUS_API_CALLBACK_AUTH_TOKENS = base64.standard_b64encode(b'valid:callback-token').decode("ascii")


class Development(Config):
    DEBUG = True
    DM_PLAIN_TEXT_LOGS = True

    DM_NOTIFY_API_KEY = "not_a_real_key-00000000-fake-uuid-0000-000000000000"

    DM_ANTIVIRUS_API_AUTH_TOKENS = 'myToken'
    DM_ANTIVIRUS_API_CALLBACK_AUTH_TOKENS = base64.standard_b64encode(b'my:callbackToken').decode("ascii")


class Live(Config):
    """Base config for deployed environments"""
    DEBUG = False
    DM_HTTP_PROTO = 'https'
    DM_LOG_PATH = '/var/log/digitalmarketplace/application.log'

    # use of invalid email addresses with live api keys annoys Notify
    DM_NOTIFY_REDIRECT_DOMAINS_TO_ADDRESS = {
        "example.com": "success@simulator.amazonses.com",
        "example.gov.uk": "success@simulator.amazonses.com",
        "user.marketplace.team": "success@simulator.amazonses.com",
    }


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
