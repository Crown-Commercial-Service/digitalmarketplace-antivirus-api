import contextlib
import mock

from app import create_app


class BaseApplicationTest:
    def setup_method(self):
        self.app = create_app('test')

    def get_authorized_client(self):
        client = self.app.test_client()
        client.environ_base = {
            **client.environ_base,
            "HTTP_AUTHORIZATION": f"Bearer {self.app.config['DM_ANTIVIRUS_API_AUTH_TOKENS']}",
        }
        return client

    @contextlib.contextmanager
    def mocked_app_logger_log(self):
        with mock.patch.object(self.app.logger, "isEnabledFor", return_value=True):
            with mock.patch.object(self.app.logger, "_log") as _log:
                yield _log
