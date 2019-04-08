import contextlib
import mock

from app import create_app


class BaseApplicationTest:
    def setup_method(self):
        self.app_env_var_mock = mock.patch.dict('gds_metrics.os.environ', {'PROMETHEUS_METRICS_PATH': '/_metrics'})
        self.app_env_var_mock.start()
        self.app = create_app('test')

    def teardown_method(self):
        self.app_env_var_mock.stop()

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


@contextlib.contextmanager
def null_context_manager():
    yield


def dict_from_tagset(tagset_seq):
    return {k_v["Key"]: k_v["Value"] for k_v in tagset_seq}


def tagset_from_dict(input_dict):
    return [{"Key": k, "Value": v} for k, v in input_dict.items()]
