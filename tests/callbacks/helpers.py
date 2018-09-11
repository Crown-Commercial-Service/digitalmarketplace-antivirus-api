from ..helpers import BaseApplicationTest


class BaseCallbackApplicationTest(BaseApplicationTest):
    def get_authorized_client(self):
        client = self.app.test_client()
        client.environ_base = {
            **client.environ_base,
            "HTTP_AUTHORIZATION": f"Basic {self.app.config['DM_ANTIVIRUS_API_CALLBACK_AUTH_TOKENS']}".encode("utf-8"),
        }
        return client
