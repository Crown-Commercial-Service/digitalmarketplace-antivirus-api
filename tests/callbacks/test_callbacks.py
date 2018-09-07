import re

from flask import json

from dmtestutils.comparisons import AnyStringMatching

from ..helpers import BaseApplicationTest
from .helpers import BaseCallbackApplicationTest


class TestCallbackBadAuth(BaseApplicationTest):
    def test_basic_auth_is_required(self):
        response = self.app.test_client().get('/callbacks')
        assert response.status_code == 401
        assert response.headers["WWW-Authenticate"] == "Basic realm=callbacks"
        assert response.mimetype == self.app.config["JSONIFY_MIMETYPE"]
        assert json.loads(response.get_data()) == {
            "error": AnyStringMatching(r".*authoriz.*", flags=re.I),
        }

    def test_invalid_basic_auth_is_rejected(self):
        response = self.app.test_client().get(
            "/callbacks",
            headers={'Authorization': 'Basic some-invalid-credentials'},
        )
        assert response.status_code == 403
        assert response.mimetype == self.app.config["JSONIFY_MIMETYPE"]
        assert json.loads(response.get_data()) == {
            "error": AnyStringMatching(r".*forbidden.*some-invalid-credentials.*", flags=re.I),
        }


class TestCallbackGoodAuth(BaseCallbackApplicationTest):
    def test_basic_auth_succeeds(self):
        response = self.get_authorized_client().get(
            "/callbacks",
        )
        assert response.status_code == 200
        assert response.mimetype == self.app.config["JSONIFY_MIMETYPE"]
