"""
Tests for the application infrastructure
"""
import re

from flask import json

from dmtestutils.comparisons import AnyStringMatching

from .helpers import BaseApplicationTest


class TestApplication(BaseApplicationTest):
    def test_index(self):
        response = self.get_authorized_client().get('/')
        assert response.status_code == 200
        assert response.mimetype == self.app.config["JSONIFY_MIMETYPE"]
        assert json.loads(response.get_data()) == {
            "this": AnyStringMatching(r".*pointless.*", flags=re.I),
        }

    def test_404(self):
        response = self.get_authorized_client().get('/foo/bar/baz')
        assert response.status_code == 404
        assert response.mimetype == self.app.config["JSONIFY_MIMETYPE"]
        assert json.loads(response.get_data()) == {
            "error": AnyStringMatching(r".*found.*", flags=re.I),
        }

    def test_bearer_token_is_required(self):
        response = self.app.test_client().get('/')
        assert response.status_code == 401
        assert response.headers["WWW-Authenticate"] == "Bearer realm=main"
        assert response.mimetype == self.app.config["JSONIFY_MIMETYPE"]
        assert json.loads(response.get_data()) == {
            "error": AnyStringMatching(r".*authoriz.*", flags=re.I),
        }

    def test_invalid_bearer_token_is_rejected(self):
        response = self.app.test_client().get(
            '/',
            headers={'Authorization': 'Bearer some-invalid-token'},
        )
        assert response.status_code == 403
        assert response.mimetype == self.app.config["JSONIFY_MIMETYPE"]
        assert json.loads(response.get_data()) == {
            "error": AnyStringMatching(r".*forbidden.*some-invalid-token.*", flags=re.I),
        }

    def test_ttl_is_not_set(self):
        response = self.get_authorized_client().get('/')
        assert response.cache_control.max_age is None
