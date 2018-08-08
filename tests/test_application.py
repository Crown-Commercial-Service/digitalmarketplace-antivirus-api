"""
Tests for the application infrastructure
"""
from flask import json

from .helpers import BaseApplicationTest


class TestApplication(BaseApplicationTest):
    def test_index(self):
        response = self.get_authorized_client().get('/')
        assert 200 == response.status_code
        assert 'this' in json.loads(response.get_data())

    def test_404(self):
        response = self.get_authorized_client().get('/foo/bar/baz')
        assert 404 == response.status_code

    def test_bearer_token_is_required(self):
        response = self.app.test_client().get('/')
        assert 401 == response.status_code
        assert 'WWW-Authenticate' in response.headers

    def test_invalid_bearer_token_is_rejected(self):
        response = self.app.test_client().get(
            '/',
            headers={'Authorization': 'Bearer invalid-token'},
        )
        assert 403 == response.status_code

    def test_ttl_is_not_set(self):
        response = self.get_authorized_client().get('/')
        assert response.cache_control.max_age is None
