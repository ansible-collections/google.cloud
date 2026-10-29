# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from unittest import mock

import pytest

from ansible_collections.google.cloud.plugins.modules import gcp_secret_manager


class FakeResponse:
    def __init__(self, status_code, data=None):
        self.status_code = status_code
        self._data = data or {}
        self.request = mock.Mock(url="https://secretmanager.googleapis.com/v1/fake")
        self.text = ""

    def json(self):
        return dict(self._data)


class FakeModuleError(Exception):
    pass


def make_module():
    module = mock.Mock()
    module.params = {
        "name": "my-secret",
        "project": "my-project",
        "location": None,
        "labels": {},
        "value": "s3cret",
    }

    def raise_for_status(response):
        if response.status_code >= 400:
            raise FakeModuleError(response.status_code)

    module.raise_for_status.side_effect = raise_for_status
    module.fail_json.side_effect = FakeModuleError
    return module


def make_session(create_status):
    session = mock.Mock()
    session.post.side_effect = [
        FakeResponse(create_status),
        FakeResponse(200, {"name": "projects/my-project/secrets/my-secret/versions/1"}),
    ]
    return session


@pytest.mark.parametrize("create_status", [200, 409])
def test_create_secret_adds_version(create_status):
    module = make_module()
    session = make_session(create_status)
    with mock.patch.object(gcp_secret_manager, "get_auth", return_value=session):
        result = gcp_secret_manager.create_secret(module)

    assert session.post.call_count == 2
    assert session.post.call_args_list[1][0][0].endswith("secrets/my-secret:addVersion")
    assert result["name"] == "my-secret"
    assert result["version"] == "1"


def test_create_secret_fails_on_other_errors():
    module = make_module()
    session = make_session(403)
    with mock.patch.object(gcp_secret_manager, "get_auth", return_value=session):
        with pytest.raises(FakeModuleError):
            gcp_secret_manager.create_secret(module)
    assert session.post.call_count == 1
