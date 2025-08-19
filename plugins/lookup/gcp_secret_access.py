# -*- coding: utf-8 -*-
# Copyright: (c) 2020, Pavlo Bashynskyi (@levonet) <levonet@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r"""
---
lookup: gcp_secret_access
author:
- Pavlo Bashynskyi (@levonet)
short_description: Retrieve secrets from GCP Secret Manager
requirements:
- python >= 2.7
- google-auth >= 1.26.0
- google-cloud-secret-manager >= 1.0.0
description:
- Retrieve secret contents from GCP Secret Manager.
- Accessing to secret content requires the Secret Manager Secret Accessor role (C(roles/secretmanager.secretAccessor)) on the secret, project, folder, or organization.
options:
  secret:
    description:
    - Secret name or resource id. Resource id should be in format C(projects/*/secrets/*/versions/*).
    - The project option is required if a secret name is used instead of resource id.
    required: True
    type: str
  version:
    description: Version id of secret. You can also access the latest version of a secret by specifying "C(latest)" as the version.
    type: str
    default: latest
  project:
    description: The Google Cloud Platform project to use.
    type: str
    env:
    - name: GCP_PROJECT
  access_token:
    description:
    - The Google Cloud access token. If specified, C(service_account_file) will be ignored.
    type: str
    env:
    - name: GCP_ACCESS_TOKEN
  service_account_file:
    description:
    - The path of a Service Account JSON file if serviceaccount is selected as type.
    type: path
    env:
    - name: GOOGLE_APPLICATION_CREDENTIALS
    - name: GCP_SERVICE_ACCOUNT_FILE
notes:
- When I(secret) is the first option in the term string, C(secret=) is not required (see examples).
- If you’re running your application elsewhere, you should download a service account JSON keyfile and point to it using the secret option or an environment variable C(GOOGLE_APPLICATION_CREDENTIALS="/path/to/keyfile.json").
"""

EXAMPLES = r"""
- ansible.builtin.debug:
    msg: "{{ lookup('google.cloud.gcp_secret_access', secret='hola', project='test_project') }}"

- ansible.builtin.debug:
    msg: "{{ lookup('google.cloud.gcp_secret_access', 'hola', project='test_project') }}"

- name: using resource id instead of secret name
  ansible.builtin.debug:
    msg: "{{ lookup('google.cloud.gcp_secret_access', 'projects/112233445566/secrets/hola/versions/1') }}"

- name: using service account file
  ansible.builtin.debug:
    msg: "{{ lookup('google.cloud.gcp_secret_access', 'hola', project='test_project', service_account_file='/path/to/keyfile.json') }}"
"""

RETURN = r"""
_raw:
  description:
  - secrets requested
"""

from ansible.errors import AnsibleError
from ansible.plugins.lookup import LookupBase
from ansible_collections.google.cloud.plugins.plugin_utils.gcp_utils import GcpSecretLookup

try:
    from google.cloud import secretmanager

    HAS_GOOGLE_SECRET_MANAGER_LIBRARY = True
except ImportError:
    HAS_GOOGLE_SECRET_MANAGER_LIBRARY = False


class GcpSecretAccessLookup(GcpSecretLookup):
    def run(self, terms, variables=None, **kwargs):
        self.set_plugin_name('google.cloud.gcp_secret_access')
        self.process_options(terms, variables=None, **kwargs)

        response = self.client(secretmanager).access_secret_version(request={"name": self.name})
        payload = response.payload.data.decode("UTF-8")

        return [payload]


class LookupModule(LookupBase):
    def run(self, terms, variables=None, **kwargs):
        if not HAS_GOOGLE_SECRET_MANAGER_LIBRARY:
            raise AnsibleError("Please install the google-cloud-secret-manager Python library")

        return GcpSecretAccessLookup().run(terms, variables=variables, **kwargs)
