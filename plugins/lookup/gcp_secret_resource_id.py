# -*- coding: utf-8 -*-
# Copyright: (c) 2020, Pavlo Bashynskyi (@levonet) <levonet@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r"""
---
lookup: gcp_secret_resource_id
author:
- Pavlo Bashynskyi (@levonet)
short_description: Retrieve resource id of secret version from GCP Secret Manager
requirements:
- python >= 2.7
- google-auth >= 1.3.0
- google-cloud-secret-manager >= 1.0.0
description:
- Retrieve resource id of secret version from GCP Secret Manager.
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
    msg: "{{ lookup('google.cloud.gcp_secret_resource_id', secret='hola', project='test_project') }}"
"""

RETURN = r"""
_raw:
  description:
  - resource id of secret version
"""

from ansible.errors import AnsibleError
from ansible.plugins.lookup import LookupBase
from ansible_collections.google.cloud.plugins.plugin_utils.gcp_utils import GcpSecretLookup

try:
    from google.cloud import secretmanager

    HAS_GOOGLE_SECRET_MANAGER_LIBRARY = True
except ImportError:
    HAS_GOOGLE_SECRET_MANAGER_LIBRARY = False


class GcpSecretResourceIdLookup(GcpSecretLookup):
    def run(self, terms, variables=None, **kwargs):
        self.set_plugin_name('google.cloud.gcp_secret_resource_id')
        self.process_options(terms, variables=None, **kwargs)

        response = self.client(secretmanager).get_secret_version(request={"name": self.name})

        return [response.name]


class LookupModule(LookupBase):
    def run(self, terms, variables=None, **kwargs):

        if not HAS_GOOGLE_SECRET_MANAGER_LIBRARY:
            raise AnsibleError("Please install the google-cloud-secret-manager Python library")

        return GcpSecretResourceIdLookup().run(terms, variables=variables, **kwargs)
