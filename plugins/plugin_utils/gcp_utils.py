from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

import os
import re

try:
    from google.oauth2 import service_account
    HAS_GOOGLE_LIBRARIES = True
except ImportError:
    HAS_GOOGLE_LIBRARIES = False

from ansible.errors import AnsibleError


# Handles all authentication and options for GCP Secrets Manager API calls in Lookup plugins.
class GcpSecretLookup():
    def __init__(self):
        if not HAS_GOOGLE_LIBRARIES:
            raise AnsibleError("Please install the google-auth library")

        self.plugin_name = ''
        self.secret_id = None
        self.version_id = None
        self.project_id = None
        self.service_account_file = None
        self.scope = ["https://www.googleapis.com/auth/cloud-platform"]

    def set_plugin_name(self, name):
        self.plugin_name = name

    def client(self, secretmanager):
        if self.service_account_file is not None:
            path = os.path.realpath(os.path.expanduser(self.service_account_file))
            credentials = service_account.Credentials.from_service_account_file(path).with_scopes(self.scope)
            return secretmanager.SecretManagerServiceClient(credentials=credentials)

        return secretmanager.SecretManagerServiceClient()

    def process_options(self, terms, variables=None, **kwargs):
        self.secret_id = kwargs.get('secret')
        self.version_id = kwargs.get('version', 'latest')
        self.project_id = kwargs.get('project', os.getenv('GCP_PROJECT'))
        self.service_account_file = kwargs.get('service_account_file', os.getenv('GOOGLE_APPLICATION_CREDENTIALS'))

        if len(terms) > 1:
            raise AnsibleError("{0} lookup plugin can have only one secret name or resource id".format(self.plugin_name))

        if self.secret_id is None and len(terms) == 1:
            self.secret_id = terms[0]

        regex = r'^projects/([^/]+)/secrets/([^/]+)/versions/(.+)$'
        match = re.match(regex, self.secret_id)
        if match:
            self.name = self.secret_id
            self.project_id = match.group(1)
            self.secret_id = match.group(2)
            self.version_id = match.group(3)
            return

        if self.project_id is None:
            raise AnsibleError("{0} lookup plugin required option: project or resource id".format(self.plugin_name))

        if self.secret_id is None:
            raise AnsibleError("{0} lookup plugin required option: secret or resource id".format(self.plugin_name))

        self.name = f"projects/{self.project_id}/secrets/{self.secret_id}/versions/{self.version_id}"
