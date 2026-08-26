# -*- coding: utf-8 -*-
# Copyright: (c) 2020, Pavlo Bashynskyi (@levonet) <levonet@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

import io
import json
import os
import re

try:
    import google.oauth2.credentials
    from google.auth import identity_pool
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
        self.access_token = None
        self.service_account_file = None
        self.scope = ["https://www.googleapis.com/auth/cloud-platform"]

    def set_plugin_name(self, name):
        self.plugin_name = name

    def client(self, secretmanager):
        if self.access_token is not None:
            credentials=google.oauth2.credentials.Credentials(self.access_token, scopes=self.scope)
            return secretmanager.SecretManagerServiceClient(credentials=credentials)

        if self.service_account_file is not None:
            path = os.path.realpath(os.path.expanduser(self.service_account_file))
            if not os.path.exists(path):
                raise AnsibleError("File {} was not found.".format(path))

            with io.open(path, "r") as file_obj:
                try:
                    info = json.load(file_obj)
                except ValueError as e:
                    raise AnsibleError("File {} is not a valid json file.".format(path))

            credential_type = info.get("type")
            if credential_type == "authorized_user":
                credentials = google.oauth2.credentials.Credentials.from_authorized_user_info(info, scopes=self.scope)
            elif credential_type == "service_account":
                credentials = service_account.Credentials.from_service_account_info(info, scopes=self.scope)
            elif credential_type == "external_account":
                if info.get("subject_token_type") == "urn:ietf:params:aws:token-type:aws4_request":
                    from google.auth import aws
                    credentials = aws.Credentials.from_info(info, scopes=self.scope)
                else:
                    credentials = identity_pool.Credentials.from_info(info, scopes=self.scope)
            else:
                raise AnsibleError(
                    "Type is {}, expected one of authorized_user, service_account, external_account.".format(credential_type)
                )

            return secretmanager.SecretManagerServiceClient(credentials=credentials)

        return secretmanager.SecretManagerServiceClient()

    def process_options(self, terms, variables=None, **kwargs):
        self.secret_id = kwargs.get('secret')
        self.version_id = kwargs.get('version', 'latest')
        self.project_id = kwargs.get('project', os.getenv('GCP_PROJECT'))
        self.access_token = kwargs.get('access_token', os.getenv('GCP_ACCESS_TOKEN'))
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

        self.name = "projects/{}/secrets/{}/versions/{}".format(self.project_id, self.secret_id, self.version_id)
