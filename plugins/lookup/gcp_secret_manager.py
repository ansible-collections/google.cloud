# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = '''
    author:
    - Dave Costakos <dcostako@redhat.com>
    name: gcp_secret_manager
    short_description: Get Secrets from Google Cloud as a Lookup plugin
    description:
    - retrieve secret keys in Secret Manager for use in playbooks
    - see https://cloud.google.com/iam/docs/service-account-creds for details on creating
      credentials for Google Cloud and the format of such credentials
    - once a secret value is retreived, it is returned decoded.  It is up to the developer
      to maintain secrecy of this value once returned. 

    options:
        key:
            description:
            - the key of the secret to look up in Secret Manager
            type: str
            required: True
        project:
            description:
            - The name of the google cloud project
            - defaults to OS env variable GCP_PROJECT if not present
            type: str
        auth_kind:
            description:
            - the type of authentication to use with Google Cloud (i.e. serviceaccount or machineaccount)
            - defaults to OS env variable GCP_AUTH_KIND if not present
            type: str
        version:
            description:
            - the version name of your secret to retrieve
            type: str
            default: latest
            required: False
        service_account_email:
            description:
            - email associated with the service account
            - defaults to OS env variable GCP_SERVICE_ACCOUNT_EMAIL if not present
            type: str
            required: False
        service_account_file:
            description:
            - JSON Credential file obtained from Google Cloud
            - defaults to OS env variable GCP_SERVICE_ACCOUNT_FILE if not present
            - see https://cloud.google.com/iam/docs/service-account-creds for details
            type: str
            required: False
        service_account_info:
            description:
            - JSON Object representing the contents of a service_account_file obtained from Google Cloud
            - defaults to OS env variable GCP_SERVICE_ACCOUNT_INFO if not present
            type: jsonarg
            required: False
        errors:
            description:
            - how to handle errors
            choices: ['strict','warn','ignore']
            default: strict
'''

EXAMPLES = '''
- name: Test secret using env variables for credentials
  ansible.builtin.debug:
    msg: "{{ lookup('google.cloud.gcp_secret_manager', key='secret_key') }}"

- name: Test secret using explicit credentials
  ansible.builtin.debug:
    msg: "{{ lookup('google.cloud.gcp_secret_manager', key='secret_key', project='project', auth_kind='serviceaccount', service_account_file='file.json') }}"

- name: Test getting specific version of a secret (old version)
  ansible.builtin.debug:
    msg: "{{ lookup('google.cloud.gcp_secret_manager', key='secret_key', version='1') }}"

- name: Test getting specific version of a secret (new version)
  ansible.builtin.debug:
    msg: "{{ lookup('google.cloud.gcp_secret_manager', key='secret_key', version='2') }}"
'''

RETURN = '''
    _raw:
        description: the contents of the secret requested (please use "no_log" to not expose this secret)
        type: list
        elements: str
'''

################################################################################
# Imports
################################################################################

import json
import os
import base64


from ansible.plugins.lookup import LookupBase

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import google.auth
    from google.oauth2 import service_account
    from google.auth.transport.requests import AuthorizedSession
    HAS_GOOGLE_LIBRARIES = True
except ImportError:
    HAS_GOOGLE_LIBRARIES = False

from ansible_collections.google.cloud.plugins.module_utils.gcp_utils import GcpSession, GcpRequest
from ansible.errors import AnsibleError

class GcpLookupException(Exception):
    pass

class LookupModule(LookupBase):
    def run(self, terms, variables, **kwargs):
        self.set_options(var_options=variables, direct=kwargs)
        self.scopes = ["https://www.googleapis.com/auth/cloud-platform"]
        self._validate()
        self.service_acct_creds = self._credentials()
        session = AuthorizedSession(self.service_acct_creds)
        response = session.get("https://secretmanager.googleapis.com/v1/projects/{project}/secrets/{key}/versions/{version}:access".format(**self.get_options()))
        if response.status_code == 200:
            result_data = response.json()
            secret_value = base64.b64decode(result_data['payload']['data'])
            return [ secret_value ]
        else:
            if self.get_option('errors') == 'warn':
                self.warn(f"secret request returned bad status: {response.status_code} {response.json()}")
                return [ '' ]
            elif self.get_option('error') == 'ignore':
                return [ '' ]
            else:
                raise AnsibleError(f"secret request returned bad status: {response.status_code} {response.json()}")

    def _validate(self):
        if HAS_GOOGLE_LIBRARIES == False:
            raise AnsibleError("Please install the google-auth library")
        
        if HAS_REQUESTS == False:
            raise AnsibleError("Please install the requests library")
        
        if self.get_option('key') == None:
            raise AnsibleError("'key' is a required parameter")
        
        if self.get_option('version') == None:
            self.set_option('version', 'latest')

        self._set_from_env('project', 'GCP_PROJECT', True)
        self._set_from_env('auth_kind', 'GCP_AUTH_KIND', True)
        self._set_from_env('service_account_email', 'GCP_SERVICE_ACCOUNT_EMAIL')
        self._set_from_env('service_account_file', 'GCP_SERVICE_ACCOUNT_FILE')
        self._set_from_env('service_account_info', 'GCP_SERVICE_ACCOUNT_INFO')
    
    def _set_from_env(self, var=None, env_name=None, raise_on_empty=False):
        if self.get_option(var) == None:
            if env_name is not None and env_name in os.environ:
                fallback = os.environ[env_name]
                self.set_option(var, fallback)

        if self.get_option(var) == None and raise_on_empty:
            msg = f"No key '{var}' provided"
            if env_name is not None:
                msg += f" and no fallback to env['{env_name}'] available"
            raise AnsibleError(msg)

    def _credentials(self):
        cred_type = self.get_option('auth_kind')

        if cred_type == 'application':
            credentials, project_id = google.auth.default(scopes=self.scopes)
            return credentials

        if cred_type == 'serviceaccount':
            if self.get_option('service_account_file') is not None:
                path = os.path.realpath(os.path.expanduser(self.get_option('service_account_file')))
                try:
                    svc_acct_creds = service_account.Credentials.from_service_account_file(path)
                except OSError as e:
                    raise GcpLookupException("Unable to read service_account_file at %s: %s" % (path, e.strerror))
                
            elif self.get_option('service_account_contents') is not None:
                try:
                    info = json.loads(self.get_option('service_account_contents'))
                except json.decoder.JSONDecodeError as e:
                  raise GcpLookupException("Unable to decode service_account_contents as JSON: %s" % e)
                
                svc_acct_creds = service_account.Credentials.from_service_account_info(info)
            else:
                raise GcpLookupException('Service Account authentication requires setting either service_account_file or service_account_contents')

            return svc_acct_creds.with_scopes(self.scopes)

        if cred_type == 'machineaccount':
            self.svc_acct_creds = google.auth.compute_engine.Credentials(self.service_account_email)
            return self.svc_acct_creds

        raise GcpLookupException("Credential type '%s' not implemented" % cred_type)        

    

    



