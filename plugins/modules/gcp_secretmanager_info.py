#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2023, Tze L. <tze@aiyor.net>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function
import os
import json
from ansible_collections.google.cloud.plugins.module_utils.gcp_utils import navigate_hash, GcpSession, GcpModule, GcpRequest

__metaclass__ = type

################################################################################
# Documentation
################################################################################

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ["preview"], 'supported_by': 'community'}

DOCUMENTATION = '''
---
module: gcp_secretmanager_info.py
description:
- Gather info for GCP Secret Manager
short_description: Gather info for GCP Secret Manager - List secrets and versions metadata.
author: Tze L. (https://github.com/tl-aiyor)
requirements:
- python >= 2.6
- requests >= 2.18.4
- google-auth >= 1.3.0
options:
  project:
    description:
    - The name of the GCP Project. This is the Project number.
    default: environment variable 'GCP_PROJECT'
    type: str
  auth_kind:
    description:
    - The type of credential used.
    type: str
    required: true
    choices:
    - application
    - machineaccount
    - serviceaccount
    - accesstoken
  service_account_contents:
    description:
    - The contents of a Service Account JSON file, either in a dictionary or as a
      JSON string that represents it.
    type: jsonarg
  service_account_file:
    description:
    - The path of a Service Account JSON file if serviceaccount is selected as type.
    type: path
  service_account_email:
    description:
    - An optional service account email address if machineaccount is selected and
      the user does not wish to use the default email.
    type: str
  access_token:
    description:
    - An OAuth2 access token if credential type is accesstoken.
    type: str
  scopes:
    description:
    - Array of scopes to be used
    type: list
    elements: str
    default: https://www.googleapis.com/auth/cloud-platform
  env_type:
    description:
    - Specifies which Ansible environment you're running this module within.
    - This should not be set unless you know what you're doing.
    - This only alters the User Agent string for any API requests.
    type: str
notes:
- for authentication, you can set service_account_file using the C(GCP_SERVICE_ACCOUNT_FILE)
  env variable.
- for authentication, you can set service_account_contents using the C(GCP_SERVICE_ACCOUNT_CONTENTS)
  env variable.
- For authentication, you can set service_account_email using the C(GCP_SERVICE_ACCOUNT_EMAIL)
  env variable.
- For authentication, you can set access_token using the C(GCP_ACCESS_TOKEN)
  env variable.
- For authentication, you can set auth_kind using the C(GCP_AUTH_KIND) env variable.
- For authentication, you can set scopes using the C(GCP_SCOPES) env variable.
- Environment variables values will only be used if the playbook values are not set.
- The I(service_account_email) and I(service_account_file) options are mutually exclusive.
'''

EXAMPLES = '''
- name: get list of secrets and the associated versions - secret payload excluded
  gcp_secretmanager_info:
    project: "{{ project_id }}"
    auth_kind: application
'''

RETURN = '''
resources:
  description: List of resources
  returned: always
  type: complex
  contains:
    name:
      description:
      - The full name of the secret (e.g., projects/111111111111/secrets/mysecret).
      returned: success
      type: str
    etag:
      description:
      - See reference for more info: https://cloud.google.com/secret-manager/docs/etags
      returned: success
      type: str
    createTime:
      description:
      - The creation time of the secret
      type: str
    versions:
      description:
      - An array consists of list of secret version metadata.
      - This does not include 
      returned: success
      type: complex
      contains:
        name:
          description: 
          - The full name of the secret version (e.g., projects/111111111111/secrets/mysecret/versions/1).
          type: str
        createTime:
          description:
          - The creation time of the secret version
          type: str
        state:
          description:
          - The state of the version.  ENABLED or DISABLED
          type: str
        etag:
          description:
          - See reference for more info: https://cloud.google.com/secret-manager/docs/etags
          type: str
'''

def main():
    module = GcpModule(argument_spec=dict(
        project=dict(default=os.environ['GCP_PROJECT'], type='str')))

    if not module.params['scopes']:
        module.params['scopes'] = [
            'https://www.googleapis.com/auth/cloud-platform']

    secrets_url = "https://secretmanager.googleapis.com/v1/projects/{project}/secrets".format(
        **module.params
    )
    auth = GcpSession(module, 'secretmanager')
    secrets = fetch_list(secrets_url, auth, 'secrets')
    results = []
    for secret in secrets:
        secret_versions_url = "https://secretmanager.googleapis.com/v1/{name}/versions".format(
          **secret
        )

        secret['versions'] = fetch_list(secret_versions_url, auth, 'versions')
        results.append(secret)
    return_value = {'resources': results}
    module.exit_json(**return_value)

def get_secret_metadata(link, auth):
    response = auth.get(link)
    return response.json()

def fetch_list(link, auth, array_name):
    return auth.list(link, return_if_object, array_name=array_name)


def return_if_object(module, response):
    # If not found, return nothing.
    if response.status_code == 404:
        return None

    # If no content, return nothing.
    if response.status_code == 204:
        return None

    try:
        module.raise_for_status(response)
        result = response.json()
    except getattr(json.decoder, 'JSONDecodeError', ValueError) as inst:
        module.fail_json(msg="Invalid JSON response with error: %s" % inst)

    if navigate_hash(result, ['error', 'errors']):
        module.fail_json(msg=navigate_hash(result, ['error', 'errors']))

    return result


if __name__ == "__main__":
    main()