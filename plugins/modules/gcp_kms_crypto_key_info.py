#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2017 Google
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
# ----------------------------------------------------------------------------
#
#     ***     AUTO GENERATED CODE    ***    Type: MMv1     ***
#
# ----------------------------------------------------------------------------
#
#     This file is automatically generated by Magic Modules and manual
#     changes will be clobbered when the file is regenerated.
#
#     Please read more about how to change this file at
#     https://www.github.com/GoogleCloudPlatform/magic-modules
#
# ----------------------------------------------------------------------------

from __future__ import absolute_import, division, print_function

__metaclass__ = type

################################################################################
# Documentation
################################################################################

ANSIBLE_METADATA = {'metadata_version': '1.1', 'status': ["preview"], 'supported_by': 'community'}

DOCUMENTATION = '''
---
module: gcp_kms_crypto_key_info
description:
- Gather info for GCP CryptoKey
short_description: Gather info for GCP CryptoKey
author: Google Inc. (@googlecloudplatform)
requirements:
- python >= 2.6
- requests >= 2.18.4
- google-auth >= 1.3.0
options:
  key_ring:
    description:
    - The KeyRing that this key belongs to.
    - 'Format: `''projects/{{project}}/locations/{{location}}/keyRings/{{keyRing}}''`.'
    required: true
    type: str
  project:
    description:
    - The Google Cloud Platform project to use.
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
    - impersonation
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
    - Required service account to impersonate if impersonation is selected.
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
- name: get info on a crypto key
  gcp_kms_crypto_key_info:
    key_ring: projects/{{ gcp_project }}/locations/us-central1/keyRings/key-key-ring
    project: test_project
    auth_kind: serviceaccount
    service_account_file: "/tmp/auth.pem"
'''

RETURN = '''
resources:
  description: List of resources
  returned: always
  type: complex
  contains:
    name:
      description:
      - The resource name for the CryptoKey.
      returned: success
      type: str
    createTime:
      description:
      - The time that this resource was created on the server.
      - This is in RFC3339 text format.
      returned: success
      type: str
    labels:
      description:
      - Labels with user-defined metadata to apply to this resource.
      returned: success
      type: dict
    purpose:
      description:
      - Immutable purpose of CryptoKey. See U(https://cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys#CryptoKeyPurpose)
        for inputs.
      returned: success
      type: str
    rotationPeriod:
      description:
      - Every time this period passes, generate a new CryptoKeyVersion and set it
        as the primary.
      - The first rotation will take place after the specified period. The rotation
        period has the format of a decimal number with up to 9 fractional digits,
        followed by the letter `s` (seconds). It must be greater than a day (ie, 86400).
      returned: success
      type: str
    versionTemplate:
      description:
      - A template describing settings for new crypto key versions.
      returned: success
      type: complex
      contains:
        algorithm:
          description:
          - The algorithm to use when creating a version based on this template.
          - See the [algorithm reference](U(https://cloud.google.com/kms/docs/reference/rest/v1/CryptoKeyVersionAlgorithm))
            for possible inputs.
          returned: success
          type: str
        protectionLevel:
          description:
          - The protection level to use when creating a version based on this template.
          returned: success
          type: str
    nextRotationTime:
      description:
      - The time when KMS will create a new version of this Crypto Key.
      returned: success
      type: str
    keyRing:
      description:
      - The KeyRing that this key belongs to.
      - 'Format: `''projects/{{project}}/locations/{{location}}/keyRings/{{keyRing}}''`.'
      returned: success
      type: str
    skipInitialVersionCreation:
      description:
      - If set to true, the request will create a CryptoKey without any CryptoKeyVersions.
        You must use the `google_kms_key_ring_import_job` resource to import the CryptoKeyVersion.
      returned: success
      type: bool
'''

################################################################################
# Imports
################################################################################
from ansible_collections.google.cloud.plugins.module_utils.gcp_utils import navigate_hash, GcpSession, GcpModule
import json

################################################################################
# Main
################################################################################


def main():
    module = GcpModule(argument_spec=dict(key_ring=dict(required=True, type='str')))

    if not module.params['scopes']:
        module.params['scopes'] = ['https://www.googleapis.com/auth/cloudkms']

    return_value = {'resources': fetch_list(module, collection(module))}
    module.exit_json(**return_value)


def collection(module):
    return "https://cloudkms.googleapis.com/v1/{key_ring}/cryptoKeys".format(**module.params)


def fetch_list(module, link):
    auth = GcpSession(module, 'kms')
    return auth.list(link, return_if_object, array_name='cryptoKeys')


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
