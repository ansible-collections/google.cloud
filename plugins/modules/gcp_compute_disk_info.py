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
module: gcp_compute_disk_info
description:
- Gather info for GCP Disk
short_description: Gather info for GCP Disk
author: Google Inc. (@googlecloudplatform)
requirements:
- python >= 2.6
- requests >= 2.18.4
- google-auth >= 1.3.0
options:
  filters:
    description:
    - A list of filter value pairs. Available filters are listed here U(https://cloud.google.com/sdk/gcloud/reference/topic/filters).
    - Each additional filter in the list will act be added as an AND condition (filter1
      and filter2) .
    type: list
    elements: str
  zone:
    description:
    - A reference to the zone where the disk resides.
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
- name: get info on a disk
  gcp_compute_disk_info:
    zone: us-central1-a
    filters:
    - name = test_object
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
    labelFingerprint:
      description:
      - The fingerprint used for optimistic locking of this resource. Used internally
        during updates.
      returned: success
      type: str
    creationTimestamp:
      description:
      - Creation timestamp in RFC3339 text format.
      returned: success
      type: str
    description:
      description:
      - An optional description of this resource. Provide this property when you create
        the resource.
      returned: success
      type: str
    id:
      description:
      - The unique identifier for the resource.
      returned: success
      type: int
    lastAttachTimestamp:
      description:
      - Last attach timestamp in RFC3339 text format.
      returned: success
      type: str
    lastDetachTimestamp:
      description:
      - Last detach timestamp in RFC3339 text format.
      returned: success
      type: str
    labels:
      description:
      - Labels to apply to this disk. A list of key->value pairs.
      returned: success
      type: dict
    licenses:
      description:
      - Any applicable publicly visible licenses.
      returned: success
      type: list
    name:
      description:
      - Name of the resource. Provided by the client when the resource is created.
        The name must be 1-63 characters long, and comply with RFC1035. Specifically,
        the name must be 1-63 characters long and match the regular expression `[a-z]([-a-z0-9]*[a-z0-9])?`
        which means the first character must be a lowercase letter, and all following
        characters must be a dash, lowercase letter, or digit, except the last character,
        which cannot be a dash.
      returned: success
      type: str
    sizeGb:
      description:
      - Size of the persistent disk, specified in GB. You can specify this field when
        creating a persistent disk using the sourceImage or sourceSnapshot parameter,
        or specify it alone to create an empty persistent disk.
      - If you specify this field along with sourceImage or sourceSnapshot, the value
        of sizeGb must not be less than the size of the sourceImage or the size of
        the snapshot.
      returned: success
      type: int
    users:
      description:
      - 'Links to the users of the disk (attached instances) in form: project/zones/zone/instances/instance
        .'
      returned: success
      type: list
    physicalBlockSizeBytes:
      description:
      - Physical block size of the persistent disk, in bytes. If not present in a
        request, a default value is used. Currently supported sizes are 4096 and 16384,
        other sizes may be added in the future.
      - If an unsupported value is requested, the error message will list the supported
        values for the caller's project.
      returned: success
      type: int
    type:
      description:
      - URL of the disk type resource describing which disk type to use to create
        the disk. Provide this when creating the disk.
      returned: success
      type: str
    sourceImage:
      description:
      - The source image used to create this disk. If the source image is deleted,
        this field will not be set.
      - 'To create a disk with one of the public operating system images, specify
        the image by its family name. For example, specify family/debian-9 to use
        the latest Debian 9 image: projects/debian-cloud/global/images/family/debian-9
        Alternatively, use a specific version of a public operating system image:
        projects/debian-cloud/global/images/debian-9-stretch-vYYYYMMDD To create a
        disk with a private image that you created, specify the image name in the
        following format: global/images/my-private-image You can also specify a private
        image by its image family, which returns the latest version of the image in
        that family. Replace the image name with family/family-name: global/images/family/my-private-family
        .'
      returned: success
      type: str
    provisionedIops:
      description:
      - Indicates how many IOPS must be provisioned for the disk.
      returned: success
      type: int
    zone:
      description:
      - A reference to the zone where the disk resides.
      returned: success
      type: str
    sourceImageEncryptionKey:
      description:
      - The customer-supplied encryption key of the source image. Required if the
        source image is protected by a customer-supplied encryption key.
      returned: success
      type: complex
      contains:
        rawKey:
          description:
          - Specifies a 256-bit customer-supplied encryption key, encoded in RFC 4648
            base64 to either encrypt or decrypt this resource.
          returned: success
          type: str
        sha256:
          description:
          - The RFC 4648 base64 encoded SHA-256 hash of the customer-supplied encryption
            key that protects this resource.
          returned: success
          type: str
        kmsKeyName:
          description:
          - The name of the encryption key that is stored in Google Cloud KMS.
          returned: success
          type: str
        kmsKeyServiceAccount:
          description:
          - The service account used for the encryption request for the given KMS
            key.
          - If absent, the Compute Engine Service Agent service account is used.
          returned: success
          type: str
    sourceImageId:
      description:
      - The ID value of the image used to create this disk. This value identifies
        the exact image that was used to create this persistent disk. For example,
        if you created the persistent disk from an image that was later deleted and
        recreated under the same name, the source image ID would identify the exact
        version of the image that was used.
      returned: success
      type: str
    diskEncryptionKey:
      description:
      - Encrypts the disk using a customer-supplied encryption key.
      - After you encrypt a disk with a customer-supplied key, you must provide the
        same key if you use the disk later (e.g. to create a disk snapshot or an image,
        or to attach the disk to a virtual machine).
      - Customer-supplied encryption keys do not protect access to metadata of the
        disk.
      - If you do not provide an encryption key when creating the disk, then the disk
        will be encrypted using an automatically generated key and you do not need
        to provide a key to use the disk later.
      returned: success
      type: complex
      contains:
        rawKey:
          description:
          - Specifies a 256-bit customer-supplied encryption key, encoded in RFC 4648
            base64 to either encrypt or decrypt this resource.
          returned: success
          type: str
        sha256:
          description:
          - The RFC 4648 base64 encoded SHA-256 hash of the customer-supplied encryption
            key that protects this resource.
          returned: success
          type: str
        kmsKeyName:
          description:
          - The name of the encryption key that is stored in Google Cloud KMS.
          - Your project's Compute Engine System service account (`service-{{PROJECT_NUMBER}}@compute-system.iam.gserviceaccount.com`)
            must have `roles/cloudkms.cryptoKeyEncrypterDecrypter` to use this feature.
          returned: success
          type: str
        kmsKeyServiceAccount:
          description:
          - The service account used for the encryption request for the given KMS
            key.
          - If absent, the Compute Engine Service Agent service account is used.
          returned: success
          type: str
    sourceSnapshot:
      description:
      - The source snapshot used to create this disk. You can provide this as a partial
        or full URL to the resource.
      returned: success
      type: dict
    sourceSnapshotEncryptionKey:
      description:
      - The customer-supplied encryption key of the source snapshot. Required if the
        source snapshot is protected by a customer-supplied encryption key.
      returned: success
      type: complex
      contains:
        rawKey:
          description:
          - Specifies a 256-bit customer-supplied encryption key, encoded in RFC 4648
            base64 to either encrypt or decrypt this resource.
          returned: success
          type: str
        kmsKeyName:
          description:
          - The name of the encryption key that is stored in Google Cloud KMS.
          returned: success
          type: str
        sha256:
          description:
          - The RFC 4648 base64 encoded SHA-256 hash of the customer-supplied encryption
            key that protects this resource.
          returned: success
          type: str
        kmsKeyServiceAccount:
          description:
          - The service account used for the encryption request for the given KMS
            key.
          - If absent, the Compute Engine Service Agent service account is used.
          returned: success
          type: str
    sourceSnapshotId:
      description:
      - The unique ID of the snapshot used to create this disk. This value identifies
        the exact snapshot that was used to create this persistent disk. For example,
        if you created the persistent disk from a snapshot that was later deleted
        and recreated under the same name, the source snapshot ID would identify the
        exact version of the snapshot that was used.
      returned: success
      type: str
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
    module = GcpModule(argument_spec=dict(filters=dict(type='list', elements='str'), zone=dict(required=True, type='str')))

    if not module.params['scopes']:
        module.params['scopes'] = ['https://www.googleapis.com/auth/compute']

    return_value = {'resources': fetch_list(module, collection(module), query_options(module.params['filters']))}
    module.exit_json(**return_value)


def collection(module):
    return "https://compute.googleapis.com/compute/v1/projects/{project}/zones/{zone}/disks".format(**module.params)


def fetch_list(module, link, query):
    auth = GcpSession(module, 'compute')
    return auth.list(link, return_if_object, array_name='items', params={'filter': query})


def query_options(filters):
    if not filters:
        return ''

    if len(filters) == 1:
        return filters[0]
    else:
        queries = []
        for f in filters:
            # For multiple queries, all queries should have ()
            if f[0] != '(' and f[-1] != ')':
                queries.append("(%s)" % ''.join(f))
            else:
                queries.append(f)

        return ' '.join(queries)


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
