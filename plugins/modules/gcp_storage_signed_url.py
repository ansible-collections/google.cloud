#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2026 Google
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

__metaclass__ = type

################################################################################
# Documentation
################################################################################

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = """
---
module: gcp_storage_signed_url
description:
- Generate a V4 signed URL for a GCS object, so that a party without any IAM access
  to the bucket can perform a single HTTP request (GET, PUT, DELETE or HEAD) against
  that object until the URL expires.
- Two signing methods are supported, and exactly one must be configured. With
  I(signer_service_account), the URL is signed by a service account other than the
  one running the module, via the IAM Credentials API C(signBlob) - no service
  account private key is ever read from disk, but the identity running the module
  needs C(roles/iam.serviceAccountTokenCreator) on the signer, and generating the
  URL costs one IAM API call. With I(hmac_key_access_id) / I(hmac_key_secret), the
  URL is signed locally from an HMAC key secret - no IAM API call and no
  serviceAccountTokenCreator grant are needed at all, at the cost of managing an
  HMAC key credential (created with C(gcloud storage hmac create) or the
  C(storage.projects.hmacKeys.create) API) instead of an IAM binding.
short_description: Generates a signed URL for a GCP Storage object
author: Google Inc. (@googlecloudplatform)
requirements:
- python >= 2.6
- requests >= 2.18.4
- google-auth >= 1.3.0
- google-cloud-storage >= 1.2.0
options:
  bucket:
    description:
    - The name of the bucket containing the object.
    required: true
    type: str
  object_name:
    description:
    - The full path of the object inside the bucket.
    required: true
    type: str
  signer_service_account:
    description:
    - Email of the service account that signs the URL, via the IAM Credentials API.
    - It must have read (or write, for I(http_method=PUT)) access to the object; the
      identity running this module must hold roles/iam.serviceAccountTokenCreator
      on it.
    - Mutually exclusive with I(hmac_key_access_id) / I(hmac_key_secret).
    type: str
  hmac_key_access_id:
    description:
    - Access ID of an HMAC key belonging to the service account (or user) that signs
      the URL.
    - The signing is performed locally, using the V4 HMAC-SHA256 algorithm - no call
      to the IAM Credentials API is made, and no serviceAccountTokenCreator grant is
      required.
    - Requires I(hmac_key_secret). Mutually exclusive with I(signer_service_account).
    type: str
  hmac_key_secret:
    description:
    - Secret of the HMAC key identified by I(hmac_key_access_id).
    - Requires I(hmac_key_access_id).
    type: str
  region:
    description:
    - Region used in the credential scope of the V4 signature when signing with an
      HMAC key. Any value is accepted by Cloud Storage; it does not need to match
      the bucket's actual location.
    - Only used with I(hmac_key_access_id).
    type: str
    default: auto
  expiration_seconds:
    description:
    - How long the signed URL stays valid, in seconds.
    - Cannot exceed 604800 (7 days), the limit of the V4 signing scheme.
    type: int
    default: 900
  http_method:
    description:
    - HTTP method the signed URL is valid for.
    type: str
    default: GET
    choices:
    - GET
    - PUT
    - DELETE
    - HEAD
  project:
    description:
    - The Google Cloud Platform project to use.
    type: str
  auth_kind:
    description:
    - The type of credential used.
    - Still required when signing with I(hmac_key_access_id), even though it is not
      used to build the signature itself.
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
  env_type:
    description:
    - Specifies which Ansible environment you're running this module within.
    - This should not be set unless you know what you're doing.
    - This only alters the User Agent string for any API requests.
    type: str
"""

EXAMPLES = """
- name: Generate a signed URL via IAM Credentials API (signBlob), then download it
  block:
    - name: Generate signed URL, signed by a dedicated service account
      google.cloud.gcp_storage_signed_url:
        bucket: my-software-bucket
        object_name: agents/agent-1.2.3.rpm
        signer_service_account: bucket-reader-sa@my-project.iam.gserviceaccount.com
        auth_kind: application
      delegate_to: localhost
      register: package_url

    - name: Download package
      ansible.builtin.get_url:
        url: "{{ package_url.signed_url }}"
        dest: /tmp/agent.rpm

- name: Generate a signed URL locally from an HMAC key, no IAM API call involved
  google.cloud.gcp_storage_signed_url:
    bucket: my-software-bucket
    object_name: agents/agent-1.2.3.rpm
    hmac_key_access_id: GOOG1EZ...
    hmac_key_secret: "{{ vaulted_hmac_secret }}"
    auth_kind: application
  delegate_to: localhost
  register: package_url
"""

RETURN = """
signed_url:
  description:
  - The generated signed URL.
  returned: success
  type: str
expires_at:
  description:
  - When the signed URL stops being valid, in ISO 8601 UTC.
  returned: success
  type: str
"""

################################################################################
# Imports
################################################################################

import datetime
import hashlib
import hmac

try:
    from urllib.parse import quote
except ImportError:
    from urllib import quote

from ansible_collections.google.cloud.plugins.module_utils.gcp_utils import (
    GcpSession,
    GcpModule,
)

try:
    import google.auth.transport.requests
    from google.cloud import storage
    from google.api_core.client_info import ClientInfo

    HAS_GOOGLE_STORAGE_LIBRARY = True
except ImportError:
    HAS_GOOGLE_STORAGE_LIBRARY = False

MAX_EXPIRATION_SECONDS = 604800

################################################################################
# Main
################################################################################


def main():
    """Main function"""

    module = GcpModule(
        argument_spec=dict(
            bucket=dict(type="str", required=True),
            object_name=dict(type="str", required=True),
            signer_service_account=dict(type="str"),
            hmac_key_access_id=dict(type="str"),
            hmac_key_secret=dict(type="str", no_log=True),
            region=dict(type="str", default="auto"),
            expiration_seconds=dict(type="int", default=900),
            http_method=dict(
                type="str", default="GET", choices=["GET", "PUT", "DELETE", "HEAD"]
            ),
        )
    )

    validate_signing_params(module)

    if module.params["expiration_seconds"] > MAX_EXPIRATION_SECONDS:
        module.fail_json(
            msg="`expiration_seconds` cannot exceed %d (7 days), the limit of the V4 "
            "signing scheme" % MAX_EXPIRATION_SECONDS
        )

    if module.params["hmac_key_access_id"]:
        signed_url, expires_at = generate_hmac_signed_url(module)
        module.exit_json(changed=False, signed_url=signed_url, expires_at=expires_at)

    if not HAS_GOOGLE_STORAGE_LIBRARY:
        module.fail_json(msg="Please install the google-cloud-storage Python library")

    if not module.params["scopes"]:
        module.params["scopes"] = [
            "https://www.googleapis.com/auth/devstorage.read_only",
            "https://www.googleapis.com/auth/iam",
        ]

    credentials = GcpSession(module, "storage")._credentials()

    # generate_signed_url() with an explicit signer_service_account signs via the IAM
    # Credentials API (signBlob) instead of a local private key, which application/
    # machineaccount credentials never carry - that call needs a live bearer token
    # from the caller's own credentials, not the target service account's.
    if not credentials.valid:
        credentials.refresh(google.auth.transport.requests.Request())

    client = storage.Client(
        project=module.params["project"],
        credentials=credentials,
        client_info=ClientInfo(user_agent="Google-Ansible-MM-signed-url"),
    )

    bucket = client.bucket(module.params["bucket"])
    blob = bucket.blob(module.params["object_name"])

    expiration = datetime.timedelta(seconds=module.params["expiration_seconds"])

    try:
        signed_url = blob.generate_signed_url(
            version="v4",
            expiration=expiration,
            method=module.params["http_method"],
            service_account_email=module.params["signer_service_account"],
            access_token=credentials.token,
        )
    except Exception as e:
        module.fail_json(msg="Could not generate signed URL: %s" % str(e))

    expires_at = datetime.datetime.utcnow() + expiration
    module.exit_json(
        changed=False,
        signed_url=signed_url,
        expires_at=expires_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
    )


def validate_signing_params(module):
    signer_service_account = module.params["signer_service_account"]
    hmac_key_access_id = module.params["hmac_key_access_id"]
    hmac_key_secret = module.params["hmac_key_secret"]

    if signer_service_account and hmac_key_access_id:
        module.fail_json(
            msg="`signer_service_account` and `hmac_key_access_id` are mutually "
            "exclusive: choose one signing method"
        )

    if not signer_service_account and not hmac_key_access_id:
        module.fail_json(
            msg="One of `signer_service_account` or `hmac_key_access_id` is "
            "required to sign the URL"
        )

    if bool(hmac_key_access_id) != bool(hmac_key_secret):
        module.fail_json(
            msg="`hmac_key_access_id` and `hmac_key_secret` are required together"
        )


def generate_hmac_signed_url(module):
    """Signs a V4 URL locally with an HMAC key, per the algorithm documented at
    https://cloud.google.com/storage/docs/authentication/signatures - no call to
    the IAM Credentials API is involved, so no serviceAccountTokenCreator grant is
    needed on the signing identity."""

    access_id = module.params["hmac_key_access_id"]
    secret = module.params["hmac_key_secret"]
    region = module.params["region"]
    http_method = module.params["http_method"]
    expiration_seconds = module.params["expiration_seconds"]

    host = "storage.googleapis.com"
    now = datetime.datetime.utcnow()
    request_timestamp = now.strftime("%Y%m%dT%H%M%SZ")
    datestamp = now.strftime("%Y%m%d")

    credential_scope = "%s/%s/storage/goog4_request" % (datestamp, region)
    credential = "%s/%s" % (access_id, credential_scope)

    canonical_uri = "/%s/%s" % (
        quote(module.params["bucket"], safe=""),
        quote(module.params["object_name"], safe="/~"),
    )

    canonical_query_string = "&".join(
        [
            "X-Goog-Algorithm=GOOG4-HMAC-SHA256",
            "X-Goog-Credential=%s" % quote(credential, safe=""),
            "X-Goog-Date=%s" % request_timestamp,
            "X-Goog-Expires=%s" % expiration_seconds,
            "X-Goog-SignedHeaders=host",
        ]
    )

    canonical_headers = "host:%s" % host
    signed_headers = "host"

    canonical_request = "\n".join(
        [
            http_method,
            canonical_uri,
            canonical_query_string,
            canonical_headers,
            "",
            signed_headers,
            "UNSIGNED-PAYLOAD",
        ]
    )

    string_to_sign = "\n".join(
        [
            "GOOG4-HMAC-SHA256",
            request_timestamp,
            credential_scope,
            hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
        ]
    )

    signing_key = _derive_hmac_signing_key(secret, datestamp, region)
    signature = hmac.new(
        signing_key, string_to_sign.encode("utf-8"), hashlib.sha256
    ).hexdigest()

    signed_url = "https://%s%s?%s&X-Goog-Signature=%s" % (
        host,
        canonical_uri,
        canonical_query_string,
        signature,
    )
    expires_at = now + datetime.timedelta(seconds=expiration_seconds)

    return signed_url, expires_at.strftime("%Y-%m-%dT%H:%M:%SZ")


def _hmac_sha256(key, msg):
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _derive_hmac_signing_key(secret, datestamp, region):
    key_date = _hmac_sha256(("GOOG4" + secret).encode("utf-8"), datestamp)
    key_region = _hmac_sha256(key_date, region)
    key_service = _hmac_sha256(key_region, "storage")
    return _hmac_sha256(key_service, "goog4_request")


if __name__ == "__main__":
    main()
