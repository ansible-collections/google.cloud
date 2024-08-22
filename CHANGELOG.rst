==========================
Google.Cloud Release Notes
==========================

.. contents:: Topics

v1.4.1
======

Bugfixes
--------

- gcp_kms_filters - add DOCUMENTATION string
- gcp_secret_manager - make an f-string usage backward compatible

v1.4.0
======

Minor Changes
-------------

- ansible - 2.16.0 is now the minimum version supported
- ansible - 3.10 is now the minimum Python version
- ansible-test - integration tests are now run against 2.16.0 and 2.17.0
- gcloud role - use dnf instead of yum on RHEL
- gcp_secret_manager - add as a module and lookup plugin (https://github.com/ansible-collections/google.cloud/pull/578)
- gcp_secret_manager - support more than 10 versions (https://github.com/ansible-collections/google.cloud/pull/634)
- restore google_cloud_ops_agents submodule (https://github.com/ansible-collections/google.cloud/pull/594)

Bugfixes
--------

- ansible-lint - remove jinja templates from test assertions

v1.3.0
======

Minor Changes
-------------

- anisble-test - integration tests are now run against 2.14.0 and 2.15.0
- ansible - 2.14.0 is now the minimum version supported
- ansible-lint - fixed over a thousand reported errors
- ansible-lint - upgraded to 6.22
- ansible-test - add support for GCP application default credentials (https://github.com/ansible-collections/google.cloud/issues/359).
- gcp_serviceusage_service - added backoff when checking for operation completion.
- gcp_serviceusage_service - use alloyb API for the integration test as spanner conflicts with other tests
- gcp_sql_ssl_cert - made sha1_fingerprint optional, which enables resource creation
- gcp_storage_default_object_acl - removed non-existent fields; the resource is not usable.

v1.2.0
======

Minor Changes
-------------

- Add DataPlane V2 Support.
- Add auth support for GCP access tokens (#574).
- Add support for ip_allocation_policy->stack_type.

Bugfixes
--------

- Use default service account if `service_account_email` is unset.

v1.1.3
======

Bugfixes
--------

- gcp_compute_instance_info: fix incorrect documentation for filter which incorrectly pointed to the gcloud filter logic rather than the API (fixes #549)

v1.1.2
======

Bugfixes
--------

- fix `gcp_compute` no longer being a valid name of the inventory plugin

v1.1.1
======

Bugfixes
--------

- fix collection to work with Python 2.7

v1.1.0
======

Minor Changes
-------------

- GCE inventory plugin - a new option ``name_suffix``, to add a suffix to the name parameter.

Bugfixes
--------

- Disk has been fixed to send the sourceSnapshot parameter.
- gcp_cloudtasks_queue - was not functional before, and is now functional.
- gcp_compute_* - these resources use the correct selflink (www.googleapis.com) as the domain, no longer erroneously reporting changes after an execution.
- gcp_compute_backend_service - no longer erroneously reports changes after an execution for ``capacity_scaler``.
- gcp_container_cluster - support GKE clusters greater than 1.19+, which cannot use basic-auth.
- gcp_crypto_key - skip_initial_version_creation defaults to the correct value.
- gcp_iam_role - now properly undeletes and recognizes soft deleted roles as absent.
- gcp_iam_role - update of a role is functional (GitHub
- gcp_spanner_database - recognize a non-existent resource as absent.
- gcp_storage_object - fix for correct version of dependency requirement.
