==========================
Google.Cloud Release Notes
==========================

.. contents:: Topics


v1.1.0-beta.0
=============

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
- gcp_spanner_database - recognize a non-existent resource as absent.
- gcp_storage_object - fix for correct version of dependency requirement.