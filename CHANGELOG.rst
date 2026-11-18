==========================
Google.Cloud Release Notes
==========================

.. contents:: Topics

v1.16.0
=======

Minor Changes
-------------

- Added gcp_storage_signed_url module - generates a V4 signed URL for a GCS object, so a party without any IAM access to the bucket can perform a single HTTP request against that object until the URL expires. Supports signing via the IAM Credentials API (``signBlob``, using a service account other than the one running the module) or locally via an HMAC key, with no IAM API call and no ``serviceAccountTokenCreator`` grant required for the latter.
- audit - added ``tests/unit/audit/test_event_query_contract.py``, which asserts the constraints the controller imposes on the query file (https://github.com/ansible-collections/google.cloud/pull/781).
- audit - dropped the mappings for ``gcp_resource_record_set`` and ``gcp_sourcerepo_repository``; neither module exists in this collection (https://github.com/ansible-collections/google.cloud/pull/781).
- event_query - the contract test now compiles every expression with ``jq``. Every other check in that file reads the query as text, so all of them pass on an expression that cannot run.
- gcp_networkconnectivity_* - Add gcp_networkconnectivity_hub and gcp_networkconnectivity_spoke with accompanying _info modules (https://github.com/ansible-collections/google.cloud/pull/788)

Bugfixes
--------

- ansible-mmv1(templates) - Reverted to a 3-way boolean check for custom diff logic, this way you can force a custom diff when the values aren't actually different
- ansible-mmv1(templates) - The DOCUMENTATION block was incorrectly printing `short_description` at the end of the block because of alphabetical order (bug - https://github.com/ansible-collections/google.cloud/issues/789, fix - https://github.com/thekad/ansible-mmv1/commit/993cb04be0c6567d2846ce473e78769a696c536f)
- ansible-mmv1(templates) - The RETURNS block was showing incomplete output (fix - https://github.com/thekad/ansible-mmv1/commit/54a04c5d75ca09e1bb75f0d4766347373bfc22ef)
- audit - ``device_type`` was looked up by the resource ``kind``, which no module's ``response_to_hash()`` returns, so every resource would have been labelled ``missing``. Each module now carries its resource type literally (https://github.com/ansible-collections/google.cloud/pull/781).
- audit - ``gcp_container_cluster`` and ``gcp_container_node_pool`` were keyed on ``.name``, which the GKE API returns as the short name only. Same-named node pools in different clusters, and same-named clusters in different projects or locations, collapsed into a single indirect node; because the controller requires ``name`` to be unique within a job, a job touching two of them lost every audit record it produced. Both now key on the full resource identity (``.id``/``.selfLink``) (https://github.com/ansible-collections/google.cloud/pull/781).
- audit - ``gcp_dns_resource_record_set`` guarded only ``.name``, so a result carrying no ``.type`` emitted the identifier ``"<name>/null"`` -- ``null | tostring`` is the string ``"null"``, not null -- and every such record in a job collided on the same identifier. ``.type`` is now guarded as well (https://github.com/ansible-collections/google.cloud/pull/781).
- audit - ``gcp_dns_resource_record_set`` was identified by name alone; an A record and a TXT record on the same name are two resources and were collapsed into one (https://github.com/ansible-collections/google.cloud/pull/781).
- audit - ``name`` was part of ``canonical_facts``, which is the only key the controller deduplicates on, so a renamed resource counted twice (https://github.com/ansible-collections/google.cloud/pull/781).
- audit - the identifier fell back to ``etag`` when a module returned no ``id``. ``etag`` changes on every mutation, so ``gcp_filestore_instance`` -- the only module in the collection that returns no ``id`` -- counted the same resource again each time it was modified (https://github.com/ansible-collections/google.cloud/pull/781).
- audit - the indirect node counting query was shipped as ``extensions/audit/taxonomy.jq``. The Automation Platform controller only reads ``extensions/audit/event_query.yml``, so the file was never loaded and this collection reported no indirect nodes at all. It is now ``extensions/audit/event_query.yml`` (https://github.com/ansible-collections/google.cloud/pull/781).
- audit - the query iterated the module result with ``.[]`` and called ``has("results")`` on each value, which raises ``Cannot check whether boolean has a string key`` on the ``changed`` key that every module returns. The controller catches jq errors and discards the whole event, so the query could not have emitted a record even if it had been loaded (https://github.com/ansible-collections/google.cloud/pull/781).
- audit - the query selected resources with ``select($data.action | in($actions))``, but the controller passes jq only the module result and no module in this collection returns its own name, so nothing was ever selected. Each module now has its own entry keyed by FQCN (https://github.com/ansible-collections/google.cloud/pull/781).
- event_query - the two Pub/Sub queries emitted ``infra_bucket`` ``app_integration_messaging``, which is not one of the nine values the Normalized Resource Taxonomy defines. Those nodes bucketed into a category nothing downstream aggregates. Corrected to ``devops_app_integration``.
- gcp_utils, inventory/gcp_compute, gcp_iam_service_account_key - Replaced deprecated `ansible.module_utils._text` imports with `ansible.module_utils.common.text.converters`

v1.15.0
=======

Minor Changes
-------------

- gcp_alloydb_* - update to most recent version generated from MMv1
- gcp_binaryauthorization_* - Adding 4 new binauthz modules for attestor/policy and accompanying info modules (https://github.com/ansible-collections/google.cloud/pull/782)
- gcp_cloudbuild_trigger - update to most recent version generated from MMv1
- gcp_cloudbuildv2_* - update to most recent version generated from MMv1
- gcp_colab_* - update to most recent version generated from MMv1
- gcp_compute inventory plugin - print an aggregate warning at the end of a sync when ``folders:`` is used and one or more resolved projects were skipped, summarizing how many out of the total.
- gcp_containeranalysis_* - Adding 2 new container analysis module and info module (https://github.com/ansible-collections/google.cloud/pull/782)
- gcp_vertexai_* - update to most recent version generated from MMv1

Bugfixes
--------

- gcp_compute inventory plugin - deduplicate resolved projects when ``folders:`` lists both a folder and one of its descendants, which previously caused that descendant's projects (and therefore its hosts) to be resolved twice.
- gcp_compute inventory plugin - resolve subfolders recursively when using ``folders:``, instead of only the projects that are direct children of the given folder. On hierarchies where the given folder only contains subfolders (no projects directly attached), the plugin previously always returned zero hosts.
- gcp_compute inventory plugin - skip a project instead of failing the entire inventory sync when a project resolved via ``folders:`` cannot be queried (Compute Engine API disabled, or blocked by a VPC Service Controls perimeter). Any other error still fails as before.
- module_utils.gcp_v2 - Fix a premature encoding bug by moving the encoding to right before sending to the API (https://github.com/ansible-collections/google.cloud/pull/782)
- module_utils.gcp_v2 - Fix double decoding bug where async operations went through the custom decoder (if any) twice (https://github.com/ansible-collections/google.cloud/pull/782)

v1.14.0
=======

Minor Changes
-------------

- gcp_alloydb_*, gcp_cloudbuild_*, gcp_colab_*, gcp_vertexai_* - update to use `plugins/module_utils/gcp_v2.py` (https://github.com/ansible-collections/google.cloud/pull/763)

v1.13.0
=======

Minor Changes
-------------

- gcp_colab_* - added four new modules (gcp_colab_notebook_execution, gcp_colab_runtime, gcp_colab_runtime_template, and gcp_colab_schedule) (https://github.com/ansible-collections/google.cloud/pull/747).
- gcp_compute_instance_* - renamed the `tags.items` field to `tags.tag_values`. The old naming is still available but will be removed in a future release. (https://github.com/ansible-collections/google.cloud/pull/750).

v1.12.0
=======

Minor Changes
-------------

- gcp_sql_instance - add `allocated_ip_range` to `settings.ip_configuration` for private IP Cloud SQL instances (name of the allocated IP range in the VPC) (https://github.com/ansible-collections/google.cloud/pull/744).
- gcp_vertexai_* - added 18 Vertex AI modules (gcp_vertexai_dataset, gcp_vertexai_deployment_resource_pool, gcp_vertexai_endpoint, gcp_vertexai_endpoint_with_model_garden_deployment, gcp_vertexai_feature_group, gcp_vertexai_feature_group_feature, gcp_vertexai_feature_online_store, gcp_vertexai_feature_online_store_featureview, gcp_vertexai_featurestore, gcp_vertexai_featurestore_entitytype, gcp_vertexai_featurestore_entitytype_feature, gcp_vertexai_index, gcp_vertexai_index_endpoint, gcp_vertexai_index_endpoint_deployed_index, gcp_vertexai_metadata_store, gcp_vertexai_rag_engine_config, gcp_vertexai_reasoning_engine, gcp_vertexai_tensorboard) (https://github.com/ansible-collections/google.cloud/pull/743).

v1.11.0
=======

Minor Changes
-------------

- gcp_cloudbuildv2_* - added gcp_cloudbuildv2_connection and gcp_cloudbuildv2_repository modules (https://github.com/ansible-collections/google.cloud/pull/729).

Bugfixes
--------

- connection plugin - fix attribute error when using reset_connection (https://github.com/ansible-collections/google.cloud/issues/737).
- connection plugin - fix ssh error in tasks with loops (https://github.com/ansible-collections/google.cloud/issues/738).

v1.10.2
=======

Bugfixes
--------

- Revert removal of Ansible 2.16 support (https://github.com/ansible-collections/google.cloud/pull/734)

v1.10.1
=======

Bugfixes
--------

- Fix runtime.yml to correctly note Ansible 2.17 minimum version (https://github.com/ansible-collections/google.cloud/pull/730)

v1.10.0
=======

Minor Changes
-------------

- gcp_alloydb_* - added gcp_alloydb_cluster, gcp_alloydb_instance, gcp_alloydb_backup, and gcp_alloydb_user modules (https://github.com/ansible-collections/google.cloud/pull/722)

Bugfixes
--------

- gcp_secret_manager - return the secret value as type `str` rather than `bytes` (https://github.com/ansible-collections/google.cloud/pull/721)

v1.9.0
======

Minor Changes
-------------

- iap - added scp_if_ssh option (https://github.com/ansible-collections/google.cloud/pull/716).

v1.8.0
======

Minor Changes
-------------

- iap - enable use of Identity Aware Proxy ssh connections to compute instances (https://github.com/ansible-collections/google.cloud/pull/709).

Bugfixes
--------

- gcp_compute_instance - add suppport for attaching disks to compute instances (https://github.com/ansible-collections/google.cloud/pull/711).
- gcp_secret_manager - use service_account_contents instead of service_account_info (https://github.com/ansible-collections/google.cloud/pull/703).

v1.7.0
======

Minor Changes
-------------

- gcp_parameter_manager - added module support for managing parameters and versions (https://github.com/ansible-collections/google.cloud/pull/684).
- gcp_storage_bucket - added support for iam_configuration (https://github.com/ansible-collections/google.cloud/pull/693).
- lookup - added lookup via gcp_parameter_manager (https://github.com/ansible-collections/google.cloud/pull/684).

Bugfixes
--------

- gcp_bigquery_table - fixed nested schema definitions (https://github.com/ansible-collections/google.cloud/issues/637).

v1.6.0
======

Minor Changes
-------------

- gcp_compute - added GVNIC support to compute instance (https://github.com/ansible-collections/google.cloud/pull/688).
- gcp_compute - added ``discard_local_ssd`` flag to compute instance (https://github.com/ansible-collections/google.cloud/pull/686).
- gcp_compute - added hostname support to dynamic inventory (https://github.com/ansible-collections/google.cloud/pull/689).
- gcp_secret_manager - added support for regional secret manager (https://github.com/ansible-collections/google.cloud/pull/685).

Bugfixes
--------

- gcp_secret_manager - cleaned up error responses (https://github.com/ansible-collections/google.cloud/pull/690).
- gcp_serviceusage_service - updated documentation (https://github.com/ansible-collections/google.cloud/pull/691).

v1.5.3
======

Bugfixes
--------

- updated README to match required format (https://github.com/ansible-collections/google.cloud/pull/682).

v1.5.2
======

Bugfixes
--------

- gcp_compute - fixed get_project_disks to process all responses (https://github.com/ansible-collections/google.cloud/pull/677).

v1.5.1
======

Bugfixes
--------

- run integration test with Ansible 2.16 to match `requires_ansible` version

v1.5.0
======

Major Changes
-------------

- google_cloud_ops_agents - role submodule removed because it prevents the collection from passing sanity and lint tests

Minor Changes
-------------

- gcp_pubsub_subscription - allows to create GCS subscription

Bugfixes
--------

- ansible - 2.17 is now the minimum version supported
- ansible - 3.11 is now the minimum Python version
- ansible-test - fixed sanity tests
- ansible-test - integration tests are now run against 2.17 and 2.18
- gcp_bigquery_table - properly handle BigQuery table clustering fields
- gcp_pubsub_subscription - fixed improper subscription uprade PATCH request

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
