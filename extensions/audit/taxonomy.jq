(
  {
    "google.cloud.gcp_bigquery_dataset": "database",
    "google.cloud.gcp_bigquery_table": "database",
    "google.cloud.gcp_compute_address": "networking",
    "google.cloud.gcp_compute_disk": "storage",
    "google.cloud.gcp_compute_firewall": "security_identity",
    "google.cloud.gcp_compute_instance": "compute",
    "google.cloud.gcp_compute_instance_group_manager": "compute",
    "google.cloud.gcp_compute_instance_template": "compute",
    "google.cloud.gcp_compute_network": "networking",
    "google.cloud.gcp_compute_ssl_certificate": "security_identity",
    "google.cloud.gcp_container_cluster": "compute",
    "google.cloud.gcp_container_node_pool": "compute",
    "google.cloud.gcp_dns_managed_zone": "networking",
    "google.cloud.gcp_dns_resource_record_set": "networking",
    "google.cloud.gcp_filestore_instance": "storage",
    "google.cloud.gcp_iam_role": "security_identity",
    "google.cloud.gcp_iam_service_account": "security_identity",
    "google.cloud.gcp_kms_key_ring": "security_identity",
    "google.cloud.gcp_pubsub_subscription": "app_integration_messaging",
    "google.cloud.gcp_pubsub_topic": "app_integration_messaging",
    "google.cloud.gcp_resource_record_set": "networking",
    "google.cloud.gcp_sourcerepo_repository": "devops_app_integration",
    "google.cloud.gcp_sql_instance": "database",
    "google.cloud.gcp_storage_bucket": "storage",
  } as $actions|
  {
    "compute#instance": "virtual_machine",
    "compute#instanceTemplate": "virtual_machine_template",
    "compute#instanceGroupManager": "instance_group",
    "compute#disk": "block_storage",
    "compute#address": "vpc",
    "compute#firewall": "firewall",
    "compute#network": "vpc",
    "compute#sslCertificate": "certificate",
    "dns#managedZone": "dns",
    "dns#resourceRecordSet": "dns",
    "bigquery#dataset": "database_analytics",
    "bigquery#table": "database_analytics",
    "sql#instance": "database_relational",
    "storage#bucket": "object_storage",
    "file#instance": "file_storage",
    "iam#role": "iam",
    "iam#serviceAccount": "iam",
    "cloudkms#keyRing": "key_vault",
    "pubsub#subscription": "messaging",
    "pubsub#topic": "messaging",
    "container#cluster": "kubernetes_cluster",
    "container#nodePool": "kubernetes_node_pool",
    "sourcerepo#repo": "source_repository",
  } as $device_type_mapping|
  .[] |
  (if has("results") then  # if ran in a loop, flatten it
    .results[] as $result |
    . + $result |
    del(.results)
  else
    .
  end) as $data |
  select($data.action | in($actions))  |  # only select objects defined in the action mapping
  ($data.id // $data.etag // $data.selfLink // $data.name) as $id |  # not everything returns an ID
  ($data.name // $id) as $name |  # not everything returns a name
  ($data.kind // "missing") as $kind |  # not everything returns a kind
  select($name != null and $id != null) |
    {
      name: $name,
      canonical_facts: {
        id: $id,
        name: $name,
        kind: $kind,
      },
      facts: {
        infra_type: "public_cloud",
        infra_bucket: $actions[$data.action],
        device_type: ($device_type_mapping[$kind] // $kind),
      }
    }
)
