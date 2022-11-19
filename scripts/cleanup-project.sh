#!/usr/bin/env bash
# cleanup-project cleans up an ansible testing project
#
# WARNING: do not run tests against a project while
# this is running, or else your tests will fail.
#
# dependencies:
#  - google-cloud-sdk (gcloudgcloud )
set -e
PROJECT_ID="${1}"
SERVICE_ACCOUNT_NAME="${2}"
ZONE="us-central1-a"

main() {
    # note: the ordering here is deliberate, to start with
    # leaf resources and work upwards to parent resources.
    cleanup_resource_per_region "compute vpn-tunnels"
    cleanup_resource "compute instances" "" "--zone=$ZONE"
    cleanup_resource_per_region "compute addresses"
    cleanup_resource "compute target-http-proxies" "" "--global"
    cleanup_resource "compute forwarding-rules" "--global" "--global"
    cleanup_resource "compute forwarding-rules" \
        "--regions=us-central1" "--region=us-central1"
    cleanup_resource "compute url-maps" "--global" "--global"
    cleanup_resource "compute url-maps" \
        "--regions=us-central1" "--region=us-central1"
    cleanup_resource "compute backend-services" "--global" "--global"
    cleanup_resource "compute backend-services" \
        "--regions=us-central1" "--region=us-central1"
}

cleanup_resource() {
    resource_group="$1"
    extra_list_args="$2"
    extra_delete_args="$3"

    for resource in $(gcloud $resource_group list --project="${PROJECT_ID}" --format="csv[no-heading](name)" $extra_list_args); do
        gcloud $resource_group delete "${resource}" --project="${PROJECT_ID}" -q $extra_delete_args
    done
}

cleanup_resource_per_region() {
    resource_group="$1"
    for resource_and_region in $(gcloud $resource_group list --project="${PROJECT_ID}" --format="csv[no-heading](name,region)"); do
        read -r resource region < <(echo "$resource_and_region" | tr "," " ")
        gcloud $resource_group delete "${resource}" --project="${PROJECT_ID}" -q --region="${region}"
    done
}

main