#!/usr/bin/env bash

set -eux

# use the gcloud CLI's currently active configuration to exercise the iap
# connection plugin's gcloud_configuration option (see issue #759)
GCLOUD_CONFIGURATION=$(gcloud config configurations list --filter="is_active:true" --format="value(name)")

# test infra
ansible-playbook playbooks/setup.yml "$@"

export ANSIBLE_INVENTORY=test.gcp_compute.yml

ansible-inventory --graph

RC=0
# we want to run teardown regardless of playbook exit status, so catch the
# exit code of ansible-playbook manually
set +e
ansible-playbook -v playbooks/test.yml "$@" --extra-vars "ansible_gcloud_configuration=${GCLOUD_CONFIGURATION}"
RC=$?
set -e

unset ANSIBLE_INVENTORY

# delete test infra
ansible-playbook playbooks/teardown.yml "$@"

exit $RC
