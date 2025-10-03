#!/usr/bin/env bash

set -eux

# prereq
ansible-galaxy collection install community.crypto

# test infra
ansible-playbook playbooks/setup.yml "$@"

export ANSIBLE_INVENTORY=test.gcp_compute.yml

ansible-inventory --graph

RC=0
# we want to run teardown regardless of playbook exit status, so catch the
# exit code of ansible-playbook manually
set +e
ansible-playbook -vvvvv playbooks/test.yml "$@"
RC=$?
set -e

unset ANSIBLE_INVENTORY

# delete test infra
ansible-playbook playbooks/teardown.yml "$@"

exit $RC
