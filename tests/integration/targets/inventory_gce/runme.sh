#!/usr/bin/env bash

set -eux

# test infra
ansible-playbook playbooks/setup.yml "$@"

export ANSIBLE_INVENTORY=test.gcp_compute.yml

RC=0
# we want to run teardown regardless of playbook exit status, so catch the
# exit code of ansible-playbook manually
set +e
for ts in testcase_*.yml;
do
    testcase=$( basename "$ts" | sed -e 's/testcase_//' | sed -e 's/.yml//' )
    ansible-playbook playbooks/test.yml "$@" --extra-vars "testcase=${testcase}"
    RC=$?
    test $RC -ne 0 && break
done
set -e

unset ANSIBLE_INVENTORY

# delete test infra
ansible-playbook playbooks/teardown.yml "$@"

exit $RC
