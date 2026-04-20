#!/usr/bin/env bash

set -eux

# Debugging
echo "PATH: ${PATH}"
echo "LD_LIBRARY_PATH: ${LD_LIBRARY_PATH}"
pwd
which python
pip install google-auth google-auth-oauthlib
ansg=$(which ansible-galaxy)
ansp=$(which ansible-playbook)
python $ansg collection install community.crypto
python $ansp playbooks/setup.yml "$@"
# End debugging

# test infra
ansible-galaxy collection install community.crypto
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
