#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function

__metaclass__ = type

#######################################################
# Documentation
#######################################################

DOCUMENTATION = '''
---
module: gcp_compute_instance_labels
short_description: Manages labels on a GCP Compute Instance in Google Cloud.
version_added: "1.0"
description:
  - Manages labels of instances in GCP. It supports creating, updating,
    merging, replacing, and purging labels based on the specified state.
requirements:
  - python >= 2.6
  - google-auth >= 1.3.0
  - requests >= 2.18.4
options:
  name:
    description:
    - The name of the compute instance to manage labels for.
    required: true
    type: str
  labels:
    description:
    - A dictionary containing the labels to add or update on the instance.
      Ignored if state is absent.
    required: false
    default: {}
    type: dict
  state:
    description:
    - Desired state of the labels. Use present (default one) to add or update
       labels, absent to remove them.Also add state absent when purging.
    choices: ['present', 'absent']
    default: 'present'
    type: str
  purge_labels:
    description:
    - Whether to remove all labels from the instance. Only effective when
      state is 'absent'.
    required: false
    default: false
    type: bool
  mode:
    description:
    - Determines how labels are applied. merge will add or update labels
       while keeping existing ones, replace will remove all existing
       labels and add the new ones specified in labels.
    choices: ['merge', 'replace']
    default: 'merge'
    type: str
  project:
    description:
    - The GCP project ID where the compute instance is located.
    required: true
    type: str
  zone:
    description:
    - The zone where the compute instance is located.
    required: true
    type: str
author:
  - Fernando Mendieta Ovejero (@valkiriaaquatica)
notes:
- for authentication, you can set service_account_file using
  the C(GCP_SERVICE_ACCOUNT_FILE) env variable.
- for authentication, you can set service_account_contents using
  the C(GCP_SERVICE_ACCOUNT_CONTENTS) env variable.
- For authentication, you can set service_account_email using
  the C(GCP_SERVICE_ACCOUNT_EMAIL) env variable.
- For authentication, you can set access_token using
  the C(GCP_ACCESS_TOKEN) env variable.
- For authentication, you can set auth_kind using
  the C(GCP_AUTH_KIND) env variable.
- For authentication, you can set scopes using
  the C(GCP_SCOPES) env variable.
- Environment variables values will only be used if
  the playbook values are not set.
- The I(service_account_email) and I(service_account_file)
  options are mutually exclusive.
'''

EXAMPLES = '''
  - name: Add new labels to a compute instance
    gcp_compute_instance_label:
      name: name_of_the_instance
      labels:
        env: production
        department: marketing
      state: present
      project: your_project_name_or_id
      zone: "europe-southwest1-a"
  - name: Add new labels to a compute instance and remove the older labels
    gcp_compute_instance_label:
      name: name_of_the_instance
      labels:
        use: dev
        department: finance
      mode: "replace"
      project: "123456789"
      auth_kind: "serviceaccount"
      state: present
      project: your_project_name_or_id
      zone: "europe-southwest1-a"
  - name: Purge all labels from a compute instance
    gcp_compute_instance_label:
      name: name_of_the_instance
      purge_labels: true
      state: absent
      project: your_project_name_or_id
      zone: us-central1-a
'''

RETURN = '''
instance:
  description: Contains details about the compute engine instance
  after the operation.
  returned: on success
  type: complex
  contains:
    id:
      description: The unique ID of the operation.
      type: str
      sample: "12345678910"
    insertTime:
      description: The time when the instance operation was inserted.
      type: str
      sample: "2024-03-22T14:06:04.976-07:00"
    kind:
      description: The type of resource for the instance.
      type: str
      sample: "compute#operation"
    name:
      description: The name of the operation.
      type: str
      sample: "operation-1565615616-877585782-527852-7852"
    operationType:
      description: The type of operation performed on the instance.
      type: str
      sample: "compute.instance.setLabels"
    progress:
      description: The progress of the operation on the instance.
      type: int
      sample: 0
    selfLink:
      description: The link to the instance resource in the GCP API.
      type: str
      sample: "https://googleapis.com/compute/v1/../../zones/../operations/.."
    startTime:
      description: The start time of the operation on the instance.
      type: str
      sample: "2024-03-22T14:06:06.709-07:00"
    status:
      description: The current status of the compute instance.
      type: str
      sample: "RUNNING"
    targetId:
      description: The ID of the compute instance.
      type: str
      sample: "012345678910111213"
    targetLink:
      description: The link to the target resource of the operation on the
      instance in GCP.
      type: str
      sample: "https://googleapis.com/compute/v1/../../zones/../instances/.."
    user:
      description: The user who initiated the operation on the instance.
      type: str
      sample: "email@email.com"
    zone:
      description: The zone of the Compute Engine instance where the operation
      was performed.
      type: str
      sample: "https://googleapis.com/compute/v1/projects/../zones/.."
'''

from ansible_collections.google.cloud.plugins.module_utils.gcp_utils import (
    GcpModule,
    GcpSession,
    remove_nones_from_dict,
)

################################################################################
# Main
################################################################################


def main():
    argument_spec = dict(
        name=dict(required=True, type="str"),
        labels=dict(required=False, type="dict", default={}),
        state=dict(choices=["present", "absent"], default="present"),
        purge_labels=dict(required=False, type="bool", default=False),
        mode=dict(choices=["merge", "replace"], default="merge"),
        project=dict(required=True, type="str"),
        zone=dict(required=True, type="str"),
    )

    module = GcpModule(argument_spec=argument_spec, supports_check_mode=True)
    validate_module_params(module)

    session = GcpSession(module, "compute")
    instance_details = fetch_instance_details(session, module.params["name"], module)

    if module.params["state"] == "present":
        result = manage_labels(
            session,
            instance_details,
            module.params["labels"],
            module,
            is_purge=False,
            mode=module.params["mode"],
        )
    elif module.params["purge_labels"]:
        result = manage_labels(session, instance_details, {}, module, is_purge=True)
    else:  # state is absent
        result = manage_labels(
            session,
            instance_details,
            module.params["labels"],
            module,
            is_purge=False,
            remove=True,
        )

    module.exit_json(**result)


def validate_module_params(module):
    if (
        module.params["state"] == "present"
        and not module.params.get("purge_labels")
        and not module.params.get("labels")
    ):
        module.fail_json(
            msg="'labels' is required when 'state' is present and 'purge_labels' if False."
        )
    if not module.params["scopes"]:
        module.params["scopes"] = ["https://www.googleapis.com/auth/compute"]

# gets details of the instance, mainly the labels
def fetch_instance_details(session, instance_name, module):
    url = (
        f"https://compute.googleapis.com/compute/v1/projects/"
        f"{module.params['project']}/zones/{module.params['zone']}/"
        f"instances/{instance_name}"
    )
    response = session.get(url)
    return (
        response.json()
        if response.ok
        else module.fail_json(
            msg=f"No se encontró la instancia con nombre {instance_name}"
        )
    )


def manage_labels(
    session,
    instance_details,
    labels,
    module,
    is_purge=False,
    remove=False,
    mode="merge",
):
    current_labels = instance_details.get("labels", {})
    updated_labels = {}
    msg = ""

    # handles the mode logic when replace or purgeed
    if mode == "replace" and not is_purge:
        updated_labels = labels
        msg = "Labels have been replaced."
    elif is_purge:
        if current_labels:
            updated_labels = {}
            msg = "All labels have been purged."
        else:
            return {"changed": False, "msg": "There were no labels to purge."}
    elif remove:
        updated_labels = {k: v for k, v in current_labels.items() if k not in labels}
        if current_labels == updated_labels:
            return {"changed": False, "msg": "The labels to be removed do not exist."}
        else:
            msg = "Specified labels have been removed."
    else:  # default to merge with the rest of labels
        updated_labels = {**current_labels, **labels} if mode == "merge" else labels
        if current_labels == updated_labels:
            return {"changed": False, "msg": "The labels to be added already exist."}
        else:
            msg = "Specified labels have been added."

    body = {
        "labels": remove_nones_from_dict(updated_labels),
        "labelFingerprint": instance_details["labelFingerprint"],
    }
    url = (
        f"https://compute.googleapis.com/compute/v1/projects/"
        f"{module.params['project']}/zones/{module.params['zone']}/"
        f"instances/{instance_details['name']}/setLabels"
    )
    response = session.post(url, body=body)
    return handle_response(
        response, module, updated_labels=updated_labels, is_purge=is_purge
    )

# handles purge, add or delete actions 
def handle_response(response, module, updated_labels=None, is_purge=False):
    if response.ok:
        changed = (
            True
            if (is_purge and updated_labels == {})
            else not response.json().get("labels") == updated_labels
        )
        return {"changed": changed, "instance": response.json()}
    else:
        module.fail_json(msg=f"Failed to modify labels: {response.text}")


if __name__ == "__main__":
    main()
