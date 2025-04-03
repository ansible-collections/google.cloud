# Copyright (c) 2017 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
    name: gcp_compute
    short_description: Google Cloud Compute Engine inventory source
    requirements:
        - requests >= 2.18.4
        - google-auth >= 1.3.0
    extends_documentation_fragment:
        - constructed
        - inventory_cache
    description:
        - Get inventory hosts from Google Cloud Platform GCE.
        - Uses a YAML configuration file that ends with gcp_compute.(yml|yaml) or gcp.(yml|yaml).
    options:
        plugin:
            description: token that ensures this is a source file for the 'gcp_compute' plugin.
            required: True
            choices: ['google.cloud.gcp_compute', 'gcp_compute']
        zones:
          description: A list of regions in which to describe GCE instances.
                       If none provided, it defaults to all zones available to a given project.
          type: list
          elements: string
        folders:
          description: A folder that contains many projects
          type: list
          required: False
          elements: string
        projects:
          description: A list of projects in which to describe GCE instances.
          type: list
          required: False
          elements: string
        filters:
          description: >
            A list of filter value pairs. Available filters are listed here
            U(https://cloud.google.com/compute/docs/reference/rest/v1/instances/aggregatedList).
            Each additional filter in the list will be added as an AND condition
            (filter1 and filter2)
          type: list
          elements: string
        hostnames:
          description: A list of options that describe the ordering for which
              hostnames should be assigned. Currently supported hostnames are
              'public_ip', 'private_ip', 'name' or 'labels.vm_name'.
          default: ['public_ip', 'private_ip', 'name']
          type: list
          elements: string
        name_suffix:
          description: Custom domain suffix. If set, this string will be appended to all hosts.
          default: ""
          type: string
          required: False
        auth_kind:
            description:
                - The type of credential used.
            required: True
            choices: ['application', 'serviceaccount', 'machineaccount', 'accesstoken']
            env:
                - name: GCP_AUTH_KIND
        scopes:
            description: list of authentication scopes
            type: list
            elements: string
            default: ['https://www.googleapis.com/auth/compute']
            env:
                - name: GCP_SCOPES
        service_account_file:
            description:
                - The path of a Service Account JSON file if serviceaccount is selected as type.
            type: path
            env:
                - name: GCP_SERVICE_ACCOUNT_FILE
                - name: GCE_CREDENTIALS_FILE_PATH
        service_account_contents:
            description:
                - A string representing the contents of a Service Account JSON file. This should not be passed in as a dictionary,
                  but a string that has the exact contents of a service account json file (valid JSON).
            type: string
            env:
                - name: GCP_SERVICE_ACCOUNT_CONTENTS
        service_account_email:
            description:
                - An optional service account email address if machineaccount is selected
                  and the user does not wish to use the default email.
            env:
                - name: GCP_SERVICE_ACCOUNT_EMAIL
        access_token:
            description:
                - An OAuth2 access token if credential type is accesstoken.
            env:
                - name: GCP_ACCESS_TOKEN
        vars_prefix:
            description: prefix to apply to host variables, does not include facts nor params
            default: ''
        use_contrib_script_compatible_sanitization:
          description:
            - By default this plugin is using a general group name sanitization to create safe and usable group names for use in Ansible.
              This option allows you to override that, in efforts to allow migration from the old inventory script.
            - For this to work you should also turn off the TRANSFORM_INVALID_GROUP_CHARS setting,
              otherwise the core engine will just use the standard sanitization on top.
            - This is not the default as such names break certain functionality as not all characters are valid Python identifiers
              which group names end up being used as.
          type: bool
          default: False
        retrieve_image_info:
          description:
            - Populate the C(image) host fact for the instances returned with the GCP image name
            - By default this plugin does not attempt to resolve the boot image of an instance to the image name cataloged in GCP
              because of the performance overhead of the task.
            - Unless this option is enabled, the C(image) host variable will be C(null)
          type: bool
          default: False
"""

EXAMPLES = """
plugin: google.cloud.gcp_compute
zones: # populate inventory with instances in these regions
  - us-east1-a
projects:
  - gcp-prod-gke-100
  - gcp-cicd-101
filters:
  - status = RUNNING
  - scheduling.automaticRestart = true AND status = RUNNING
service_account_file: /tmp/service_account.json
auth_kind: serviceaccount
scopes:
 - 'https://www.googleapis.com/auth/cloud-platform'
 - 'https://www.googleapis.com/auth/compute.readonly'
keyed_groups:
  # Create groups from GCE labels
  - prefix: gcp
    key: labels
name_suffix: .example.com
hostnames:
  # List host by name instead of the default public ip
  - name
compose:
  # Set an inventory parameter to use the Public IP address to connect to the host
  # For Private ip use "networkInterfaces[0].networkIP"
  ansible_host: networkInterfaces[0].accessConfigs[0].natIP
"""

import json

from ansible.errors import AnsibleError, AnsibleParserError
from ansible.module_utils._text import to_text
from ansible.module_utils.basic import missing_required_lib
from ..module_utils.gcp_utils import (
    GcpSession,
    navigate_hash,
    GcpRequestException,
    HAS_GOOGLE_LIBRARIES,
)
from ansible.plugins.inventory import BaseInventoryPlugin, Constructable, Cacheable


# Mocking a module to reuse module_utils
class GcpMockModule(object):
    def __init__(self, params):
        self.params = params

    def fail_json(self, *args, **kwargs):
        raise AnsibleError(kwargs["msg"])


class GcpInstance(object):
    def __init__(
        self, json, hostname_ordering, project_disks, should_format=True, name_suffix=""
    ):
        self.hostname_ordering = hostname_ordering
        self.project_disks = project_disks
        self.name_suffix = name_suffix
        self.json = json
        if should_format:
            self.convert()

    def to_json(self):
        return self.json

    def convert(self):
        if "zone" in self.json:
            self.json["zone_selflink"] = self.json["zone"]
            self.json["zone"] = self.json["zone"].split("/")[-1]
        if "machineType" in self.json:
            self.json["machineType_selflink"] = self.json["machineType"]
            self.json["machineType"] = self.json["machineType"].split("/")[-1]

        if "networkInterfaces" in self.json:
            for network in self.json["networkInterfaces"]:
                if "network" in network:
                    network["network"] = self._format_network_info(network["network"])
                if "subnetwork" in network:
                    network["subnetwork"] = self._format_network_info(
                        network["subnetwork"]
                    )

        if "metadata" in self.json:
            # If no metadata, 'items' will be blank.
            # We want the metadata hash overriden anyways for consistency.
            self.json["metadata"] = self._format_metadata(
                self.json["metadata"].get("items", {})
            )

        self.json["project"] = self.json["selfLink"].split("/")[6]
        self.json["image"] = self._get_image()

    def _format_network_info(self, address):
        """
        :param address: A GCP network address
        :return a dict with network shortname and region
        """
        split = address.split("/")
        region = ""
        if "global" in split:
            region = "global"
        else:
            region = split[8]
        return {"region": region, "name": split[-1], "selfLink": address}

    def _format_metadata(self, metadata):
        """
        :param metadata: A list of dicts where each dict has keys "key" and "value"
        :return a dict with key/value pairs for each in list.
        """
        new_metadata = {}
        for pair in metadata:
            new_metadata[pair["key"]] = pair["value"]
        return new_metadata

    def hostname(self):
        """
        :return the hostname of this instance
        """
        for order in self.hostname_ordering:
            name = None
            if order.startswith("labels."):
                if "labels" in self.json:
                    name = self.json["labels"].get(order[7:])
            elif order == "public_ip":
                name = self._get_publicip()
            elif order == "private_ip":
                name = self._get_privateip()
            elif order == "name":
                name = self.json["name"] + self.name_suffix
            else:
                raise AnsibleParserError("%s is not a valid hostname precedent" % order)

            if name:
                return name

        raise AnsibleParserError("No valid name found for host")

    def _get_publicip(self):
        """
        :return the publicIP of this instance or None
        """
        # Get public IP if exists
        for interface in self.json["networkInterfaces"]:
            if "accessConfigs" in interface:
                for accessConfig in interface["accessConfigs"]:
                    if "natIP" in accessConfig:
                        return accessConfig["natIP"]
        return None

    def _get_image(self):
        """
        :param instance: A instance response from GCP
        :return the image of this instance or None
        """
        image = None
        if self.project_disks and "disks" in self.json:
            for disk in self.json["disks"]:
                if disk.get("boot"):
                    image = self.project_disks[disk["source"]]
        return image

    def _get_privateip(self):
        """
        :param item: A host response from GCP
        :return the privateIP of this instance or None
        """
        # Fallback: Get private IP
        for interface in self.json["networkInterfaces"]:
            if "networkIP" in interface:
                return interface["networkIP"]


class InventoryModule(BaseInventoryPlugin, Constructable, Cacheable):

    NAME = "google.cloud.gcp_compute"

    _instances = (
        r"https://www.googleapis.com/compute/v1/projects/%s/aggregated/instances"
    )

    def __init__(self):
        super(InventoryModule, self).__init__()

        self.group_prefix = "gcp_"

    def _populate_host(self, item):
        """
        :param item: A GCP instance
        """
        hostname = item.hostname()
        self.inventory.add_host(hostname)
        for key in item.to_json():
            try:
                self.inventory.set_variable(
                    hostname, self.get_option("vars_prefix") + key, item.to_json()[key]
                )
            except (ValueError, TypeError) as e:
                self.display.warning(
                    "Could not set host info hostvar for %s, skipping %s: %s"
                    % (hostname, key, to_text(e))
                )
        self.inventory.add_child("all", hostname)

    def verify_file(self, path):
        """
        :param path: the path to the inventory config file
        :return the contents of the config file
        """
        if super(InventoryModule, self).verify_file(path):
            if path.endswith(("gcp.yml", "gcp.yaml")):
                return True
            elif path.endswith(("gcp_compute.yml", "gcp_compute.yaml")):
                return True
        return False

    def fetch_list(self, params, link, query):
        """
        :param params: a dict containing all of the fields relevant to build URL
        :param link: a formatted URL
        :param query: a formatted query string
        :return the JSON response containing a list of instances.
        """
        lists = []
        resp = self._return_if_object(
            self.fake_module, self.auth_session.get(link, params={"filter": query})
        )
        if resp:
            lists.append(resp.get("items"))
            while resp.get("nextPageToken"):
                resp = self._return_if_object(
                    self.fake_module,
                    self.auth_session.get(
                        link,
                        params={
                            "filter": query,
                            "pageToken": resp.get("nextPageToken"),
                        },
                    ),
                )
                lists.append(resp.get("items"))
        return self.build_list(lists)

    def build_list(self, lists):
        arrays_for_zones = {}
        for resp in lists:
            for zone in resp:
                if "instances" in resp[zone]:
                    if zone in arrays_for_zones:
                        arrays_for_zones[zone] = (
                            arrays_for_zones[zone] + resp[zone]["instances"]
                        )
                    else:
                        arrays_for_zones[zone] = resp[zone]["instances"]
        return arrays_for_zones

    def _get_query_options(self, filters):
        """
        :param config_data: contents of the inventory config file
        :return A fully built query string
        """
        if not filters:
            return ""

        if len(filters) == 1:
            return filters[0]
        else:
            queries = []
            for f in filters:
                # For multiple queries, all queries should have ()
                if f[0] != "(" and f[-1] != ")":
                    queries.append("(%s)" % "".join(f))
                else:
                    queries.append(f)

            return " ".join(queries)

    def _return_if_object(self, module, response):
        """
        :param module: A GcpModule
        :param response: A Requests response object
        :return JSON response
        """
        # If not found, return nothing.
        if response.status_code == 404:
            return None

        # If no content, return nothing.
        if response.status_code == 204:
            return None

        try:
            response.raise_for_status
            result = response.json()
        except getattr(json.decoder, "JSONDecodeError", ValueError) as inst:
            module.fail_json(msg="Invalid JSON response with error: %s" % inst)
        except GcpRequestException as inst:
            module.fail_json(msg="Network error: %s" % inst)

        if navigate_hash(result, ["error", "errors"]):
            module.fail_json(msg=navigate_hash(result, ["error", "errors"]))

        return result

    def _add_hosts(self, items, config_data, format_items=True, project_disks=None):
        """
        :param items: A list of hosts
        :param config_data: configuration data
        :param format_items: format items or not
        """
        if not items:
            return

        hostname_ordering = ["public_ip", "private_ip", "name"]
        if self.get_option("hostnames"):
            hostname_ordering = self.get_option("hostnames")

        name_suffix = self.get_option("name_suffix")

        for host_json in items:
            host = GcpInstance(
                host_json, hostname_ordering, project_disks, format_items, name_suffix
            )
            self._populate_host(host)

            hostname = host.hostname()
            self._set_composite_vars(
                self.get_option("compose"), host.to_json(), hostname
            )
            self._add_host_to_composed_groups(
                self.get_option("groups"), host.to_json(), hostname
            )
            self._add_host_to_keyed_groups(
                self.get_option("keyed_groups"), host.to_json(), hostname
            )

    def _get_project_disks(self, config_data, query):
        """
        project space disk images
        """

        try:
            self._project_disks
        except AttributeError:
            self._project_disks = {}
            request_params = {"maxResults": 500, "filter": query}

            for project in config_data["projects"]:
                session_responses = []
                page_token = True
                while page_token:
                    response = self.auth_session.get(
                        "https://www.googleapis.com/compute/v1/projects/{0}/aggregated/disks".format(
                            project
                        ),
                        params=request_params,
                    )
                    response_json = response.json()
                    if "nextPageToken" in response_json:
                        request_params["pageToken"] = response_json["nextPageToken"]
                    elif "pageToken" in request_params:
                        del request_params["pageToken"]

                    if "items" in response_json:
                        session_responses.append(response_json)
                    page_token = "pageToken" in request_params

                for response in session_responses:
                    if "items" in response:
                        # example k would be a zone or region name
                        # example v would be { "disks" : [], "otherkey" : "..." }
                        for zone_or_region, aggregate in response["items"].items():
                            if "zones" in zone_or_region:
                                if "disks" in aggregate:
                                    zone = zone_or_region.replace("zones/", "")
                                    for disk in aggregate["disks"]:
                                        if (
                                            "zones" in config_data
                                            and zone in config_data["zones"]
                                        ):
                                            # If zones specified, only store those zones' data
                                            if "sourceImage" in disk:
                                                self._project_disks[
                                                    disk["selfLink"]
                                                ] = disk["sourceImage"].split("/")[-1]
                                            else:
                                                self._project_disks[
                                                    disk["selfLink"]
                                                ] = disk["selfLink"].split("/")[-1]

                                        else:
                                            if "sourceImage" in disk:
                                                self._project_disks[
                                                    disk["selfLink"]
                                                ] = disk["sourceImage"].split("/")[-1]
                                            else:
                                                self._project_disks[
                                                    disk["selfLink"]
                                                ] = disk["selfLink"].split("/")[-1]

        return self._project_disks

    def fetch_projects(self, params, link, query):
        module = GcpMockModule(params)
        auth = GcpSession(module, "cloudresourcemanager")
        response = auth.get(link, params={"filter": query})
        return self._return_if_object(module, response)

    def projects_for_folder(self, config_data, folder):
        link = "https://cloudresourcemanager.googleapis.com/v1/projects"
        query = "parent.id = {0}".format(folder)
        projects = []
        config_data["scopes"] = ["https://www.googleapis.com/auth/cloud-platform"]
        projects_response = self.fetch_projects(config_data, link, query)

        if "projects" in projects_response:
            for item in projects_response.get("projects"):
                projects.append(item["projectId"])
        return projects

    def parse(self, inventory, loader, path, cache=True):

        if not HAS_GOOGLE_LIBRARIES:
            raise AnsibleParserError(
                "gce inventory plugin cannot start: %s"
                % missing_required_lib("google-auth")
            )

        super(InventoryModule, self).parse(inventory, loader, path)

        config_data = {}
        config_data = self._read_config_data(path)

        if self.get_option("use_contrib_script_compatible_sanitization"):
            self._sanitize_group_name = (
                self._legacy_script_compatible_group_sanitization
            )

        # setup parameters as expected by 'fake module class' to reuse module_utils w/o changing the API
        params = {
            "filters": self.get_option("filters"),
            "projects": self.get_option("projects"),
            "folders": self.get_option("folders"),
            "scopes": self.get_option("scopes"),
            "zones": self.get_option("zones"),
            "auth_kind": self.get_option("auth_kind"),
            "service_account_file": self.get_option("service_account_file"),
            "service_account_contents": self.get_option("service_account_contents"),
            "service_account_email": self.get_option("service_account_email"),
            "access_token": self.get_option("access_token"),
        }

        self.fake_module = GcpMockModule(params)
        self.auth_session = GcpSession(self.fake_module, "compute")

        query = self._get_query_options(params["filters"])

        if self.get_option("retrieve_image_info"):
            project_disks = self._get_project_disks(config_data, query)
        else:
            project_disks = None

        # Cache logic
        if cache:
            cache = self.get_option("cache")
            cache_key = self.get_cache_key(path)
        else:
            cache_key = None

        cache_needs_update = False
        if cache:
            try:
                results = self._cache[cache_key]
                for project in results:
                    for zone in results[project]:
                        self._add_hosts(
                            results[project][zone],
                            config_data,
                            False,
                            project_disks=project_disks,
                        )
            except KeyError:
                cache_needs_update = True

        projects = []
        if params["projects"]:
            projects = projects + params["projects"]

        if params["folders"]:
            for folder in params["folders"]:
                projects = projects + self.projects_for_folder(config_data, folder)

        if not cache or cache_needs_update:
            cached_data = {}
            for project in projects:
                cached_data[project] = {}
                params["project"] = project
                zones = params["zones"]
                # Fetch all instances
                link = self._instances % project
                resp = self.fetch_list(params, link, query)
                for key, value in resp.items():
                    zone = key[6:]
                    if not zones or zone in zones:
                        self._add_hosts(value, config_data, project_disks=project_disks)
                        cached_data[project][zone] = value

        if cache_needs_update:
            self._cache[cache_key] = cached_data

    @staticmethod
    def _legacy_script_compatible_group_sanitization(name):

        return name
