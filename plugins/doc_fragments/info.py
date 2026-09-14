# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Google Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


class ModuleDocFragment(object):
    # GCP info doc fragment.
    DOCUMENTATION = r"""
    options:
        filters:
            description:
              - A list of filter expression strings used to filter the resources returned by the API.
              - Each string is a filter expression (e.g. C(some_field = "SOME_VALUE")).
              - Multiple expressions are combined with a logical AND.
              - Refer to the filter topic documentation U(https://cloud.google.com/sdk/gcloud/reference/topic/filters).
              - Refer to the AIP-160 filter syntax documentation U(https://google.aip.dev/160).
            type: list
            elements: str
    """
