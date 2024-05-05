#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2017 Google
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
# ----------------------------------------------------------------------------
#
#     ***     AUTO GENERATED CODE    ***    Type: MMv1     ***
#
# ----------------------------------------------------------------------------
#
#     This file is automatically generated by Magic Modules and manual
#     changes will be clobbered when the file is regenerated.
#
#     Please read more about how to change this file at
#     https://www.github.com/GoogleCloudPlatform/magic-modules
#
# ----------------------------------------------------------------------------

from __future__ import absolute_import, division, print_function

__metaclass__ = type

################################################################################
# Documentation
################################################################################

ANSIBLE_METADATA = {'metadata_version': '1.1', 'status': ["preview"], 'supported_by': 'community'}

DOCUMENTATION = '''
---
module: gcp_bigquery_table_info
description:
- Gather info for GCP Table
short_description: Gather info for GCP Table
author: Google Inc. (@googlecloudplatform)
requirements:
- python >= 2.6
- requests >= 2.18.4
- google-auth >= 1.3.0
options:
  dataset:
    description:
    - Name of the dataset.
    required: false
    type: str
  project:
    description:
    - The Google Cloud Platform project to use.
    type: str
  auth_kind:
    description:
    - The type of credential used.
    type: str
    required: true
    choices:
    - application
    - machineaccount
    - serviceaccount
    - accesstoken
  service_account_contents:
    description:
    - The contents of a Service Account JSON file, either in a dictionary or as a
      JSON string that represents it.
    type: jsonarg
  service_account_file:
    description:
    - The path of a Service Account JSON file if serviceaccount is selected as type.
    type: path
  service_account_email:
    description:
    - An optional service account email address if machineaccount is selected and
      the user does not wish to use the default email.
    - Required service account to impersonate if impersonation is selected.
    type: str
  access_token:
    description:
    - An OAuth2 access token if credential type is accesstoken.
    type: str
  scopes:
    description:
    - Array of scopes to be used
    type: list
    elements: str
  env_type:
    description:
    - Specifies which Ansible environment you're running this module within.
    - This should not be set unless you know what you're doing.
    - This only alters the User Agent string for any API requests.
    type: str
notes:
- for authentication, you can set service_account_file using the C(GCP_SERVICE_ACCOUNT_FILE)
  env variable.
- for authentication, you can set service_account_contents using the C(GCP_SERVICE_ACCOUNT_CONTENTS)
  env variable.
- For authentication, you can set service_account_email using the C(GCP_SERVICE_ACCOUNT_EMAIL)
  env variable.
- For authentication, you can set access_token using the C(GCP_ACCESS_TOKEN)
  env variable.
- For authentication, you can set auth_kind using the C(GCP_AUTH_KIND) env variable.
- For authentication, you can set scopes using the C(GCP_SCOPES) env variable.
- Environment variables values will only be used if the playbook values are not set.
- The I(service_account_email) and I(service_account_file) options are mutually exclusive.
'''

EXAMPLES = '''
- name: get info on a table
  gcp_bigquery_table_info:
    dataset: example_dataset
    project: test_project
    auth_kind: serviceaccount
    service_account_file: "/tmp/auth.pem"
'''

RETURN = '''
resources:
  description: List of resources
  returned: always
  type: complex
  contains:
    tableReference:
      description:
      - Reference describing the ID of this table.
      returned: success
      type: complex
      contains:
        datasetId:
          description:
          - The ID of the dataset containing this table.
          returned: success
          type: str
        projectId:
          description:
          - The ID of the project containing this table.
          returned: success
          type: str
        tableId:
          description:
          - The ID of the the table.
          returned: success
          type: str
    clustering:
      description:
      - One or more fields on which data should be clustered. Only top-level, non-repeated,
        simple-type fields are supported. When you cluster a table using multiple
        columns, the order of columns you specify is important. The order of the specified
        columns determines the sort order of the data.
      returned: success
      type: list
    creationTime:
      description:
      - The time when this dataset was created, in milliseconds since the epoch.
      returned: success
      type: int
    description:
      description:
      - A user-friendly description of the dataset.
      returned: success
      type: str
    friendlyName:
      description:
      - A descriptive name for this table.
      returned: success
      type: str
    id:
      description:
      - An opaque ID uniquely identifying the table.
      returned: success
      type: str
    labels:
      description:
      - The labels associated with this dataset. You can use these to organize and
        group your datasets .
      returned: success
      type: dict
    lastModifiedTime:
      description:
      - The time when this table was last modified, in milliseconds since the epoch.
      returned: success
      type: int
    location:
      description:
      - The geographic location where the table resides. This value is inherited from
        the dataset.
      returned: success
      type: str
    name:
      description:
      - Name of the table.
      returned: success
      type: str
    numBytes:
      description:
      - The size of this table in bytes, excluding any data in the streaming buffer.
      returned: success
      type: int
    numLongTermBytes:
      description:
      - The number of bytes in the table that are considered "long-term storage".
      returned: success
      type: int
    numRows:
      description:
      - The number of rows of data in this table, excluding any data in the streaming
        buffer.
      returned: success
      type: int
    requirePartitionFilter:
      description:
      - If set to true, queries over this table require a partition filter that can
        be used for partition elimination to be specified.
      returned: success
      type: bool
    type:
      description:
      - Describes the table type.
      returned: success
      type: str
    view:
      description:
      - The view definition.
      returned: success
      type: complex
      contains:
        useLegacySql:
          description:
          - Specifies whether to use BigQuery's legacy SQL for this view .
          returned: success
          type: bool
        userDefinedFunctionResources:
          description:
          - Describes user-defined function resources used in the query.
          returned: success
          type: complex
          contains:
            inlineCode:
              description:
              - An inline resource that contains code for a user-defined function
                (UDF). Providing a inline code resource is equivalent to providing
                a URI for a file containing the same code.
              returned: success
              type: str
            resourceUri:
              description:
              - A code resource to load from a Google Cloud Storage URI (gs://bucket/path).
              returned: success
              type: str
    timePartitioning:
      description:
      - If specified, configures time-based partitioning for this table.
      returned: success
      type: complex
      contains:
        expirationMs:
          description:
          - Number of milliseconds for which to keep the storage for a partition.
          returned: success
          type: int
        field:
          description:
          - If not set, the table is partitioned by pseudo column, referenced via
            either '_PARTITIONTIME' as TIMESTAMP type, or '_PARTITIONDATE' as DATE
            type. If field is specified, the table is instead partitioned by this
            field. The field must be a top-level TIMESTAMP or DATE field. Its mode
            must be NULLABLE or REQUIRED.
          returned: success
          type: str
        type:
          description:
          - The only type supported is DAY, which will generate one partition per
            day.
          returned: success
          type: str
    streamingBuffer:
      description:
      - Contains information regarding this table's streaming buffer, if one is present.
        This field will be absent if the table is not being streamed to or if there
        is no data in the streaming buffer.
      returned: success
      type: complex
      contains:
        estimatedBytes:
          description:
          - A lower-bound estimate of the number of bytes currently in the streaming
            buffer.
          returned: success
          type: int
        estimatedRows:
          description:
          - A lower-bound estimate of the number of rows currently in the streaming
            buffer.
          returned: success
          type: int
        oldestEntryTime:
          description:
          - Contains the timestamp of the oldest entry in the streaming buffer, in
            milliseconds since the epoch, if the streaming buffer is available.
          returned: success
          type: int
    schema:
      description:
      - Describes the schema of this table.
      returned: success
      type: complex
      contains:
        fields:
          description:
          - Describes the fields in a table.
          returned: success
          type: complex
          contains:
            description:
              description:
              - The field description. The maximum length is 1,024 characters.
              returned: success
              type: str
            fields:
              description:
              - Describes the nested schema fields if the type property is set to
                RECORD.
              returned: success
              type: list
            mode:
              description:
              - The field mode.
              returned: success
              type: str
            name:
              description:
              - The field name.
              returned: success
              type: str
            type:
              description:
              - The field data type.
              returned: success
              type: str
    encryptionConfiguration:
      description:
      - Custom encryption configuration.
      returned: success
      type: complex
      contains:
        kmsKeyName:
          description:
          - Describes the Cloud KMS encryption key that will be used to protect destination
            BigQuery table. The BigQuery Service Account associated with your project
            requires access to this encryption key.
          returned: success
          type: str
    expirationTime:
      description:
      - The time when this table expires, in milliseconds since the epoch. If not
        present, the table will persist indefinitely.
      returned: success
      type: int
    externalDataConfiguration:
      description:
      - Describes the data format, location, and other properties of a table stored
        outside of BigQuery. By defining these properties, the data source can then
        be queried as if it were a standard BigQuery table.
      returned: success
      type: complex
      contains:
        autodetect:
          description:
          - Try to detect schema and format options automatically. Any option specified
            explicitly will be honored.
          returned: success
          type: bool
        compression:
          description:
          - The compression type of the data source.
          returned: success
          type: str
        ignoreUnknownValues:
          description:
          - Indicates if BigQuery should allow extra values that are not represented
            in the table schema .
          returned: success
          type: bool
        maxBadRecords:
          description:
          - The maximum number of bad records that BigQuery can ignore when reading
            data .
          returned: success
          type: int
        sourceFormat:
          description:
          - The data format.
          returned: success
          type: str
        sourceUris:
          description:
          - The fully-qualified URIs that point to your data in Google Cloud.
          - 'For Google Cloud Storage URIs: Each URI can contain one ''*'' wildcard
            character and it must come after the ''bucket'' name. Size limits related
            to load jobs apply to external data sources. For Google Cloud Bigtable
            URIs: Exactly one URI can be specified and it has be a fully specified
            and valid HTTPS URL for a Google Cloud Bigtable table. For Google Cloud
            Datastore backups, exactly one URI can be specified. Also, the ''*'' wildcard
            character is not allowed.'
          returned: success
          type: list
        schema:
          description:
          - The schema for the data. Schema is required for CSV and JSON formats.
          returned: success
          type: complex
          contains:
            fields:
              description:
              - Describes the fields in a table.
              returned: success
              type: complex
              contains:
                description:
                  description:
                  - The field description.
                  returned: success
                  type: str
                fields:
                  description:
                  - Describes the nested schema fields if the type property is set
                    to RECORD .
                  returned: success
                  type: list
                mode:
                  description:
                  - Field mode.
                  returned: success
                  type: str
                name:
                  description:
                  - Field name.
                  returned: success
                  type: str
                type:
                  description:
                  - Field data type.
                  returned: success
                  type: str
        googleSheetsOptions:
          description:
          - Additional options if sourceFormat is set to GOOGLE_SHEETS.
          returned: success
          type: complex
          contains:
            skipLeadingRows:
              description:
              - The number of rows at the top of a Google Sheet that BigQuery will
                skip when reading the data.
              returned: success
              type: int
        csvOptions:
          description:
          - Additional properties to set if sourceFormat is set to CSV.
          returned: success
          type: complex
          contains:
            allowJaggedRows:
              description:
              - Indicates if BigQuery should accept rows that are missing trailing
                optional columns .
              returned: success
              type: bool
            allowQuotedNewlines:
              description:
              - Indicates if BigQuery should allow quoted data sections that contain
                newline characters in a CSV file .
              returned: success
              type: bool
            encoding:
              description:
              - The character encoding of the data.
              returned: success
              type: str
            fieldDelimiter:
              description:
              - The separator for fields in a CSV file.
              returned: success
              type: str
            quote:
              description:
              - The value that is used to quote data sections in a CSV file.
              returned: success
              type: str
            skipLeadingRows:
              description:
              - The number of rows at the top of a CSV file that BigQuery will skip
                when reading the data.
              returned: success
              type: int
        bigtableOptions:
          description:
          - Additional options if sourceFormat is set to BIGTABLE.
          returned: success
          type: complex
          contains:
            ignoreUnspecifiedColumnFamilies:
              description:
              - If field is true, then the column families that are not specified
                in columnFamilies list are not exposed in the table schema .
              returned: success
              type: bool
            readRowkeyAsString:
              description:
              - If field is true, then the rowkey column families will be read and
                converted to string.
              returned: success
              type: bool
            columnFamilies:
              description:
              - List of column families to expose in the table schema along with their
                types.
              returned: success
              type: complex
              contains:
                columns:
                  description:
                  - Lists of columns that should be exposed as individual fields as
                    opposed to a list of (column name, value) pairs.
                  returned: success
                  type: complex
                  contains:
                    encoding:
                      description:
                      - The encoding of the values when the type is not STRING.
                      returned: success
                      type: str
                    fieldName:
                      description:
                      - If the qualifier is not a valid BigQuery field identifier,
                        a valid identifier must be provided as the column field name
                        and is used as field name in queries.
                      returned: success
                      type: str
                    onlyReadLatest:
                      description:
                      - If this is set, only the latest version of value in this column
                        are exposed .
                      returned: success
                      type: bool
                    qualifierString:
                      description:
                      - Qualifier of the column.
                      returned: success
                      type: str
                    type:
                      description:
                      - The type to convert the value in cells of this column.
                      returned: success
                      type: str
                encoding:
                  description:
                  - The encoding of the values when the type is not STRING.
                  returned: success
                  type: str
                familyId:
                  description:
                  - Identifier of the column family.
                  returned: success
                  type: str
                onlyReadLatest:
                  description:
                  - If this is set only the latest version of value are exposed for
                    all columns in this column family .
                  returned: success
                  type: bool
                type:
                  description:
                  - The type to convert the value in cells of this column family.
                  returned: success
                  type: str
    dataset:
      description:
      - Name of the dataset.
      returned: success
      type: str
'''

################################################################################
# Imports
################################################################################
from ansible_collections.google.cloud.plugins.module_utils.gcp_utils import navigate_hash, GcpSession, GcpModule
import json

################################################################################
# Main
################################################################################


def main():
    module = GcpModule(argument_spec=dict(dataset=dict(type='str')))

    if not module.params['scopes']:
        module.params['scopes'] = ['https://www.googleapis.com/auth/bigquery']

    return_value = {'resources': fetch_list(module, collection(module))}
    module.exit_json(**return_value)


def collection(module):
    return "https://bigquery.googleapis.com/bigquery/v2/projects/{project}/datasets/{dataset}/tables".format(**module.params)


def fetch_list(module, link):
    auth = GcpSession(module, 'bigquery')
    return auth.list(link, return_if_object, array_name='tables')


def return_if_object(module, response):
    # If not found, return nothing.
    if response.status_code == 404:
        return None

    # If no content, return nothing.
    if response.status_code == 204:
        return None

    try:
        module.raise_for_status(response)
        result = response.json()
    except getattr(json.decoder, 'JSONDecodeError', ValueError) as inst:
        module.fail_json(msg="Invalid JSON response with error: %s" % inst)

    if navigate_hash(result, ['error', 'errors']):
        module.fail_json(msg=navigate_hash(result, ['error', 'errors']))

    return result


if __name__ == "__main__":
    main()
