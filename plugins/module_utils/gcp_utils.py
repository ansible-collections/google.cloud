# Copyright (c), Google Inc, 2017
# Simplified BSD License (see licenses/simplified_bsd.txt or https://opensource.org/licenses/BSD-2-Clause)

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import google.auth
    import google.auth.compute_engine
    from google.oauth2 import service_account
    from google.auth.transport.requests import AuthorizedSession
    HAS_GOOGLE_LIBRARIES = True
except ImportError:
    HAS_GOOGLE_LIBRARIES = False

from ansible.module_utils.basic import AnsibleModule, env_fallback
from ansible.module_utils.six import string_types
from ansible.module_utils._text import to_text
import ast
import os
import json


def navigate_hash(source, path, default=None):
    if not source:
        return None

    key = path[0]
    path = path[1:]
    if key not in source:
        return default
    result = source[key]
    if path:
        return navigate_hash(result, path, default)
    else:
        return result


class GcpRequestException(Exception):
    pass


def remove_nones_from_dict(obj):
    new_obj = {}
    for key in obj:
        value = obj[key]
        if value is not None and value != {} and value != []:
            new_obj[key] = value
    return new_obj


# Handles the replacement of dicts with values -> the needed value for GCP API
def replace_resource_dict(item, value):
    if isinstance(item, list):
        items = []
        for i in item:
            items.append(replace_resource_dict(i, value))
        return items
    else:
        if not item:
            return item
        if isinstance(item, dict):
            return item.get(value)

        # Item could be a string or a string representing a dictionary.
        try:
            new_item = ast.literal_eval(item)
            return replace_resource_dict(new_item, value)
        except ValueError:
            return item


# Handles all authentication and HTTP sessions for GCP API calls.
class GcpSession(object):
    def __init__(self, module, product):
        self.module = module
        self.product = product
        self._validate()

    def get(self, url, body=None, **kwargs):
        kwargs.update({'json': body, 'headers': self._headers()})
        try:
            return self.session().get(url, **kwargs)
        except getattr(requests.exceptions, 'RequestException') as inst:
            self.module.fail_json(msg=inst.message)

    def post(self, url, body=None, headers=None, **kwargs):
        if headers:
            headers = self.merge_dictionaries(headers, self._headers())
        else:
            headers = self._headers()

        try:
            return self.session().post(url, json=body, headers=headers)
        except getattr(requests.exceptions, 'RequestException') as inst:
            self.module.fail_json(msg=inst.message)

    def post_contents(self, url, file_contents=None, headers=None, **kwargs):
        if headers:
            headers = self.merge_dictionaries(headers, self._headers())
        else:
            headers = self._headers()

        try:
            return self.session().post(url, data=file_contents, headers=headers)
        except getattr(requests.exceptions, 'RequestException') as inst:
            self.module.fail_json(msg=inst.message)

    def delete(self, url, body=None):
        try:
            return self.session().delete(url, json=body, headers=self._headers())
        except getattr(requests.exceptions, 'RequestException') as inst:
            self.module.fail_json(msg=inst.message)

    def put(self, url, body=None):
        try:
            return self.session().put(url, json=body, headers=self._headers())
        except getattr(requests.exceptions, 'RequestException') as inst:
            self.module.fail_json(msg=inst.message)

    def patch(self, url, body=None, **kwargs):
        kwargs.update({'json': body, 'headers': self._headers()})
        try:
            return self.session().patch(url, **kwargs)
        except getattr(requests.exceptions, 'RequestException') as inst:
            self.module.fail_json(msg=inst.message)

    def session(self):
        return AuthorizedSession(
            self._credentials())

    def _validate(self):
        if not HAS_REQUESTS:
            self.module.fail_json(msg="Please install the requests library")

        if not HAS_GOOGLE_LIBRARIES:
            self.module.fail_json(msg="Please install the google-auth library")

        if self.module.params.get('service_account_email') is not None and self.module.params['auth_kind'] != 'machineaccount':
            self.module.fail_json(
                msg="Service Account Email only works with Machine Account-based authentication"
            )

        if (self.module.params.get('service_account_file') is not None or
                self.module.params.get('service_account_contents') is not None) and self.module.params['auth_kind'] != 'serviceaccount':
            self.module.fail_json(
                msg="Service Account File only works with Service Account-based authentication"
            )

    def _credentials(self):
        cred_type = self.module.params['auth_kind']
        if cred_type == 'application':
            credentials, project_id = google.auth.default(scopes=self.module.params['scopes'])
            return credentials
        elif cred_type == 'serviceaccount' and self.module.params.get('service_account_file'):
            path = os.path.realpath(os.path.expanduser(self.module.params['service_account_file']))
            return service_account.Credentials.from_service_account_file(path).with_scopes(self.module.params['scopes'])
        elif cred_type == 'serviceaccount' and self.module.params.get('service_account_contents'):
            cred = json.loads(self.module.params.get('service_account_contents'))
            return service_account.Credentials.from_service_account_info(cred).with_scopes(self.module.params['scopes'])
        elif cred_type == 'machineaccount':
            return google.auth.compute_engine.Credentials(
                self.module.params['service_account_email'])
        else:
            self.module.fail_json(msg="Credential type '%s' not implemented" % cred_type)

    def _headers(self):
        return {
            'User-Agent': "Google-Ansible-MM-{0}".format(self.product)
        }

    def _merge_dictionaries(self, a, b):
        new = a.copy()
        new.update(b)
        return new


class GcpModule(AnsibleModule):
    def __init__(self, *args, **kwargs):
        arg_spec = {}
        if 'argument_spec' in kwargs:
            arg_spec = kwargs['argument_spec']

        kwargs['argument_spec'] = self._merge_dictionaries(
            arg_spec,
            dict(
                project=dict(
                    required=False,
                    type='str',
                    fallback=(env_fallback, ['GCP_PROJECT'])),
                auth_kind=dict(
                    required=False,
                    fallback=(env_fallback, ['GCP_AUTH_KIND']),
                    choices=['machineaccount', 'serviceaccount', 'application'],
                    type='str'),
                service_account_email=dict(
                    required=False,
                    fallback=(env_fallback, ['GCP_SERVICE_ACCOUNT_EMAIL']),
                    type='str'),
                service_account_file=dict(
                    required=False,
                    fallback=(env_fallback, ['GCP_SERVICE_ACCOUNT_FILE']),
                    type='path'),
                service_account_contents=dict(
                    required=False,
                    fallback=(env_fallback, ['GCP_SERVICE_ACCOUNT_CONTENTS']),
                    type='str'),
                scopes=dict(
                    required=False,
                    fallback=(env_fallback, ['GCP_SCOPES']),
                    type='list')
            )
        )

        mutual = []
        if 'mutually_exclusive' in kwargs:
            mutual = kwargs['mutually_exclusive']

        kwargs['mutually_exclusive'] = mutual.append(
            ['service_account_email', 'service_account_file', 'service_account_contents']
        )

        AnsibleModule.__init__(self, *args, **kwargs)

    def raise_for_status(self, response):
        try:
            response.raise_for_status()
        except getattr(requests.exceptions, 'RequestException') as inst:
            self.fail_json(msg="GCP returned error: %s" % response.json())

    def _merge_dictionaries(self, a, b):
        new = a.copy()
        new.update(b)
        return new


# This class does difference checking according to a set of GCP-specific rules.
# This will be primarily used for checking dictionaries.
# In an equivalence check, the left-hand dictionary will be the request and
# the right-hand side will be the response.

# Rules:
# Extra keys in response will be ignored.
# Ordering of lists does not matter.
#   - exception: lists of dictionaries are
#     assumed to be in sorted order.
class GcpRequest(object):
    def __init__(self, request):
        self.request = request

    def __eq__(self, other):
        return not self.difference(other)

    def __ne__(self, other):
        return not self.__eq__(other)

    # Returns the difference between a request + response.
    # While this is used under the hood for __eq__ and __ne__,
    # it is useful for debugging.
    def difference(self, response):
        return self._compare_value(self.request, response.request)

    def _compare_dicts(self, req_dict, resp_dict):
        difference = {}
        for key in req_dict:
            if resp_dict.get(key):
                difference[key] = self._compare_value(req_dict.get(key), resp_dict.get(key))

        # Remove all empty values from difference.
        sanitized_difference = {}
        for key in difference:
            if difference[key]:
                sanitized_difference[key] = difference[key]

        return sanitized_difference

    # Takes in two lists and compares them.
    # All things in the list should be identical (even if a dictionary)
    def _compare_lists(self, req_list, resp_list):
        # Have to convert each thing over to unicode.
        # Python doesn't handle equality checks between unicode + non-unicode well.
        difference = []
        for index in range(len(list1)):
            value1 = list1[index]
            if index < len(list2):
                value2 = list2[index]
                difference.append(self._compare_value(value1, value2))

        difference2 = []
        for value in difference:
            if value:
                difference2.append(value)

        return difference2

    # Compare two values of arbitrary types.
    def _compare_value(self, req_value, resp_value):
        diff = None
        # If a None is found, a difference does not exist.
        # Only differing values matter.
        if not resp_value:
            return None

        # Can assume non-None types at this point.
        try:
            if isinstance(value1, list):
                diff = self._compare_lists(value1, value2)
            elif isinstance(value2, dict):
                diff = self._compare_dicts(value1, value2)
            elif isinstance(value1, bool):
                diff = self._compare_boolean(value1, value2)
            # Always use to_text values to avoid unicode issues.
            elif to_text(req_value) != to_text(resp_value):
                diff = req_value
        # to_text may throw UnicodeErrors.
        # These errors shouldn't crash Ansible and should be hidden.
        except UnicodeError:
            pass

        return diff

    def _compare_boolean(self, value1, value2):
        try:
            # Both True
            if value1 and value2 is True:
                return None
            # Value1 True, value2 'true'
            elif value1 and to_text(value2) == 'true':
                return None
            # Both False
            elif not value1 and not value2:
                return None
            # Value1 False, value2 'false'
            elif not value1 and to_text(value2) == 'false':
                return None
            else:
                return value2

        # to_text may throw UnicodeErrors.
        # These errors shouldn't crash Ansible and should be hidden.
        except UnicodeError:
            return None
