# Copyright (c), Google Inc, 2026
# Simplified BSD License (see licenses/simplified_bsd.txt or https://opensource.org/licenses/BSD-2-Clause)

import fnmatch
import json
import pprint
import time
import typing as T

try:
    from requests import Response as RequestsResponse
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

    class RequestsResponse:
        pass


# avoid stuttering
from ansible_collections.google.cloud.plugins.module_utils.gcp_utils import (
    GcpModule as Module,
)
from ansible_collections.google.cloud.plugins.module_utils.gcp_utils import (
    GcpSession as Session,
)
from ansible_collections.google.cloud.plugins.module_utils.gcp_utils import (
    navigate_hash,
)

# match what magic-modules calls it
from ansible_collections.google.cloud.plugins.module_utils.gcp_utils import (
    replace_resource_dict as resource_ref,
)

assert resource_ref

ASYNC_RETRY_WAIT = 1.0


# Define a type alias for a nested dictionary structure
NestedDict = T.Dict[str, T.Union[T.Any, "NestedDict", T.List[T.Any]]]


def deep_equal(base_dict: NestedDict, compare_dict: NestedDict) -> bool:
    """
    Compares two dictionaries. Returns True if and only if:
    1. Every key present in base_dict is also present in compare_dict.
    2. For every matching key, the value in base_dict strictly matches
       the value in compare_dict.
       - If the values are non-dict and non-sequence types, they must be equal.
       - If the values are sequences, the comparison is done recursively for each
         element in both sequences.
       - If the values are both dictionaries, the comparison is done recursively.
    """

    # Check if all keys in base_dict are present in compare_dict
    if not base_dict.keys() <= compare_dict.keys():
        return False

    # Iterate through the keys of the base dictionary to compare vs the other
    for key, base_value in base_dict.items():
        compare_value = compare_dict[key]

        # Handle Nested Dictionaries
        if isinstance(base_value, dict) and isinstance(compare_value, dict):
            if not deep_equal(base_value, compare_value):
                return False

        # Handle Lists/Tuples/Sets
        elif isinstance(base_value, (list, tuple)) and isinstance(
            compare_value, (list, tuple)
        ):
            if len(base_value) != len(compare_value):
                return False

            for idx, val in enumerate(base_value):
                if isinstance(val, dict) and isinstance(compare_value[idx], dict):
                    if not deep_equal(val, compare_value[idx]):
                        return False
                elif val != compare_value[idx]:
                    return False

        # Handle All Other Values
        elif base_value != compare_value:
            return False

    # If you're here, the values are equal
    return True


def flatten_nested_dict(
    data: NestedDict, parent_key: str = "", separator: str = ".", **kwargs
) -> T.List[str]:
    """
    Recursively traverses a nested dictionary and returns a list of
    dot-separated strings representing the full key paths.

    Returns:
        A list of strings, e.g., ['a.b.c', 'a.d', 'e'].
    """
    items = []

    for key, value in data.items():
        # Construct the full path for the current key
        new_key = f"{parent_key}{separator}{key}" if parent_key else key

        # Check the key against exclusion patterns
        is_excluded = False
        glob_excludes = kwargs.get("glob_excludes", [])
        for pattern in glob_excludes:
            if fnmatch.fnmatch(new_key, pattern):
                is_excluded = True
                break

        if is_excluded:
            continue

        # Check if the value is a dictionary
        if isinstance(value, dict):
            items.extend(
                flatten_nested_dict(
                    value, new_key, separator, glob_excludes=glob_excludes
                )
            )
        else:
            items.append(new_key)

    return items


def debug(module: T.Optional[Module], **kwargs) -> None:
    "Prints debugging output using module logging"

    if module is not None:
        if module._verbosity >= 3:
            module.log(pprint.saferepr(kwargs))


class ResourceOpConfig(object):
    verb: str
    uri: str
    timeout: int
    async_uri: str

    def __init__(
        self, verb: str, uri: str, timeout_minutes: int, async_uri: str
    ) -> None:
        self.verb = verb.lower()
        self.uri = uri
        self.timeout = timeout_minutes * 60
        self.async_uri = async_uri

    def get(self, key: str) -> T.Any:
        return getattr(self, key)


class ResourceOpConfigs(object):
    read: ResourceOpConfig
    create: ResourceOpConfig
    update: ResourceOpConfig
    delete: ResourceOpConfig
    base_url: str
    base_uri: str

    def __init__(
        self, base_url: str, base_uri: str, configs: T.Dict[str, ResourceOpConfig]
    ):
        self.base_url = base_url
        self.base_uri = base_uri
        for k, v in configs.items():
            setattr(self, k, v)

    def build_link_template(self, op: str) -> str:
        link: str = ""

        if op == "read":
            link = self.base_url + self.read.uri
        elif op == "create":
            link = self.base_url + self.create.uri
        elif op == "update":
            link = self.base_url + self.update.uri
        elif op == "delete":
            link = self.base_url + self.delete.uri
        else:
            link = self.base_url + self.base_uri

        return link


class Resource(object):
    """
    Convenience class to handle requests to the API
    """

    module: T.Optional[Module] = None
    kind: T.Optional[str] = None
    product: T.Optional[str]
    request: NestedDict = {}
    response: NestedDict = {}
    op_configs: ResourceOpConfigs
    url_params: NestedDict = {}

    def __init__(
        self,
        request: T.Optional[NestedDict] = None,
        **kwargs: T.Dict[str, T.Any],
    ) -> None:
        if request is not None:
            self.request = request
            self.url_params = request.copy()  # make a shallow copy to manipulate freely
        if kwargs.get("kind") is not None:
            self.kind = str(kwargs["kind"])
        if kwargs.get("product") is not None:
            self.product = str(kwargs["product"])
        module: T.Any = kwargs.get("module")
        if module is not None and isinstance(module, Module):
            self.module = module
        op_configs: T.Any = kwargs.get("op_configs")
        if op_configs is not None and isinstance(op_configs, ResourceOpConfigs):
            self.op_configs = op_configs

    def debug(self, **kwargs) -> None:
        debug(self.module, **kwargs)

    def session(self) -> Session:
        "Returns an authenticated GCP session"

        return Session(self.module, self.product)

    def raise_for_status(self, response: RequestsResponse):
        if self.module is not None:
            self.module.raise_for_status(response)
        else:
            raise ValueError("Cannot raise_for_status over None module")

    def fail_json(self, msg: str):
        if self.module is not None:
            self.module.fail_json(msg=msg)
        else:
            raise ValueError("Cannot fail_json over None module")

    def if_object(
        self, response: T.Optional[RequestsResponse], allow_not_found: bool = False
    ) -> T.Optional[NestedDict]:
        """
        Convenience function to analyze the requests.Response object and decide
        if it should raise an ansible error or not.
        """

        if response is None:
            return None

        # If not found, return nothing.
        if allow_not_found and response.status_code == 404:
            return None

        # If no content, return nothing.
        if response.status_code == 204:
            return None

        result: T.Optional[NestedDict] = None
        try:
            self.raise_for_status(response)
            result = response.json()
        except getattr(json.decoder, "JSONDecodeError", ValueError):
            self.fail_json(f"Invalid JSON response with error: {response.text}")

        # old-style responses
        msg: T.Optional[str] = navigate_hash(result, ["error", "errors"])
        if msg is not None:
            self.fail_json(msg)

        # new-style responses
        msg = navigate_hash(result, ["error", "message"])
        if msg is not None:
            self.fail_json(msg)

        return result

    def _request(self) -> NestedDict:
        "Placeholder for auto-generated subclasses"

        return self.request

    def _response(self) -> NestedDict:
        "Placeholder for auto-generated subclasses"

        return self.response

    def to_request(self) -> T.Optional[NestedDict]:
        "This should be built from self.request"

        req = remove_empties(self._request())
        req = self.encode(req or {})

        return req

    def encode(self, request: NestedDict) -> NestedDict:
        "Placeholder for auto-generated subclasses"

        return request

    def decode(self, response: NestedDict) -> NestedDict:
        "Placeholder for auto-generated subclasses"

        return response

    def from_response(self, response: NestedDict) -> NestedDict:
        """
        This should set self.response from the given dictionary and then build the
        response from there
        """

        self.response = response
        self.response.update(self._response())

        rsp: T.Optional[NestedDict] = remove_empties(self.response)

        return self.decode(rsp or {})

    def get(self, link: str, allow_not_found: bool = True) -> T.Optional[NestedDict]:
        """
        Make GET request.
        """

        self.debug(method="get", link=link)

        return self.if_object(self.session().get(link), allow_not_found)

    def wait_for_op(self, op_url: str, retries: int) -> T.Optional[NestedDict]:
        "Retry the given number of times for an async operation to succeed"

        self.debug(msg="Waiting for async op", op_url=op_url, retries=retries)
        for retry in range(1, retries):
            op = self.session().get(op_url)
            op_obj = self.if_object(op, allow_not_found=False)
            if op_obj:
                done: bool = bool(navigate_hash(op_obj, ["done"], False))
                if done:
                    rsp: T.Any = navigate_hash(op_obj, ["response"], {})

                    if rsp is not None:
                        return self.decode(rsp)

            self.debug(op_url=op_url, retry=retry)
            time.sleep(ASYNC_RETRY_WAIT)  # TODO: should we relax the check?

        self.fail_json("Failed to poll for async op completion")

    def async_op(
        self,
        op_func: T.Callable,
        link: str,
        async_uri: str,
        retries: int,
    ) -> T.Optional[NestedDict]:
        "Perform an asynchronous operation and wait for the result"

        op_result: T.Optional[NestedDict] = op_func(link)

        op_id: str = str(navigate_hash(op_result, ["name"], ""))
        self.url_params.update({"op_id": op_id})
        op_url: str = (self.op_configs.base_url + async_uri).format(**self.url_params)

        return self.wait_for_op(op_url, retries)

    def post_async(
        self, link: str, async_uri: str, retries: int
    ) -> T.Optional[NestedDict]:
        "Perform an asynchronous post"

        return self.async_op(
            op_func=self.post,
            link=link,
            async_uri=async_uri,
            retries=retries,
        )

    def put_async(
        self, link: str, async_uri: str, retries: int
    ) -> T.Optional[NestedDict]:
        "Perform an asynchronous put"

        return self.async_op(
            op_func=self.put,
            link=link,
            async_uri=async_uri,
            retries=retries,
        )

    def patch_async(
        self, link: str, async_uri: str, retries: int
    ) -> T.Optional[NestedDict]:
        "Perform an asynchronous patch"

        return self.async_op(
            op_func=self.patch,
            link=link,
            async_uri=async_uri,
            retries=retries,
        )

    def delete_async(
        self, link: str, async_uri: str, retries: int
    ) -> T.Optional[NestedDict]:
        "Perform an asynchronous delete"

        return self.async_op(
            op_func=self.delete,
            link=link,
            async_uri=async_uri,
            retries=retries,
        )

    def with_kind(self, response_obj: T.Optional[NestedDict]) -> T.Optional[NestedDict]:
        "Make sure all responses have the kind attached to them"

        if response_obj is not None and len(response_obj) > 0:
            response_obj.update({"kind": self.kind})
        return response_obj

    def post(self, link) -> T.Optional[NestedDict]:
        """
        Make POST request.
        """

        req = self.to_request()
        self.debug(method="post", link=link, request=req)
        return self.if_object(self.session().post(link, req))

    def put(self, link) -> T.Optional[NestedDict]:
        """
        Make PUT request.
        """

        req = self.to_request()
        self.debug(method="put", link=link, request=req)
        return self.if_object(self.session().put(link, req))

    def patch(self, link) -> T.Optional[NestedDict]:
        """
        Make PATCH request
        """

        req = self.to_request()
        self.debug(method="patch", link=link, request=req)
        return self.if_object(self.session().patch(link, req))

    def delete(self, link) -> T.Optional[NestedDict]:
        """
        Make DELETE request.
        """

        # normally, you don't need to pass a request body on deletes, but *some* APIs
        # require it so you still pass it by customizing the encoder function
        req = self.encode({})
        self.debug(method="delete", link=link, request=req)
        return self.if_object(self.session().delete(link, req))

    def diff(self, response: NestedDict) -> bool:
        """
        Returns the difference between request and response
        """

        req: NestedDict = self.to_request() or {}
        rsp: NestedDict = self.from_response(response)

        return not deep_equal(req, rsp)

    def dot_fields(self) -> T.List[str]:
        """
        Returns a list of dot-separated strings with (almost) all fields in the current object
        """

        req: NestedDict = self.to_request() or {}
        dotfields: T.List[str] = []

        # these 3 are free-form dicts, we don't want to list all the possible children
        exclusions: T.Tuple = (
            "labels",
            "annotations",
            "tags",
        )
        for i in exclusions:
            if i in req.keys():
                dotfields.append(i)

        fields = flatten_nested_dict(
            req, separator=".", glob_excludes=[f"{x}.*" for x in exclusions]
        )
        dotfields.extend(fields)

        return dotfields

    def build_link(self, op: str) -> str:
        """
        Builds a link for a given operation: read/create/update/delete etc
        """

        self.debug(action="build_link", op=op)
        tpl: str = self.op_configs.build_link_template(op)
        self.debug(action="build_link", tpl=tpl)
        url: str = tpl.format(**self.url_params)
        self.debug(action="build_link", link=url)

        return url


def empty(data: T.Any) -> bool:
    """
    Quick function to test if something is "empty".
    """

    if data is None:
        return True
    elif data == {}:
        return True
    elif data == []:
        return True
    elif data == "":
        return True
    else:
        return False


def remove_nones(data: T.Optional[NestedDict]) -> NestedDict:
    """
    Removes keys with None values from a dict. It is necessary to make
    a distinction between this and empties because there are some APIs
    that accept (or even require) empty values.
    """

    if isinstance(data, dict):
        return {k: v for k, v in data.items() if v is not None}
    else:
        return {}


def remove_empties(data: T.Optional[NestedDict]) -> T.Optional[NestedDict]:
    """
    Removes keys with "empty" values from a dict. Basically the original
    remove_nones_from_dict behavior.
    """

    if isinstance(data, dict):
        return {k: v for k, v in data.items() if not empty(v)}
    else:
        return None
