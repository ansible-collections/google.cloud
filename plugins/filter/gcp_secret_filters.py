# (c) 2019, Eric Anderson <eric.sysmin@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

# Usage:
#     vars:
#         encrypted_myvar: "{{ var | b64encode | gcp_kms_encrypt(projects='default',
#           key_ring='key_ring', crypto_key='crypto_key') }}"
#         decrypted_myvar: "{{ encrypted_myvar | gcp_kms_decrypt(projects='default',
#           key_ring='key_ring', crypto_key='crypto_key') }}"

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from ansible.errors import AnsibleError
from ansible_collections.google.cloud.plugins.module_utils.gcp_utils import GcpSession


class GcpMockModule(object):
    def __init__(self, params):
        self.params = params

    def fail_json(self, *args, **kwargs):
        raise AnsibleError(kwargs['msg'])


class GcpSecretFilter():
    def run(self, method, **kwargs):
        params = {
            'secret': kwargs.get('secret', None),
            'versions': kwargs.get('version', 'latest'),
            'projects': kwargs.get('projects', None),
            'scopes': kwargs.get('scopes', None),
            'auth_kind': kwargs.get('auth_kind', 'application'),
            'service_account_file': kwargs.get('service_account_file', None),
            'service_account_email': kwargs.get('service_account_email', None),
        }
        if not params['scopes']:
            params['scopes'] = ['https://www.googleapis.com/auth/cloud-platform']
        fake_module = GcpMockModule(params)
        if method == "decode":
            return self.secret_decode(fake_module)

    def secret_decode(self, module):
        payload = {"ciphertext": module.params['ciphertext']}

        auth = GcpSession(module, 'secretmanager')
        url = "https://secretmanager.googleapis.com/v1/projects/{projects}/secrets/{secret}/" \
            "versions/{version}:access".format(**module.params)
        response = auth.get(url, body=payload)
        return response.json()['payload']['data']

def gcp_secret_decode(plaintext, **kwargs):
    return GcpKmsFilter().run('decode', plaintext=plaintext, **kwargs)

class FilterModule(object):

    def filters(self):
        return {
            'gcp_secret_decode': gcp_secret_decode,
        }
