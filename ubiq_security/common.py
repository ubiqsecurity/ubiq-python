import base64
import http
import json
import requests
import urllib.error
from copy import copy

from .auth import http_auth
from .algorithm import algorithm
from .caching import encryptable_keycache, decrypt_key, CONFIG


@encryptable_keycache(maxsize=100, ttl=CONFIG.get_key_caching_ttl_seconds(), enable_cache=CONFIG.get_key_caching_unstructured(), encrypted=CONFIG.get_key_caching_encrypt())
def fetchDecryptKey(host, papi, sapi, srsa, datakey, client_id, alg):
    if CONFIG.get_logging_verbose():
        print('****** PERFORMING EXPENSIVE CALL ----- fetchDecryptKey')
    
    key = {}

    url = host + '/api/v0/decryption/key'
    response = requests.post(
        url,
        data=json.dumps(
            {
                'encrypted_data_key': base64.b64encode(
                    datakey).decode('utf-8')
            }).encode('utf-8'),
        auth=http_auth(papi, sapi))
    if response.status_code != http.HTTPStatus.OK:
        try:
            response_json = response.json()
        except JSONDecodeError:
            response_json = {}
        raise urllib.error.HTTPError(
            url, response.status_code,
            response_json.get('message', http.HTTPStatus(response.status_code).phrase),
            response.headers, response.content)

    content = json.loads(response.content.decode('utf-8'))

    key['algo'] = algorithm(alg)
    # the client's id for recognizing key reuse
    key['client_id'] = client_id
    # the server's id for sending updates
    key['finger_print'] = content['key_fingerprint']
    key['session'] = content['encryption_session']

    # Need these from the response or we can't decrypt the key later
    key['encrypted_private_key'] = content['encrypted_private_key']
    key['wrapped_data_key'] = content['wrapped_data_key']

    # this key hasn't been used (yet)
    key['uses'] = 0
    
    if "unwrapped_data_key" in key:
        # Unencrypted, return key
        return key
    else:                
        return decrypt_key(key, srsa)

