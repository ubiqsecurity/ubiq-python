import base64
import http
import json
import requests
import urllib.error
from copy import copy

from .auth import http_auth
from .algorithm import algorithm
from .configuration import ubiqConfiguration

import cryptography.exceptions as crypto_exceptions
import cryptography.hazmat.primitives as crypto
from cryptography.hazmat.backends import default_backend as crypto_backend


def fetchDecryptKey(host, papi, sapi, srsa, datakey, client_id, alg):
    config = ubiqConfiguration()
    key = {}
    # If Missing or Cache is disabled
    if (not papi in fetchDecryptKey.cache or
        not datakey in fetchDecryptKey.cache[papi] or
            not config.get_key_caching_unstructured()):

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
            raise urllib.error.HTTPError(
                url, response.status_code,
                http.HTTPStatus(response.status_code).phrase,
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

        if config.get_key_caching_unstructured():
            # Store in Cache
            if not papi in fetchDecryptKey.cache:
                fetchDecryptKey.cache[papi] = {}

            fetchDecryptKey.cache[papi][datakey] = key

    if len(key) == 0:
        # Get key from cache, key was not fetched.
        key = fetchDecryptKey.cache[papi][datakey]
    
    # Get a copy of the key. If it came from cache, it's a reference.
    # Decrypting the key would modify the cache, ignoring configuration.
    key = copy(key)

    if "raw" in key:
        # Unencrypted, return key
        return key
    else:
        # decrypt the client's private key (sent
        # by the server)
        prvkey = crypto.serialization.load_pem_private_key(
            key['encrypted_private_key'].encode('utf-8'),
            srsa.encode('utf-8'),
            crypto_backend())
        # use the private key to decrypt the data key
        key['raw'] = prvkey.decrypt(
            base64.b64decode(key['wrapped_data_key']),
            crypto.asymmetric.padding.OAEP(
                mgf=crypto.asymmetric.padding.MGF1(
                    algorithm=crypto.hashes.SHA1()),
                algorithm=crypto.hashes.SHA1(),
                label=None))
        
        if config.get_key_caching_unstructured() and not config.get_key_caching_encrypt():
            # Update store to have unwrapped version of the
            fetchDecryptKey.cache[papi][datakey] = key
        
        return key

fetchDecryptKey.cache = {}
