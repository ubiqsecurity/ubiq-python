from cachetools import cached, TTLCache

import base64
import cryptography.exceptions as crypto_exceptions
import cryptography.hazmat.primitives as crypto
import cryptography.hazmat.primitives.serialization as serialize
from cryptography.hazmat.backends import default_backend as crypto_backend

from .configuration import ubiqConfiguration

CONFIG = ubiqConfiguration()


def decrypt_key(key, srsa):
    prvkey = serialize.load_pem_private_key(
        key['encrypted_private_key'].encode('utf-8'),
        srsa.encode('utf-8'),
        crypto_backend())

    key['unwrapped_data_key'] = prvkey.decrypt(
        base64.b64decode(key['wrapped_data_key']),
        crypto.asymmetric.padding.OAEP(
            mgf=crypto.asymmetric.padding.MGF1(
                algorithm=crypto.hashes.SHA1()),
            algorithm=crypto.hashes.SHA1(),
            label=None))
    
    return key

# Cache will not contain the unwrapped_data_key. Decrypt at retrieval.
class EncryptedCache(TTLCache):
    # Decrypt wrapped_data_key when retrieved.
    def __getitem__(self, key):
        if CONFIG.get_logging_verbose():
            print('RETRIEVING FROM CACHE')
        # Get srsa from args
        srsa = key[3]
        cached_key = super().__getitem__(key)

        # decrypt the client's private key (sent by the server)
        return decrypt_key(cached_key, srsa)

    # Don't cache the unwrapped_data_key
    def __setitem__(self, key, value):
        if CONFIG.get_logging_verbose():
            print(f'STORING IN CACHE')
        # Modify a copy instead of the returned result
        cache_copy = dict(value)
        del cache_copy['unwrapped_data_key']
        # Save the copy (returning the version with unwrapped_data_key)
        super().__setitem__(key, cache_copy)
        
        # if len(key) is 5, no key_num was provided to call
        # and if key_number is present, this is a structured key
        if 'key_number' in key and len(key) == 5:
            # Store key at No Key Num (current) and the Key's Key_num
            n = int(key['key_number'])
            second_key = key[:-1] + (n,)
            print(f'STORING IN CACHE - KEY_NUM: {n}')
            super().__setitem__(second_key, cache_copy)
            

# Basic enable/disable-able TTL Cache
def config_cache(maxsize=100, ttl=1800, enable_cache=True):
    def decorator(func):
        if enable_cache:
            return cached(cache=TTLCache(maxsize=maxsize, ttl=ttl))(func)
        return func
    return decorator

# Decorator for methods with the potential to leave cache encrypted and decrypt at runtime.
def encryptable_keycache(maxsize=100, ttl=1800, enable_cache=True, encrypted=False):
    def decorator(func):
        if enable_cache:
            if encrypted:
                return cached(cache=EncryptedCache(maxsize=maxsize, ttl=ttl))(func)
            else:
                return cached(cache=TTLCache(maxsize=maxsize, ttl=ttl))(func)
        return func
    return decorator