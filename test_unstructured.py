import ubiq_security as ubiq
import threading
import time
import uuid

import requests
import logging


creds = ubiq.configCredentials(None, "Unstructured")
config = ubiq.ubiqConfiguration()
# print(config.key_caching_unstructured)

original = "This is something to encrypt"
original_bytes = bytes(original, 'utf-8')

cipher = ubiq.encrypt(creds, original_bytes)

output = ubiq.decrypt(creds, cipher)
output = ubiq.decrypt(creds, cipher)
output = ubiq.decrypt(creds, cipher)

print(str(output))

print(ubiq.fetchDecryptKey.cache)
print(f"unstructured %s encrypt %s"%(config.get_key_caching_unstructured(), config.get_key_caching_encrypt()))
print(config.get_key_caching_unstructured() and not config.get_key_caching_encrypt())