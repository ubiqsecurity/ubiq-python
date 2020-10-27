#!/usr/bin/env python3

UBIQ_HOST = 'api.ubiqsecurity.com'

from .auth import http_auth
from .encrypt import encryption, encrypt
from .decrypt import decryption, decrypt
from .credentials import credentials, configCredentials
