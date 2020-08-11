#!/usr/bin/env python3
#
# Copyright 2020 Ubiq Security, Inc., Proprietary and All Rights Reserved.
#
# NOTICE:  All information contained herein is, and remains the property
# of Ubiq Security, Inc. The intellectual and technical concepts contained
# herein are proprietary to Ubiq Security, Inc. and its suppliers and may be
# covered by U.S. and Foreign Patents, patents in process, and are
# protected by trade secret or copyright law. Dissemination of this
# information or reproduction of this material is strictly forbidden
# unless prior written permission is obtained from Ubiq Security, Inc.
#
# Your use of the software is expressly conditioned upon the terms
# and conditions available at:
#
#     https://ubiqsecurity.com/legal
#

UBIQ_HOST = 'api.ubiqsecurity.com:8811'

from .auth import http_auth
from .encrypt import encryption, encrypt
from .decrypt import decryption, decrypt
from .credentials import credentials, configCredentials
