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

import base64
import http
import json
import requests
import struct
import urllib.error

import cryptography.hazmat.primitives as crypto
from cryptography.hazmat.backends import default_backend as crypto_backend

from . import UBIQ_HOST
from .auth import http_auth
from .algorithm import algorithm
from .credentials import credentials

class encryption:
    """Ubiq Platform Encryption object

    This object represents a single data encryption key and can be used
    to encrypt several separate plain texts using the same key
    """

    def _endpoint_base(self):
        return self._host + '/api/v0'

    def __del__(self):
        """
        If the key was used less times than was requested, send an
        update to the server. This function is called automatically.
        """
        try:
            if self._key['uses'] < self._key['max_uses']:
                requests.patch(
                    self._endpoint_base() +
                    '/encryption/key/' + self._key['id'] + '/' + self._key['session'],
                    data=json.dumps(
                        { "requested": self._key['max_uses'],
                          "actual": self._key['uses'] }).encode('utf-8'),
                    auth=http_auth(self._papi, self._sapi))
        except:
            pass

    def __init__(self, creds, uses):
        """Initialize the encryption object

        papi:
            The client's public API key (used to identify the
            client to the server)
        sapi:
            The client's secret API key (used to authenticate HTTP requests)
        srsa:
            The client's secret RSA encryption key/password (used to decrypt
            the client's RSA key from the server). This key is not retained
            by this object.
        uses:
            The number of separate encryptions the caller wishes to perform
            with the key. This number may be limited by the server.
        host:
            A string of the form 'host[:port]' with the []'s denoting an
            optional portion of the string indicating the server to which
            to make the request.
        """

        # If the host does not begin with either http or https
        # insert https://
        self._host = creds.host
        if (not self._host.lower().startswith('http')):
            self._host = "https://" + self._host

        self._papi = creds.access_key_id
        self._sapi = creds.secret_signing_key

        #
        # request a new encryption key from the server. if the request
        # fails, the function raises a urllib.error.HTTPError indicating
        # the status code returned by the server. this exception is
        # propagated back to the caller
        #

        url = self._endpoint_base() + '/encryption/key'

        response = requests.post(
            url,
            data=json.dumps({ 'uses': uses }).encode('utf-8'),
            auth=http_auth(self._papi, self._sapi))

        if response.status_code != http.HTTPStatus.CREATED:
            raise urllib.error.HTTPError(
                url, response.status_code,
                http.HTTPStatus(response.status_code).phrase,
                response.headers, response.content)

        #
        # the code below largely assumes that the server returns
        # a json object that contains the members and is formatted
        # according to the Ubiq REST specification. if it doesn't
        # the code raises an exception about missing keys and those
        # exceptions are propagated back to the caller
        #

        content = json.loads(response.content.decode('utf-8'))

        #
        # decrypt the client's private key. if the decryption fails,
        # the function raises a ValueError which is propagated up.
        #
        prvkey = crypto.serialization.load_pem_private_key(
            content['encrypted_private_key'].encode('utf-8'), creds.secret_crypto_access_key.encode('utf-8'),
            crypto_backend())

        self._key = {}
        self._key['id'] = content['key_fingerprint']
        self._key['session'] = content['encryption_session']
        self._key['security_model'] = content['security_model']
        self._key['algorithm'] = self._key['security_model']['algorithm'].lower()
        self._key['max_uses'] = content['max_uses']
        self._key['uses'] = 0

        #
        # use the client's private key to decrypt the data key to
        # be used for encryption
        #
        self._key['raw'] = prvkey.decrypt(
            base64.b64decode(content['wrapped_data_key']),
            crypto.asymmetric.padding.OAEP(
                mgf=crypto.asymmetric.padding.MGF1(
                    algorithm=crypto.hashes.SHA1()),
                algorithm=crypto.hashes.SHA1(),
                label=None))

        #
        # the service also returns the encryption key encrypted by
        # its own master key. this value is attached to each cipher
        # text created by this object
        #
        self._key['encrypted'] = base64.b64decode(
            content['encrypted_data_key'])

        self._algo = algorithm(self._key['algorithm'])

    def begin(self):
        """Begin the encryption process

        When this function is called, the encryption object increments
        the number of uses of the key and creates a new internal context
        to be used to encrypt the data.
        """
        if hasattr(self, '_enc'):
            raise RuntimeError("encryption already in progress")

        if self._key['uses'] >= self._key['max_uses']:
            raise RuntimeError("maximum key uses exceeded")
        self._key['uses'] += 1

        # create a new encryption context
        self._enc, iv = self._algo.encryptor(self._key['raw'])

        # create and return the header for the cipher text
        return (struct.pack('!BBBBH',
                            0, 0,
                            self._algo.id,
                            len(iv), len(self._key['encrypted'])) +
                iv + self._key['encrypted'])

    def update(self, data):
        """Encrypt some plain text

        Any cipher text produced by the operation is returned
        """
        return self._enc.update(data)

    def end(self):
        """Finalize an encryption

        This function finalizes the encryption (producing the final
        cipher text for the encryption, if necessary) and adds any
        authentication information (if required by the algorithm).
        Any data produced is returned by the function.

        This function also resets the internal context, so that the
        caller can start a new encryption using the begin() function.
        """
        res = self._enc.finalize()
        if not self._algo.len['tag'] == 0:
            res += self._enc.tag
        del self._enc
        return res

def encrypt(creds, data):
    """Simple encryption interface
    papi:
        The client's public API key (used to identify the
        client to the server)
    sapi:
        The client's secret API key (used to authenticate HTTP requests)
    srsa:
        The client's secret RSA encryption key/password (used to decrypt
        the client's RSA key from the server).
    data:
        A byte string containing the plain text to be encrypted
    host:
        A string of the form 'host[:port]' with the []'s denoting an
        optional portion of the string indicating the server to which
        to make the request.

    returns:
        the entire cipher text that can be passed to the decrypt function
    """
    enc = encryption(creds, 1)
    return enc.begin() + enc.update(data) + enc.end()
