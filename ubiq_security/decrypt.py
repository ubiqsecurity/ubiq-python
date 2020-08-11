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

import cryptography.exceptions as crypto_exceptions
import cryptography.hazmat.primitives as crypto
from cryptography.hazmat.backends import default_backend as crypto_backend

from . import UBIQ_HOST
from .auth import http_auth
from .algorithm import algorithm

class decryption:
    def _endpoint_base(self):
        return self._host + '/api/v0'

    def reset(self):
        """Reset the internal state of the decryption object

        This function can be called at any time to abort an existing
        decryption operation. It is also called by internal functions
        when a new decryption requires a different key than the one
        used by the previous decryption.
        """
        if hasattr(self, '_key'):
            if self._key['uses'] > 0:
                requests.patch(
                    self._endpoint_base() +
                    '/decryption/key/' + self._key['finger_print'] + '/' + self._key['session'],
                    data=json.dumps(
                        { 'uses': self._key['uses'] }).encode('utf-8'),
                    auth=http_auth(self._papi, self._sapi))
            del self._key

    def __del__(self):
        try:
            self.reset()
        except:
            pass

    def __init__(self, creds):
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
        self._srsa = creds.secret_crypto_access_key
        
    def begin(self):
        """Begin the decryption process

        returns:
            any plain text produced by the call
        """

        # this interface does not take any cipher text in its arguments
        # in an attempt to maintain an API that corresponds to the
        # encryption object. in doing so, the work that can take place
        # in this function is limited. without any data, there is no
        # way to determine which key is in use or decrypt any data.
        #
        # this function simply throws an error if starting an decryption
        # while one is already in progress, and initializes the internal
        # buffer, otherwise

        if hasattr(self, '_key') and 'dec' in self._key:
            raise RuntimeError("decryption already in progress")

        self._buf = b''
        return b''

    def update(self, data):
        """Decrypt cipher text

        Cipher text must be passed to this function in the order in
        which it was output from the encryption.update function.

        data:
            (A portion of) the cipher text to be decrypted

        returns:
            any plain text produced by the call
        """

        #
        # each encryption has a header on it that identifies the algorithm
        # used  and an encryption of the data key that was used to encrypt
        # the original plain text. there is no guarantee how much of that
        # data will be passed to this function or how many times this
        # function will be called to process all of the data. to that end,
        # this function buffers data internally, when it is unable to
        # process it.
        #
        # the function buffers data internally until the entire header is
        # received. once the header has been received, the encrypted data
        # key is sent to the server for decryption. after the header has
        # been successfully handled, this function always decrypts all of
        # the data in its internal buffer *except* for however many bytes
        # are specified by the algorithm's tag size. see the end() function
        # for details.
        #

        self._buf += data
        pt = b''

        # if there is no key or 'dec' member of key, then the code
        # is still trying to build a complete header

        if not hasattr(self, '_key') or not 'dec' in self._key:
            fmt = '!BBBBH'
            fmtlen = struct.calcsize(fmt)

            # does the buffer contain enough of the header to
            # determine the lengths of the initialization vector
            # and the key?

            if len(self._buf) >= fmtlen:
                ver, sbz, alg, veclen, keylen = struct.unpack(
                    fmt, self._buf[:fmtlen])

                if ver != 0 or sbz != 0:
                    raise RuntimeError('invalid encryption header')

                # does the buffer contain the entire header?

                if len(self._buf) >= fmtlen + veclen + keylen:

                    # extract the initialization vector and the key
                    vec = self._buf[fmtlen:fmtlen + veclen]
                    key = self._buf[fmtlen + veclen:fmtlen + veclen + keylen]

                    # remove the header from the buffer
                    self._buf = self._buf[fmtlen + veclen + keylen:]

                    # generate a local identifier for the key
                    sha = crypto.hashes.Hash(
                        crypto.hashes.SHA256(), backend=crypto_backend())
                    sha.update(key)
                    client_id = sha.finalize()

                    # if the object already has a key (from a previous
                    # decryption), is the key in this header the same as
                    # that previous one?
                    #
                    # if not, clear out the existing key
                    if hasattr(self, '_key'):
                        if self._key['client_id'] != client_id:
                            self.reset()

                    # if the object (still) has a key, then it can be
                    # reused--see below. if not, then request a decryption
                    # of the key in the current header from the server
                    if not hasattr(self, '_key'):
                        url = self._endpoint_base() + '/decryption/key'
                        response = requests.post(
                            url,
                            data=json.dumps(
                                {
                                    'encrypted_data_key': base64.b64encode(
                                        key).decode('utf-8')
                                }).encode('utf-8'),
                            auth=http_auth(self._papi, self._sapi))
                        if response.status_code != http.HTTPStatus.OK:
                            raise urllib.error.HTTPError(
                                url, response.status_code,
                                http.HTTPStatus(response.status_code).phrase,
                                response.headers, response.content)

                        content = json.loads(response.content.decode('utf-8'))

                        self._key = {}

                        self._key['algo']      = algorithm(alg)
                        # the client's id for recognizing key reuse
                        self._key['client_id'] = client_id
                        # the server's id for sending updates
                        self._key['finger_print'] = content['key_fingerprint']
                        self._key['session'] = content['encryption_session']

                        # decrypt the client's private key (sent
                        # by the server)
                        prvkey = crypto.serialization.load_pem_private_key(
                            content['encrypted_private_key'].encode('utf-8'),
                            self._srsa.encode('utf-8'),
                            crypto_backend())
                        # use the private key to decrypt the data key
                        self._key['raw'] = prvkey.decrypt(
                            base64.b64decode(content['wrapped_data_key']),
                            crypto.asymmetric.padding.OAEP(
                                mgf=crypto.asymmetric.padding.MGF1(
                                    algorithm=crypto.hashes.SHA1()),
                                algorithm=crypto.hashes.SHA1(),
                                label=None))

                        # this key hasn't been used (yet)
                        self._key['uses'] = 0

                    # if the key object exists, create a new decryptor
                    # with the initialization vector from the header and
                    # the decrypted key (which is either new from the
                    # server or cached from the previous decryption). in
                    # either case, increment the key usage
                    if hasattr(self, '_key'):
                        self._key['dec'] = self._key['algo'].decryptor(
                            self._key['raw'], vec)
                        self._key['uses'] += 1

        # if the object has a key and a decryptor, then decrypt whatever
        # data is in the buffer, less any data that needs to be saved to
        # serve as the tag.
        if hasattr(self, '_key') and 'dec' in self._key:
            sz = len(self._buf) - self._key['algo'].len['tag']
            if sz > 0:
                pt = self._key['dec'].update(self._buf[:sz])
                self._buf = self._buf[sz:]

        return pt

    def end(self):
        """Finish a decryption

        returns:
            any plain text produced by the call
        """
        # the update function always maintains tag-size bytes in
        # the buffer because this function provides no data parameter.
        # by the time the caller calls this function, all data must
        # have already been input to the decryption object.

        pt = b''

        try:
            # determine how much of the buffer contains data
            # and how much of it contains the tag
            sz = len(self._buf) - self._key['algo'].len['tag']

            if sz < 0:
                # there's not enough data in the buffer for a complete tag
                raise crypto_exceptions.InvalidTag
            elif sz == 0:
                # the buffer contains exactly the right amount of data
                # for a complete tag. if the tag length is zero, just
                # finalize the decryption
                if self._key['algo'].len['tag'] == 0:
                    pt = self._key['dec'].finalize()
                else:
                    pt = self._key['dec'].finalize_with_tag(self._buf)
            else:
                # this is a logic error that can't occur based
                # on the logic in the update function. the update
                # function never leaves more data than the tag
                # size in the buffer once the header has been
                # successfully parsed.
                raise AssertionError
        finally:
            del self._key['dec']
            del self._buf

        return pt

def decrypt(creds, data):
    """Simple decryption interface
    papi:
        The client's public API key (used to identify the
        client to the server)
    sapi:
        The client's secret API key (used to authenticate HTTP requests)
    srsa:
        The client's secret RSA encryption key/password (used to decrypt
        the client's RSA key from the server).
    data:
        A byte string containing the cipher text to be decrypted
    host:
        A string of the form 'host[:port]' with the []'s denoting an
        optional portion of the string indicating the server to which
        to make the request.

    returns:
        the entire cipher text that can be passed to the decrypt function
    """
    dec = decryption(creds)
    return dec.begin() + dec.update(data) + dec.end()
