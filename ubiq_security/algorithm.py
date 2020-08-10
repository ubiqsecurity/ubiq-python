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


import cryptography.hazmat as crypto
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes)

import os

class algorithm:
    """Internal representation of supported algorithm(s)

    This class is mostly a "front", allowing names and id's of algorithms
    to be seamlessly translated to code/function calls. A caller can
    create an algorithm object, supplying either the name of the algorithm
    or its numerical id, and the created object can be used to perform
    encryptions or decryptions using the algorithm specified.
    """

    #
    # names and numbers must be unique, individually. that is, using the
    # same number with two different names or vice versa is illegal. also,
    # do NOT alter the names or numbers of existing entries as that will
    # invalidate data that has already used the existing entry
    #
    # entries are in the format:
    # (algorithm-numeric-id, 'algorithm-text-name'):
    #     (algorithm-class, mode-class, key-length, iv-length, tag-length)
    # with all lengths specified in bytes
    #
    _ALGORITHM = {
        (0, 'aes-256-gcm'): (crypto.primitives.ciphers.algorithms.AES,
                             crypto.primitives.ciphers.modes.GCM,
                             32, 12, 16),
    }

    def __init__(self, ident):
        """
        ident:
            The name or numerical id of an algorithm
        """
        try:
            self.len = {}
            ((self.id, self.name),
             (self._algo, self._mode,
              self.len['key'], self.len['iv'], self.len['tag'])) = next(
                  ((k, v) for k, v in self._ALGORITHM.items() if ident in k))
        except:
            raise RuntimeError('algorithm (' + str(ident) + ') not found')

    def encryptor(self, key, iv=None):
        """
        key:
            A byte string containing the key to be used with this encryption
        iv:
            If the caller specifies the initialization vector, it must be
            the correct length and, if so, will be used. If it is not
            specified, the function will generate a new one

        returns:
            The encryptor object and the initialization vector
        """
        if len(key) != self.len['key']:
            raise RuntimeError('invalid key length')
        if iv is not None and len(iv) != self.len['iv']:
            raise RuntimeError('invalid initialization vector length')

        if iv is None:
            iv = os.urandom(self.len['iv'])

        return (
            crypto.primitives.ciphers.Cipher(
                self._algo(key),
                self._mode(iv),
                backend=crypto.backends.default_backend()).encryptor(),
            iv)

    def decryptor(self, key, iv):
        """
        key:
            A byte string containing the key to be used with this decryption
        iv:
            The initialization vector used when the data was encrypted

        Note that if a tag was used with the encryption, the caller must
        use the 'finalize_with_tag' function to verify the decryption.
        """
        if len(key) != self.len['key']:
            raise RuntimeError('invalid key length')
        if len(iv) != self.len['iv']:
            raise RuntimeError('invalid initialization vector length')

        if self.len['tag'] == 0:
            mode = self._mode(iv)
        else:
            mode = self._mode(iv, None, self.len['tag'])

        return crypto.primitives.ciphers.Cipher(
            self._algo(key),
            mode,
            backend=crypto.backends.default_backend()).decryptor()
