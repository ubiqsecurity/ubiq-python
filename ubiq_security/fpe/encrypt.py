#/usr/bin/env python3

import base64
from ubiq_security_fpe import ff1

from ..credentials import credentials

from .common import fmtInput, strConvertRadix, encKeyNumber, fmtOutput
from .common import fetchFFS, fetchKey

class Encryption:
    def __del__(self):
        # todo: overwrite 'unwrapped_data_key'
        return

    def __init__(self, creds, ffs):
        if not creds.set():
            raise RuntimeError("credentials not set")

        # If the host does not begin with either http or https
        # insert https://
        self._host = creds.host
        if (not self._host.lower().startswith('http')):
            self._host = "https://" + self._host
        self._host += '/api/v0/'

        self._papi = creds.access_key_id
        self._sapi = creds.secret_signing_key

        self._ffs = fetchFFS(self._host, self._papi, self._sapi, ffs)
        self._key = fetchKey(self._host,
                             self._papi, self._sapi,
                             creds.secret_crypto_access_key,
                             ffs)

        if self._ffs['encryption_algorithm'] == 'FF1':
            self._algo = ff1.Context(
                self._key['unwrapped_data_key'],
                base64.b64decode(self._ffs['tweak']),
                self._ffs['tweak_min_len'], self._ffs['tweak_max_len'],
                len(self._ffs['input_character_set']),
                self._ffs['input_character_set'])
        else:
            raise RuntimeError('unsupported algorithm: ' +
                               self._ffs['encryption_algorithm'])

    def Cipher(self, pt, twk = None):
        pth = self._ffs['passthrough']
        ics = self._ffs['input_character_set']
        ocs = self._ffs['output_character_set']

        fmt, pt = fmtInput(pt, pth, ics, ocs)

        ct = self._algo.Encrypt(pt, twk)

        ct = strConvertRadix(ct, ics, ocs)
        ct = encKeyNumber(ct, ocs,
                          self._key['key_number'],
                          self._ffs['msb_encoding_bits'])
        return fmtOutput(fmt, ct, pth)

def Encrypt(creds, ffs, pt, twk = None):
    return Encryption(creds, ffs).Cipher(pt, twk)
