#/usr/bin/env python3

import base64

from ..credentials import credentials


from .common import fmtInput, strConvertRadix, decKeyNumber, fmtOutput
from .common import fetchFFS, fetchKey
from ubiq_security_fpe import ff1

class Decryption:
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
        self._srsa = creds.secret_crypto_access_key

        self._ffs = fetchFFS(self._host, self._papi, self._sapi, ffs)

    def Cipher(self, ct, twk = None):
        pth = self._ffs['passthrough']
        ics = self._ffs['input_character_set']
        ocs = self._ffs['output_character_set']

        fmt, ct = fmtInput(ct, pth, ocs, ics)
        ct, n = decKeyNumber(ct, ocs, self._ffs['msb_encoding_bits'])
        if not hasattr(self, '_key') or self._key['key_number'] != n:
            self._key = fetchKey(self._host,
                                 self._papi, self._sapi, self._srsa,
                                 self._ffs['name'], n)
            if self._ffs['encryption_algorithm'] == 'FF1':
                self._ctx = ff1.Context(
                    self._key['unwrapped_data_key'],
                    base64.b64decode(self._ffs['tweak']),
                    self._ffs['tweak_min_len'], self._ffs['tweak_max_len'],
                    len(ics), ics)
            else:
                raise RuntimeError('unsupported algorithm: ' +
                                   self._ffs['encryption_algorithm'])
        ct = strConvertRadix(ct, ocs, ics)

        pt = self._ctx.Decrypt(ct, twk)

        return fmtOutput(fmt, pt, pth)

def Decrypt(creds, ffs, ct, twk = None):
    return Decryption(creds, ffs).Cipher(ct, twk)
