#/usr/bin/env python3

import base64

from ..credentials import credentials


from .common import fmtInput, strConvertRadix, decKeyNumber, fmtOutput
from .common import fetchDataset, fetchKey
from .lib import ff1

class Decryption:
    def __del__(self):
        # todo: overwrite 'unwrapped_data_key'
        return

    def __init__(self, creds, dataset_name):
        if not creds.set():
            raise RuntimeError("credentials not set")
        
        self._creds = creds

        # If the host does not begin with either http or https
        # insert https://
        self._host = creds.host
        if (not self._host.lower().startswith('http')):
            self._host = "https://" + self._host
        self._host += '/api/v0/'

        self._papi = creds.access_key_id
        self._sapi = creds.secret_signing_key
        self._srsa = creds.secret_crypto_access_key

        self._dataset = fetchDataset(self._host, self._papi, self._sapi, dataset_name)

    def Cipher(self, ct, twk = None):
        pth = self._dataset['passthrough']
        ics = self._dataset['input_character_set']
        ocs = self._dataset['output_character_set']
        rules = self._dataset.get('passthrough_rules', [])

        input_min = self._dataset['min_input_length']
        input_max = self._dataset['max_input_length']
        
        fmt, ct, rules = fmtInput(ct, pth, ocs, ics, rules)

        input_len = len(ct)
        if input_len < input_min or input_len > input_max:
            raise RuntimeError('Invalid input len (%s) min: %s max %s'%(input_len, input_min, input_max))

        ct, n = decKeyNumber(ct, ocs, self._dataset['msb_encoding_bits'])
        if not hasattr(self, '_key') or self._key['key_number'] != n:
            self._key = fetchKey(self._host,
                                 self._papi, self._sapi, self._srsa,
                                 self._dataset['name'], n)
            if self._dataset['encryption_algorithm'] == 'FF1':
                self._ctx = ff1.Context(
                    self._key['unwrapped_data_key'],
                    base64.b64decode(self._dataset['tweak']),
                    self._dataset['tweak_min_len'], self._dataset['tweak_max_len'],
                    len(ics), ics)
            else:
                raise RuntimeError('unsupported algorithm: ' +
                                   self._dataset['encryption_algorithm'])
        ct = strConvertRadix(ct, ocs, ics)

        pt = self._ctx.Decrypt(ct, twk)

        self._creds.add_event(dataset_name=self._dataset['name'], dataset_group_name="", billing_action="decrypt",
            dataset_type="structured", key_number=n, count=1)
        return fmtOutput(fmt, pt, pth, rules)

def Decrypt(creds, dataset_name, ct, twk = None):
    return Decryption(creds, dataset_name).Cipher(ct, twk)
