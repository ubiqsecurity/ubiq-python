#/usr/bin/env python3

import base64
from .lib import ff1

from ..credentials import credentials

from .common import fmtInput, strConvertRadix, encKeyNumber, fmtOutput
from .common import fetchDataset, fetchKey, fetchCurrentKeys

class Encryption:
    def __del__(self):
        # todo: overwrite 'unwrapped_data_key'
        return

    def __init__(self, creds, dataset_name):
        if not creds.set():
            raise RuntimeError("credentials not set")
        
        self._creds = creds

        self._host = creds.host
        self._host += '/api/v0/'

        self._papi = creds.access_key_id
        self._sapi = creds.secret_signing_key
        self._srsa = creds.secret_crypto_access_key

        self._dataset = fetchDataset(self._creds, dataset_name)
        self._key = fetchKey(self._creds,
                             dataset_name)

        if self._dataset['encryption_algorithm'] == 'FF1':
            self._algo = ff1.Context(
                self._key['unwrapped_data_key'],
                base64.b64decode(self._dataset['tweak']),
                self._dataset['tweak_min_len'], self._dataset['tweak_max_len'],
                len(self._dataset['input_character_set']),
                self._dataset['input_character_set'])
        else:
            raise RuntimeError('unsupported algorithm: ' +
                               self._dataset['encryption_algorithm'])

    def Cipher(self, pt, twk = None):
        pth = self._dataset['passthrough']
        ics = self._dataset['input_character_set']
        ocs = self._dataset['output_character_set']
        rules = self._dataset.get('passthrough_rules', [])

        input_min = self._dataset['min_input_length']
        input_max = self._dataset['max_input_length']

        fmt, pt, rules = fmtInput(pt, pth, ics, ocs, rules)

        input_len = len(pt)
        if input_len < input_min or input_len > input_max:
            raise RuntimeError('Invalid input len (%s) min: %s max %s'%(input_len, input_min, input_max))

        ct = self._algo.Encrypt(pt, twk)

        ct = strConvertRadix(ct, ics, ocs)
        ct = encKeyNumber(ct, ocs,
                          self._key['key_number'],
                          self._dataset['msb_encoding_bits'])
        
        self._creds.add_event(dataset_name=self._dataset['name'], dataset_group_name="", billing_action="encrypt",
                dataset_type="structured", key_number=self._key['key_number'], count=1)
        
        return fmtOutput(fmt, ct, pth, rules)
    
    def CipherForSearch(self, pt, twk=None):
        keys = fetchCurrentKeys(self._creds,
                            self._dataset['name'])
        
        pth = self._dataset['passthrough']
        ics = self._dataset['input_character_set']
        ocs = self._dataset['output_character_set']
        rules = self._dataset.get('passthrough_rules', [])
        

        fmt, pt, rules = fmtInput(pt, pth, ics, ocs, rules)


        searchCipher = []
        for _, (key_num, key) in enumerate(keys.items()):
            algo = ff1.Context(
                key['unwrapped_data_key'],
                base64.b64decode(self._dataset['tweak']),
                self._dataset['tweak_min_len'], self._dataset['tweak_max_len'],
                len(ics),
                ics)
            ct = algo.Encrypt(pt, twk)
            ct = strConvertRadix(ct, ics, ocs)
            ct = encKeyNumber(ct, ocs,
                          key_num,
                          self._dataset['msb_encoding_bits'])
            searchCipher.append(fmtOutput(fmt, ct, pth, rules))

        return searchCipher



def Encrypt(creds, dataset_name, pt, twk = None):
    results = Encryption(creds, dataset_name).Cipher(pt, twk)
    if creds.configuration.get_event_reporting_synchronous():
        creds.process_events()
    return results

def EncryptForSearch(creds, dataset_name, pt, twk = None):
    result = Encryption(creds, dataset_name).CipherForSearch(pt, twk)
    if creds.configuration.get_event_reporting_synchronous():
        creds.process_events()
    return result
