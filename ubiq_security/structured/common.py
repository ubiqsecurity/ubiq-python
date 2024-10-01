#!/usr/bin/env python3

import base64
import http
import json
import requests
import urllib

from ..auth import http_auth
from .lib import ffx
from ..caching import encryptable_keycache, config_cache, decrypt_key, CONFIG

import cryptography.hazmat.primitives as crypto
import cryptography.hazmat.primitives.serialization as serialize 
from cryptography.hazmat.backends import default_backend as crypto_backend


def strConvertRadix(s, ics, ocs):
    return ffx.NumberToString(len(ocs), ocs,
                              ffx.StringToNumber(len(ics), ics, s),
                              len(s))

def fmtInput(s, pth, ics, ocs, rules = []):
    fmt = ''
    trm = '%s'%(s)
    
    # Check if there's a passthrough rule. If not, create for legacy passthrough.
    if not any(rule.get('type') == 'passthrough' for rule in rules):
        rules.insert(0, {'type': 'passthrough', 'value': pth, 'priority': 1})
        
    # Sort the rules by priority
    rules.sort(key=lambda x: x['priority'])
    for idx, rule in enumerate(rules):
        if(rule['type'] == 'passthrough'):
            pth = rule['value']
            o = ''
            for c in trm:
                if c in pth:
                    fmt += c
                else:
                    fmt += ocs[0]
                    o += c
            trm = o
        elif(rule['type'] == 'prefix'):
            rules[idx]['buffer'] = trm[:rule['value']]
            trm = trm[rule['value']:]
        elif(rule['type'] == 'suffix'):
            rules[idx]['buffer'] = trm[(-1 * rule['value']):]
            trm = trm[:(-1 * rule['value'])]
        else:
            raise RuntimeError('Ubiq Python Library does not support rule type "%s" at this time.'%(rule['type']))

    # Validate final string contains only allowed characters.
    if not all((c in ics) for c in trm):
        raise RuntimeError('Invalid input string character(s)')

    return fmt, trm, rules

def encKeyNumber(s, ocs, n, sft):    
    return ocs[ocs.find(s[0]) + (int(n) << sft)] + s[1:]

def decKeyNumber(s, ocs, sft):
    charBuf = s[0]
    encoded_value = ocs.find(charBuf)
    key_num = encoded_value >> sft

    return ocs[encoded_value - (key_num << sft)] + s[1:], key_num

def fmtOutput(fmt, s, pth, rules):
    # Sort the rules by decreasing priority
    rules.sort(key=lambda x: x['priority'], reverse=True)

    for rule in rules:
        if(rule['type'] == 'passthrough'):
            o = ''
            for c in fmt:
                if c not in pth:
                    o, s = o + s[0], s[1:]
                else:
                    o += c
                
            if len(s) > 0:
                raise RuntimeError('mismatched format and output strings')
            s = o
        elif(rule['type'] == 'prefix'):
            s = rule['buffer'] + s
        elif(rule['type'] == 'suffix'):
            s = s + rule['buffer']
        else:
            raise RuntimeError('Ubiq Python Library does not support rule type "%s" at this time.'%(rule['type']))

    return s

@config_cache(maxsize=100, ttl=CONFIG.get_key_caching_ttl_seconds(), enable_cache=CONFIG.get_key_caching_structured())
def fetchDataset(host, papi, sapi, dataset_name):
    url = host + 'ffs'
    url += '?ffs_name=' + dataset_name
    url += '&papi=' + papi
    resp = requests.get(url, auth=http_auth(papi, sapi))
    if resp.status_code != http.HTTPStatus.OK:
        raise urllib.error.HTTPError(
            url, resp.status_code,
            http.HTTPStatus(resp.status_code).phrase,
            resp.headers, resp.content)

    return json.loads(resp.content.decode())

def flushDataset(papi = None, dataset_name = None):
    # deprecated with new cache tool.
    # use fetchDataset.cache_clear() instead to nuke the cache.
    if hasattr(fetchDataset, 'cache'):
        fetchDataset.cache.clear_cache()
    pass

@encryptable_keycache(maxsize=100, ttl=CONFIG.get_key_caching_ttl_seconds(), enable_cache=CONFIG.get_key_caching_structured(), encrypted=CONFIG.get_key_caching_encrypt())
def fetchKey(host, papi, sapi, srsa, dataset_name, n = -1):
    if CONFIG.get_logging_verbose():
        print(f'****** PERFORMING EXPENSIVE CALL ----- fetchKey for dataset {dataset_name}')
    url = host + 'fpe/key'
    url += '?ffs_name=' + dataset_name
    url += '&papi=' + papi
    if n >= 0:
        url += '&key_number=' + str(n)
    resp = requests.get(url, auth=http_auth(papi, sapi))
    if resp.status_code != http.HTTPStatus.OK:
        raise urllib.error.HTTPError(
            url, resp.status_code,
            http.HTTPStatus(resp.status_code).phrase,
            resp.headers, resp.content)
    key = json.loads(resp.content.decode())

    return decrypt_key(key, srsa)

def allKeysToNInCache(papi, dataset_name, n):
    present = True
    for i in range(0,n+1):
        present = present and (i in fetchKey.cache[papi][dataset_name])
    return present

def fetchAllKeys(host, papi, sapi, srsa, dataset_name):
    if CONFIG.get_logging_verbose():
        print(f'****** PERFORMING EXPENSIVE CALL ----- fetchAllKeys for dataset {dataset_name}')

    url=f"{host}fpe/def_keys?ffs_name={dataset_name}&papi={papi}"
    resp = requests.get(url, auth=http_auth(papi, sapi))

    if resp.status_code != http.HTTPStatus.OK:
        raise urllib.error.HTTPError(
            url, resp.status_code,
            http.HTTPStatus(resp.status_code).phrase,
            resp.headers, resp.content)
    keys = json.loads(resp.content.decode())

    prvkey = serialize.load_pem_private_key(
        keys[dataset_name]['encrypted_private_key'].encode(), srsa.encode(),
        crypto_backend())
    
    all_keys = {}
    for i, enc_key in enumerate(keys[dataset_name]['keys']):
        if hasattr(fetchKey, 'cache') and (host, papi, sapi, srsa, dataset_name, i) in fetchKey.cache:
            continue

        key = {
            'encrypted_private_key': keys[dataset_name]['encrypted_private_key'],
            'key_number': i,
            'wrapped_data_key': enc_key
        }
        key['unwrapped_data_key'] = prvkey.decrypt(
            base64.b64decode(key['wrapped_data_key']),
            crypto.asymmetric.padding.OAEP(
                mgf=crypto.asymmetric.padding.MGF1(
                    algorithm=crypto.hashes.SHA1()),
                algorithm=crypto.hashes.SHA1(),
                label=None))
        all_keys[i] = key
        if hasattr(fetchKey, 'cache'):
            fetchKey.cache.__setitem__((host, papi, sapi, srsa, dataset_name, i), key)
    return all_keys

@config_cache(maxsize=1, ttl=CONFIG.get_key_caching_ttl_seconds(), enable_cache=CONFIG.get_key_caching_structured())
def fetchCurrentKeys(host, papi, sapi, srsa, dataset_name):
    keys = fetchAllKeys(host, papi, sapi, srsa, dataset_name)
    
    return keys

def flushKey(papi = None, dataset_name = None, n = None):
    if hasattr(fetchKey, 'cache'):
        fetchKey.cache.clear_cache()
    pass
