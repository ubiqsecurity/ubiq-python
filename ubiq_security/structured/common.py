#!/usr/bin/env python3

import base64
import http
import json
import requests
import urllib
import time
import copy

from ..auth import http_auth
from .lib import ffx


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

def fetchDataset(creds, dataset_name):
    papi = creds.access_key_id
    sapi = creds.secret_signing_key
    host = creds.host
    
    config = creds.configuration
    ttl_seconds = config.key_caching_ttl_seconds
    unstructured_cache_enabled = config.key_caching_structured
    
    if (not unstructured_cache_enabled or
        not papi in fetchDataset.cache or
        not dataset_name in fetchDataset.cache[papi] or
        fetchDataset.cache[papi][dataset_name]["expires"] < time.time()):
        
        if config.logging_verbose:
            print('****** PERFORMING EXPENSIVE CALL ----- fetchDataset')
        
        url = host + '/api/v0/ffs'
        url += '?ffs_name=' + dataset_name
        url += '&papi=' + papi

        resp = requests.get(url, auth=http_auth(papi, sapi))
        if resp.status_code != http.HTTPStatus.OK:
            raise urllib.error.HTTPError(
                url, resp.status_code,
                http.HTTPStatus(resp.status_code).phrase,
                resp.headers, resp.content)
        if not papi in fetchDataset.cache:
            fetchDataset.cache[papi] = {}
        fetchDataset.cache[papi][dataset_name] = { "dataset" : json.loads(resp.content.decode()), "expires" : time.time() + ttl_seconds }

    return fetchDataset.cache[papi][dataset_name]["dataset"]
fetchDataset.cache = {}

def flushDataset(papi = None, dataset_name = None):
    if papi == None:
        fetchDataset.cache = {}
    elif papi in fetchDataset.cache:
        if dataset_name == None:
            del fetchDataset.cache[papi]
        elif dataset_name in fetchDataset.cache[papi]:
            del fetchDataset.cache[papi][dataset_name]
            
def add_to_fetchkey_cache(papi, dataset_name, n, key, ttl_seconds):
    cache_entry = { "key" : key, "expires": time.time() + ttl_seconds }
    
    if not papi in fetchKey.cache:
        fetchKey.cache[papi] = {}
    if not dataset_name in fetchKey.cache[papi]:
        fetchKey.cache[papi][dataset_name] = {}

    # the -1 entry points to the "current" key at the
    # server. it is cached so that the next caller that
    # wants the "current" key can get it, but it should
    # be timed-out occasionally in case the "current"
    # pointer changes at the server.
    #
    # that timeout is future work
    if n == -1:
        # -1 can be an index because keys are stored
        # in a dictionary, not a list
        fetchKey.cache[papi][dataset_name][n] = cache_entry

    # also cache the key at its "real" identifier
    n = int(key['key_number'])
    fetchKey.cache[papi][dataset_name][n] = cache_entry

def fetchKey(creds, dataset_name, n = -1):
    papi = creds.access_key_id
    sapi = creds.secret_signing_key
    srsa = creds.secret_crypto_access_key
    host = creds.host
    
    config = creds.configuration
    ttl_seconds = config.key_caching_ttl_seconds
    structured_cache_enabled = creds.configuration.key_caching_structured
    cache_encrypted = creds.configuration.key_caching_encrypt
    
    key = None
    
    if (not structured_cache_enabled or
        not papi in fetchKey.cache or
        not dataset_name in fetchKey.cache[papi] or
        not n in fetchKey.cache[papi][dataset_name] or
        fetchKey.cache[papi][dataset_name][n]["expires"] < time.time()):
        
        if config.logging_verbose:
            print('****** PERFORMING EXPENSIVE CALL ----- fetchKey')

        url = host + '/api/v0/fpe/key'
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
        
        if structured_cache_enabled and cache_encrypted:
            add_to_fetchkey_cache(papi, dataset_name, n, copy.deepcopy(key), ttl_seconds)
    else:
        key = fetchKey.cache[papi][dataset_name][n]["key"]
    
    if key != None and not 'unwrapped_data_key' in key:
        prvkey = serialize.load_pem_private_key(
            key['encrypted_private_key'].encode(), srsa.encode(),
            crypto_backend())

        key['unwrapped_data_key'] = prvkey.decrypt(
            base64.b64decode(key['wrapped_data_key']),
            crypto.asymmetric.padding.OAEP(
                mgf=crypto.asymmetric.padding.MGF1(
                    algorithm=crypto.hashes.SHA1()),
                algorithm=crypto.hashes.SHA1(),
                label=None))

        if structured_cache_enabled and not cache_encrypted:
            add_to_fetchkey_cache(papi, dataset_name, n, copy.deepcopy(key), ttl_seconds)
    return key
fetchKey.cache = {}

def allKeysToNInCache(papi, dataset_name, n):
    present = True
    for i in range(0,n+1):
        present = present and (i in fetchKey.cache[papi][dataset_name])
    return present

def fetchAllKeys(creds, dataset_name):
    papi = creds.access_key_id
    sapi = creds.secret_signing_key
    srsa = creds.secret_crypto_access_key
    host = creds.host
    
    config = creds.configuration
    ttl_seconds = config.key_caching_ttl_seconds
    structured_cache_enabled = config.key_caching_structured
    cache_encrypted = config.key_caching_encrypt
    
    if config.logging_verbose:
        print('****** PERFORMING EXPENSIVE CALL ----- fetchAllKeys')
    
    url=f"{host}/api/v0/fpe/def_keys?ffs_name={dataset_name}&papi={papi}"
    resp = requests.get(url, auth=http_auth(papi, sapi))
    
    all_keys = {}

    if resp.status_code != http.HTTPStatus.OK:
        raise urllib.error.HTTPError(
            url, resp.status_code,
            http.HTTPStatus(resp.status_code).phrase,
            resp.headers, resp.content)
    keys = json.loads(resp.content.decode())

    if structured_cache_enabled:
        if not papi in fetchKey.cache:
            fetchKey.cache[papi] = {}
        if not dataset_name in fetchKey.cache[papi]:
            fetchKey.cache[papi][dataset_name] = {}

    prvkey = serialize.load_pem_private_key(
        keys[dataset_name]['encrypted_private_key'].encode(), srsa.encode(),
        crypto_backend())
    
    for i, enc_key in enumerate(keys[dataset_name]['keys']):
        if (structured_cache_enabled and # Cache is Enabled
            i in fetchKey.cache[papi][dataset_name] and # Key in cache
            fetchKey.cache[papi][dataset_name][i]["expires"] > time.time()): # Cache isnt expired
            key = fetchKey.cache[papi][dataset_name][i]["key"]
            
            if 'unwrapped_data_key' in key:
                all_keys[i] = key
                continue

        key = {
            'encrypted_private_key': keys[dataset_name]['encrypted_private_key'],
            'wrapped_data_key': enc_key,
            'key_number': i
        }
        
        # Store cache encrpypted (don't store unwrapped)
        if structured_cache_enabled and cache_encrypted:
            cache_entry = { "key" : key, "expires": time.time() + ttl_seconds }
            fetchKey.cache[papi][dataset_name][i] = cache_entry
        
        key['unwrapped_data_key'] = prvkey.decrypt(
            base64.b64decode(key['wrapped_data_key']),
            crypto.asymmetric.padding.OAEP(
                mgf=crypto.asymmetric.padding.MGF1(
                    algorithm=crypto.hashes.SHA1()),
                algorithm=crypto.hashes.SHA1(),
                label=None))
        
        # Store cache unencrypted
        if structured_cache_enabled and not cache_encrypted: 
            cache_entry = { "key" : key, "expires": time.time() + ttl_seconds }
            fetchKey.cache[papi][dataset_name][i] = cache_entry

        all_keys[i] = key

    return all_keys

def fetchCurrentKeys(creds, dataset_name):
    return fetchAllKeys(creds, dataset_name)


def flushKey(papi = None, dataset_name = None, n = None):
    if papi == None:
        fetchKey.cache = {}
    elif papi in fetchKey.cache:
        if dataset_name == None:
            del fetchKey.cache[papi]
        elif dataset_name in fetchKey.cache[papi]:
            if n == None:
                del fetchKey.cache[papi][dataset_name]
            elif n in fetchKey.cache[papi][dataset_name]:
                del fetchKey.cache[papi][dataset_name][n]
