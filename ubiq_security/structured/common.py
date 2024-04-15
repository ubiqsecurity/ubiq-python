#!/usr/bin/env python3

import base64
import http
import json
import requests
import urllib

from ..auth import http_auth
from .lib import ffx


import cryptography.hazmat.primitives as crypto
from cryptography.hazmat.backends import default_backend as crypto_backend

def strConvertRadix(s, ics, ocs):
    return ffx.NumberToString(len(ocs), ocs,
                              ffx.StringToNumber(len(ics), ics, s),
                              len(s))

def fmtInput(s, pth, ics, ocs):
    fmt = ''
    trm = ''
    for c in s:
        if c in pth:
            fmt += c
        else:
            fmt += ocs[0]
            if c in ics:
                trm += c
            else:
                raise RuntimeError('invalid input character')
    return fmt, trm

def encKeyNumber(s, ocs, n, sft):    
    return ocs[ocs.find(s[0]) + (int(n) << sft)] + s[1:]

def decKeyNumber(s, ocs, sft):
    charBuf = s[0]
    encoded_value = ocs.find(charBuf)
    key_num = encoded_value >> sft

    return ocs[encoded_value - (key_num << sft)] + s[1:], key_num

def fmtOutput(fmt, s, pth):
    o = ''
    for c in fmt:
        if c not in pth:
            o, s = o + s[0], s[1:]
        else:
            o += c

    if len(s) > 0:
        raise RuntimeError('mismatched format and output strings')

    return o

def fetchDataset(host, papi, sapi, dataset_name):
    if (not papi in fetchDataset.cache or
        not dataset_name in fetchDataset.cache[papi]):
        url = host + 'ffs'
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
        fetchDataset.cache[papi][dataset_name] = json.loads(resp.content.decode())

    return fetchDataset.cache[papi][dataset_name]
fetchDataset.cache = {}

def flushDataset(papi = None, dataset_name = None):
    if papi == None:
        fetchDataset.cache = {}
    elif papi in fetchDataset.cache:
        if dataset_name == None:
            del fetchDataset.cache[papi]
        elif dataset_name in fetchDataset.cache[papi]:
            del fetchDataset.cache[papi][dataset_name]

def fetchKey(host, papi, sapi, srsa, dataset_name, n = -1):
    if (not papi in fetchKey.cache or
        not dataset_name in fetchKey.cache[papi] or
        not n in fetchKey.cache[papi][dataset_name]):
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

        prvkey = crypto.serialization.load_pem_private_key(
            key['encrypted_private_key'].encode(), srsa.encode(),
            crypto_backend())

        key['unwrapped_data_key'] = prvkey.decrypt(
            base64.b64decode(key['wrapped_data_key']),
            crypto.asymmetric.padding.OAEP(
                mgf=crypto.asymmetric.padding.MGF1(
                    algorithm=crypto.hashes.SHA1()),
                algorithm=crypto.hashes.SHA1(),
                label=None))

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
            fetchKey.cache[papi][dataset_name][n] = key

        # also cache the key at its "real" identifier
        n = int(key['key_number'])
        fetchKey.cache[papi][dataset_name][n] = key

    return fetchKey.cache[papi][dataset_name][n]
fetchKey.cache = {}

def allKeysToNInCache(papi, dataset_name, n):
    present = True
    for i in range(0,n+1):
        present = present and (i in fetchKey.cache[papi][dataset_name])
    return present

def fetchAllKeys(host, papi, sapi, srsa, dataset_name):
    url=f"{host}fpe/def_keys?ffs_name={dataset_name}&papi={papi}"
    resp = requests.get(url, auth=http_auth(papi, sapi))

    if resp.status_code != http.HTTPStatus.OK:
        raise urllib.error.HTTPError(
            url, resp.status_code,
            http.HTTPStatus(resp.status_code).phrase,
            resp.headers, resp.content)
    keys = json.loads(resp.content.decode())

    if not papi in fetchKey.cache:
        fetchKey.cache[papi] = {}
    if not dataset_name in fetchKey.cache[papi]:
        fetchKey.cache[papi][dataset_name] = {}

    prvkey = crypto.serialization.load_pem_private_key(
        keys[dataset_name]['encrypted_private_key'].encode(), srsa.encode(),
        crypto_backend())
    
    for i, enc_key in enumerate(keys[dataset_name]['keys']):
        if i in fetchKey.cache[papi][dataset_name]:
            continue

        key = {
            'encrypted_private_key': keys[dataset_name]['encrypted_private_key'],
            'wrapped_data_key': enc_key
        }
        key['unwrapped_data_key'] = prvkey.decrypt(
            base64.b64decode(key['wrapped_data_key']),
            crypto.asymmetric.padding.OAEP(
                mgf=crypto.asymmetric.padding.MGF1(
                    algorithm=crypto.hashes.SHA1()),
                algorithm=crypto.hashes.SHA1(),
                label=None))
        fetchKey.cache[papi][dataset_name][i] = key

def fetchCurrentKeys(host, papi, sapi, srsa, dataset_name):
    fetchAllKeys(host, papi, sapi, srsa, dataset_name)

    return {key_num: key for key_num, key in sorted(fetchKey.cache[papi][dataset_name].items()) if key_num not in [-1]}

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
