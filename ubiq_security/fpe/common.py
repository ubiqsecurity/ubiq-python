#!/usr/bin/env python3

import base64
import http
import json
import requests
import urllib

from ..auth import http_auth

from .algo import ffx

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

def fetchFFS(host, papi, sapi, ffs):
    if (not papi in fetchFFS.cache or
        not ffs in fetchFFS.cache[papi]):
        url = host + 'ffs'
        url += '?ffs_name=' + ffs
        url += '&papi=' + papi
        resp = requests.get(url, auth=http_auth(papi, sapi))
        if resp.status_code != http.HTTPStatus.OK:
            raise urllib.error.HTTPError(
                url, resp.status_code,
                http.HTTPStatus(resp.status_code).phrase,
                resp.headers, resp.content)
        if not papi in fetchFFS.cache:
            fetchFFS.cache[papi] = {}
        fetchFFS.cache[papi][ffs] = json.loads(resp.content.decode())

    return fetchFFS.cache[papi][ffs]
fetchFFS.cache = {}

def flushFFS(papi = None, ffs = None):
    if papi == None:
        fetchFFS.cache = {}
    elif papi in fetchFFS.cache:
        if ffs == None:
            del fetchFFS.cache[papi]
        elif ffs in fetchFFS.cache[papi]:
            del fetchFFS.cache[papi][ffs]

def fetchKey(host, papi, sapi, srsa, ffs, n = -1):
    if (not papi in fetchKey.cache or
        not ffs in fetchKey.cache[papi] or
        not n in fetchKey.cache[papi][ffs]):
        url = host + 'fpe/key'
        url += '?ffs_name=' + ffs
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
        if not ffs in fetchKey.cache[papi]:
            fetchKey.cache[papi][ffs] = {}

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
            fetchKey.cache[papi][ffs][n] = key

        # also cache the key at its "real" identifier
        n = int(key['key_number'])
        fetchKey.cache[papi][ffs][n] = key

    return fetchKey.cache[papi][ffs][n]
fetchKey.cache = {}

def flushKey(papi = None, ffs = None, n = None):
    if papi == None:
        fetchKey.cache = {}
    elif papi in fetchKey.cache:
        if ffs == None:
            del fetchKey.cache[papi]
        elif ffs in fetchKey.cache[papi]:
            if n == None:
                del fetchKey.cache[papi][ffs]
            elif n in fetchKey.cache[papi][ffs]:
                del fetchKey.cache[papi][ffs][n]
