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
import cryptography.hazmat.backends
import cryptography.hazmat.primitives.hashes
import cryptography.hazmat.primitives.hmac
import email.utils
import http.client
import requests.auth
import time
import urllib.parse

class http_auth(requests.auth.AuthBase):
    """HTTP Authentication for the Ubiq Platform

    This module implements HTTP authentication for the Ubiq platform
    via message signing as described by the IETF httpbis-message-signatures
    draft specification.

    The module is intended to be used in conjunction with the `requests`
    library as in `requests.get(url, auth=http_auth(id, key))`.
    """

    def __init__(self, access_id, access_key):
        """
        access_id:
            a string containing the client's public API key (pAPI)
        access_key:
            a string containing the client's secret API key (sAPI)
        """

        self.access_id = access_id
        self.access_key = access_key

    def __call__(self, r):
        """
        The `requests` library calls this function prior to sending
        the HTTP request out over the network. This function calculates
        the signature for the message, adding the Signature header
        to contain the data. Certain HTTP headers are required for
        signature calculation and will be added by this code as
        necessary. The modified request is returned.
        """

        # the '(request-target)' is part of the signed data.
        # it's value is 'http_method path?query'

        parsed = urllib.parse.urlparse(r.url)
        r.headers['Content-type'] = 'application/json'
        req_tgt = r.method.lower() + ' ' + parsed.path
        if parsed.query:
            req_tgt += '?' + parsed.query

        # the time at which the signature was created
        # expressed as the unix epoch

        created = str(int(time.time()))

        # the requests library doesn't typically add the Host
        # header. it needs to be present to be part of the
        # signature. the port value is not included if it is
        # the default port for the scheme

        if not r.headers.get('Host'):
            r.headers['Host'] = parsed.hostname
            if parsed.port:
                if ((parsed.scheme == 'http' and
                     parsed.port != http.client.HTTP_PORT) or
                    (parsed.scheme == 'https' and
                     parsed.port != http.client.HTTPS_PORT)):
                    r.headers['Host'] += ':' + str(parsed.port)

        # the Date field is required for the signature

        if not r.headers.get('Date'):
            r.headers['Date'] = email.utils.formatdate(
                timeval=None, localtime=False, usegmt=True)

        # the Digest header is always included/overridden by
        # this code. it is a hash of the body of the http message
        # and is always present even if the body is empty

        hash_sha512 = cryptography.hazmat.primitives.hashes.Hash(
            cryptography.hazmat.primitives.hashes.SHA512(),
            backend=cryptography.hazmat.backends.default_backend())
        if r.body:
            hash_sha512.update(r.body)
        r.headers['Digest']  = 'SHA-512='
        r.headers['Digest'] += base64.b64encode(
            hash_sha512.finalize()).decode('utf-8')

        #
        # sign the message. the signature is an hmac of the
        # headers listed below
        #

        hmac_sha512 = cryptography.hazmat.primitives.hmac.HMAC(
            self.access_key.encode('utf-8'),
            cryptography.hazmat.primitives.hashes.SHA512(),
            backend=cryptography.hazmat.backends.default_backend())

        headers = []

        # the (request-target) and (created) are faux headers defined
        # by the message signature spec. they are added to the list
        # of "real" headers to make the code below simpler and then
        # removed from the request after the hmac has been updated

        r.headers['(request-target)'] = req_tgt
        r.headers['(created)'] = created

        # include the specified headers in the hmac calculation. each
        # header is of the form 'header_name: header value\n'
        #
        # included headers are also added to an ordered list of headers
        # which is included in the message

        for name in ['(created)',
                     '(request-target)',
                     'Content-Length',
                     'Content-Type',
                     'Date',
                     'Digest',
                     'Host']:
            if r.headers.get(name):
                headers.append(name.lower())
                hmac_sha512.update(
                    (name.lower() + ': ' + r.headers[name] + '\n').
                    encode('utf-8'))

        del r.headers['(created)']
        del r.headers['(request-target)']

        # build the Signature header itself

        r.headers['Signature']  = 'keyId="' + self.access_id + '"'
        r.headers['Signature'] += ', algorithm="hmac-sha512"'
        r.headers['Signature'] += ', created=' + created
        r.headers['Signature'] += ', headers="' + ' '.join(headers) + '"'
        r.headers['Signature'] += ', signature="'
        r.headers['Signature'] += base64.b64encode(
            hmac_sha512.finalize()).decode('utf-8')
        r.headers['Signature'] += '"'

        return r
