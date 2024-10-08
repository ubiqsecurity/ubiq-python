#!/usr/bin/env python3

import math
import sys
import typing

VALID_M2CRYPTO_VERSIONS = ['0.42.0', '0.41.0']    
from importlib.metadata import version, PackageNotFoundError
class InvalidLibraryVersionException(Exception):
    pass
     
# Check if M2Crypto on system. (Faster, but possible compatibility issues.)
try:
    m2_ver = version('M2Crypto')
    if m2_ver in VALID_M2CRYPTO_VERSIONS:
        from M2Crypto import EVP
        M2CRYPTO = True
    else:
        print(f'Version {m2_ver} is not supported by ubiq_security for Python. Defaulting to Cryptography.')
        raise InvalidLibraryVersionException()
except (ImportError, PackageNotFoundError, InvalidLibraryVersionException) as e :
    import cryptography.hazmat.primitives.ciphers as crypto
    M2CRYPTO = False


DEFAULT_ALPHABET: typing.Final[str] = '0123456789abcdefghijklmnopqrstuvwxyz'

class Context:
    def __init__(self,
                 key, twk,
                 maxtxtlen, mintwklen, maxtwklen,
                 radix, alpha):
        self.BLKSZ = (int)(16)
        self.key = key

        self.alg = None
        if len(key) == 16:
            self.alg = 'aes_128_cbc'
        elif len(key) == 24:
            self.alg = 'aes_192_cbc'
        elif len(key) == 32:
            self.alg = 'aes_256_cbc'
        if self.alg == None:
            raise RuntimeError('Key length invalid.')

        if radix < 2 or radix > len(alpha):
            raise RuntimeError('Unsupported radix or incompatible alphabet')

        self.alpha = alpha

        #
        # for both ff1 and ff3-1: radix**minlen >= 1000000
        #
        # therefore:
        #   minlen = ceil(log_radix(1000000))
        #          = ceil(log_10(1000000) / log_10(radix))
        #          = ceil(6 / log_10(radix))
        #
        mintxtlen = math.ceil(6 / math.log10(radix));
        if mintxtlen < 2 or mintxtlen > maxtxtlen:
            raise RuntimeError('Invalid text length bounds')

        if (mintwklen > maxtwklen or
            len(twk) < mintwklen or
            (maxtwklen > 0 and len(twk) > maxtwklen)):
            raise RuntimeError('Invalid tweak length or bounds')

        self.radix = radix

        self.mintxtlen = mintxtlen
        self.maxtxtlen = maxtxtlen
        self.mintwklen = mintwklen
        self.maxtwklen = maxtwklen

        self.twk = twk

    def PRF(self, buf):
        BLKSZ = self.BLKSZ

        if len(buf) % BLKSZ != 0:
            raise RuntimeError(
                'Plaintext length must be a multiple of ' +
                str(BLKSZ))

        if M2CRYPTO:
            cipher = EVP.Cipher(alg=self.alg, key=self.key, iv=bytearray(16), op=1)
            dst = cipher.update(buf)
        else:
            cipher = crypto.Cipher(crypto.algorithms.AES(self.key), crypto.modes.CBC(bytearray(16))).encryptor()
            dst = cipher.update(buf) + cipher.finalize()
        
        return dst[-BLKSZ:]

    def Ciph(self, buf):
        return self.PRF(buf[0:self.BLKSZ])

def StringToNumber(radix, alpha, s):
    p = 1
    n = 0
    for i in range(len(s)):
        x = alpha.index(s[len(s) - i - 1])
        n += x * p
        p *= radix
    return n

def NumberToString(radix, alpha, n, l = 1):
    s = ''
    while n:
        s = alpha[int(n % radix)] + s
        n //= radix
    while len(s) < l:
        s = alpha[0] + s
    return s
