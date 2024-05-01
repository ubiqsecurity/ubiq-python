#!/usr/bin/env python3

import math

from . import ffx

class Context:
    def __init__(self,
                 key, twk,
                 mintwklen, maxtwklen,
                 radix, alpha = ffx.DEFAULT_ALPHABET):
        self.ffx = ffx.Context(key, twk,
                               2**32,
                               mintwklen, maxtwklen,
                               radix, alpha)

    def cipher(self, X, T, ENC):
        BLKSZ = self.ffx.BLKSZ

        n = len(X)
        u = int(n / 2)
        v = n - u

        b = int((math.ceil(math.log2(self.ffx.radix) * v) + 7) / 8)
        d = 4 * int((b + 3) / 4) + 4

        R = bytearray([0] * int((d + (BLKSZ - 1)) / BLKSZ) * BLKSZ)

        if T == None:
            T = self.ffx.twk
        if T == None:
            T = bytes([])

        if (n < self.ffx.mintxtlen or
            n > self.ffx.maxtxtlen or
            len(T) < self.ffx.mintwklen or
            (self.ffx.maxtwklen > 0 and
             len(T) > self.ffx.maxtwklen)):
            raise RuntimeError('Input or tweak length error')

        PQ = bytearray(
            [0] * (BLKSZ + int((len(T) + b + 1 + 15) / BLKSZ) * BLKSZ))

        # initialize the P portion of PQ
        PQ[:8] = [1, 2, 1,
                  self.ffx.radix >> 16 & 0xff,
                  self.ffx.radix >> 8 & 0xff,
                  self.ffx.radix & 0xff,
                  10, u & 0xff]
        PQ[8:12] = n.to_bytes(4, byteorder='big')
        PQ[12:16] = len(T).to_bytes(4, byteorder='big')

        # initialize the constant portion of Q
        PQ[BLKSZ:BLKSZ + len(T)] = T

        nA = ffx.StringToNumber(self.ffx.radix, self.ffx.alpha, X[:u])
        nB = ffx.StringToNumber(self.ffx.radix, self.ffx.alpha, X[u:])
        if not ENC:
            nA, nB = nB, nA

        mU = self.ffx.radix ** u
        mV = mU
        if u != v:
            mV *= self.ffx.radix

        for i in range(10):
            if ENC:
                PQ[-b - 1] = i
            else:
                PQ[-b - 1] = 9 - i

            PQ[-b:] = nB.to_bytes(b, byteorder='big')

            R[:BLKSZ] = self.ffx.PRF(PQ)

            for j in range(int(len(R) / BLKSZ) - 1):
                w = int.from_bytes(R[12:BLKSZ], byteorder='big')

                R[12:BLKSZ] = (w ^ (j + 1)).to_bytes(4, byteorder='big')
                R[BLKSZ * (j + 1):BLKSZ * (j + 2)] = self.ffx.Ciph(R)
                R[12:BLKSZ] = w.to_bytes(4, byteorder='big')

            y = int.from_bytes(R[:d], byteorder='big')
            if ENC:
                y = nA + y
            else:
                y = nA - y

            nA, nB = nB, nA

            if int(ENC) == i % 2:
                nB = y % mV
            else:
                nB = y % mU

        if not ENC:
            nA, nB = nB, nA

        return (ffx.NumberToString(self.ffx.radix, self.ffx.alpha, nA, u) +
                ffx.NumberToString(self.ffx.radix, self.ffx.alpha, nB, v))

    def Encrypt(self, pt, twk = None):
        return self.cipher(pt, twk, True)

    def Decrypt(self, ct, twk = None):
        return self.cipher(ct, twk, False)
