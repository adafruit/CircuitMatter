# Derived from https://github.com/tlsfuzzer/python-ecdsa
# SPDX-FileCopyrightText: Copyright (c) 2010 Brian Warner
# SPDX-FileCopyrightText: Copyright (c) 2024 Dan Halbert for Adafruit Industries
#
# SPDX-License-Identifier: MIT

"""
RFC 6979:
    Deterministic Usage of the Digital Signature Algorithm (DSA) and
    Elliptic Curve Digital Signature Algorithm (ECDSA)

    http://tools.ietf.org/html/rfc6979

Many thanks to Coda Hale for his implementation in Go language:
    https://github.com/codahale/rfc6979
"""

import hmac
from binascii import hexlify
from .util import number_to_string, number_to_string_crop


def bits2int(data, qlen):
    x = int(hexlify(data), 16)
    l = len(data) * 8

    if l > qlen:
        return x >> (l - qlen)
    return x


def bits2octets(data, order):
    z1 = bits2int(data, order.bit_length())
    z2 = z1 - order

    if z2 < 0:
        z2 = z1

    return number_to_string_crop(z2, order)


# https://tools.ietf.org/html/rfc6979#section-3.2
def generate_k(order, secexp, hash_func, data, retry_gen=0, extra_entropy=b""):
    """
    Generate the ``k`` value - the nonce for DSA.

    :param int order: order of the DSA generator used in the signature
    :param int secexp: secure exponent (private key) in numeric form
    :param hash_func: reference to the same hash function used for generating
        hash, like :py:class:`hashlib.sha1`
    :param bytes data: hash in binary form of the signing data
    :param int retry_gen: how many good 'k' values to skip before returning
    :param bytes extra_entropy: additional added data in binary form as per
        section-3.6 of rfc6979
    :rtype: int
    """

    qlen = order.bit_length()
    holen = hash_func().digest_size
    rolen = (qlen + 7) // 8
    bx = (
        number_to_string(secexp, order),
        bits2octets(data, order),
        extra_entropy,
    )

    # Step B
    v = b"\x01" * holen

    # Step C
    k = b"\x00" * holen

    # Step D

    k = hmac.new(k, digestmod=hash_func)
    k.update(v + b"\x00")
    for i in bx:
        k.update(i)
    k = k.digest()

    # Step E
    v = hmac.new(k, v, hash_func).digest()

    # Step F
    k = hmac.new(k, digestmod=hash_func)
    k.update(v + b"\x01")
    for i in bx:
        k.update(i)
    k = k.digest()

    # Step G
    v = hmac.new(k, v, hash_func).digest()

    # Step H
    while True:
        # Step H1
        t = b""

        # Step H2
        while len(t) < rolen:
            v = hmac.new(k, v, hash_func).digest()
            t += v

        # Step H3
        secret = bits2int(t, qlen)

        if 1 <= secret < order:
            if retry_gen <= 0:
                return secret
            retry_gen -= 1

        k = hmac.new(k, v + b"\x00", hash_func).digest()
        v = hmac.new(k, v, hash_func).digest()
