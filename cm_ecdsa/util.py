# Derived from https://github.com/tlsfuzzer/python-ecdsa
# SPDX-FileCopyrightText: Copyright (c) 2010 Brian Warner
# SPDX-FileCopyrightText: Copyright (c) 2024 Dan Halbert for Adafruit Industries
#
# SPDX-License-Identifier: MIT

"""
This module includes some utility functions.

The methods most typically used are the sigencode and sigdecode functions
to be used with :func:`~ecdsa.keys.SigningKey.sign` and
:func:`~ecdsa.keys.VerifyingKey.verify`
respectively. See the :func:`sigencode_strings`, :func:`sigdecode_string`,
:func:`sigencode_der`, :func:`sigencode_strings_canonize`,
:func:`sigencode_string_canonize`, :func:`sigencode_der_canonize`,
:func:`sigdecode_strings`, :func:`sigdecode_string`, and
:func:`sigdecode_der` functions.
"""

import binascii
import math
import os
import sys

from cm_sha import sha256

from . import der
from ._compat import int2byte, normalise_bytes

# RFC5480:
#   The "unrestricted" algorithm identifier is:
#     id-ecPublicKey OBJECT IDENTIFIER ::= {
#       iso(1) member-body(2) us(840) ansi-X9-62(10045) keyType(2) 1 }

oid_ecPublicKey = (1, 2, 840, 10045, 2, 1)
encoded_oid_ecPublicKey = der.encode_oid(*oid_ecPublicKey)

# RFC5480:
# The ECDH algorithm uses the following object identifier:
#      id-ecDH OBJECT IDENTIFIER ::= {
#        iso(1) identified-organization(3) certicom(132) schemes(1)
#        ecdh(12) }

oid_ecDH = (1, 3, 132, 1, 12)

# RFC5480:
# The ECMQV algorithm uses the following object identifier:
#      id-ecMQV OBJECT IDENTIFIER ::= {
#        iso(1) identified-organization(3) certicom(132) schemes(1)
#        ecmqv(13) }

oid_ecMQV = (1, 3, 132, 1, 13)


def entropy_to_bits(ent_256):
    """Convert a bytestring to string of 0's and 1's"""
    return bin(int.from_bytes(ent_256, "big"))[2:].zfill(len(ent_256) * 8)


def bytes_needed(order):
    num_bits = order.bit_length()
    num_bytes = num_bits // 8
    if num_bits % 8 > 0:
        # Need another byte for less than a byte's worth of bits.
        num_bytes += 1
    return num_bytes


def randrange(order, entropy=None):
    """Return a random integer k such that 1 <= k < order, uniformly
    distributed across that range. Worst case should be a mean of 2 loops at
    (2**k)+2.

    Note that this function is not declared to be forwards-compatible: we may
    change the behavior in future releases. The entropy= argument (which
    should get a callable that behaves like os.urandom) can be used to
    achieve stability within a given release (for repeatable unit tests), but
    should not be used as a long-term-compatible key generation algorithm.
    """
    assert order > 1
    if entropy is None:
        entropy = os.urandom
    upper_2 = (order - 2).bit_length()
    upper_256 = upper_2 // 8 + 1
    while True:  # I don't think this needs a counter with bit-wise randrange
        ent_256 = entropy(upper_256)
        ent_2 = entropy_to_bits(ent_256)
        rand_num = int(ent_2[:upper_2], base=2) + 1
        if 0 < rand_num < order:
            return rand_num


def number_to_string (num, order):
    l = bytes_needed(order)
    fmt_str = "%0" + str(2 * l) + "x"
    string = binascii.unhexlify((fmt_str % num).encode())
    assert len(string) == l, (len(string), l)
    return string


def number_to_string_crop(num, order):
    l = bytes_needed(order)
    fmt_str = "%0" + str(2 * l) + "x"
    string = binascii.unhexlify((fmt_str % num).encode())
    return string[:l]


def string_to_number(string):
    return int(binascii.hexlify(string), 16)


def string_to_number_fixedlen(string, order):
    l = bytes_needed(order)
    assert len(string) == l, (len(string), l)
    return int(binascii.hexlify(string), 16)


def sigencode_strings(r, s, order):
    """
    Encode the signature to a pair of strings in a tuple

    Encodes signature into raw encoding (:term:`raw encoding`) with the
    ``r`` and ``s`` parts of the signature encoded separately.

    It's expected that this function will be used as a ``sigencode=`` parameter
    in :func:`ecdsa.keys.SigningKey.sign` method.

    :param int r: first parameter of the signature
    :param int s: second parameter of the signature
    :param int order: the order of the curve over which the signature was
        computed

    :return: raw encoding of ECDSA signature
    :rtype: tuple(bytes, bytes)
    """
    r_str = number_to_string(r, order)
    s_str = number_to_string(s, order)
    return (r_str, s_str)


def sigencode_string(r, s, order):
    """
    Encode the signature to raw format (:term:`raw encoding`)

    It's expected that this function will be used as a ``sigencode=`` parameter
    in :func:`ecdsa.keys.SigningKey.sign` method.

    :param int r: first parameter of the signature
    :param int s: second parameter of the signature
    :param int order: the order of the curve over which the signature was
        computed

    :return: raw encoding of ECDSA signature
    :rtype: bytes
    """
    # for any given curve, the size of the signature numbers is
    # fixed, so just use simple concatenation
    r_str, s_str = sigencode_strings(r, s, order)
    return r_str + s_str


def sigencode_der(r, s, order):
    """
    Encode the signature into the ECDSA-Sig-Value structure using :term:`DER`.

    Encodes the signature to the following :term:`ASN.1` structure::

        Ecdsa-Sig-Value ::= SEQUENCE {
            r       INTEGER,
            s       INTEGER
        }

    It's expected that this function will be used as a ``sigencode=`` parameter
    in :func:`ecdsa.keys.SigningKey.sign` method.

    :param int r: first parameter of the signature
    :param int s: second parameter of the signature
    :param int order: the order of the curve over which the signature was
        computed

    :return: DER encoding of ECDSA signature
    :rtype: bytes
    """
    return der.encode_sequence(der.encode_integer(r), der.encode_integer(s))


def sigencode_strings_canonize(r, s, order):
    """
    Encode the signature to a pair of strings in a tuple

    Encodes signature into raw encoding (:term:`raw encoding`) with the
    ``r`` and ``s`` parts of the signature encoded separately.

    Makes sure that the signature is encoded in the canonical format, where
    the ``s`` parameter is always smaller than ``order / 2``.
    Most commonly used in bitcoin.

    It's expected that this function will be used as a ``sigencode=`` parameter
    in :func:`ecdsa.keys.SigningKey.sign` method.

    :param int r: first parameter of the signature
    :param int s: second parameter of the signature
    :param int order: the order of the curve over which the signature was
        computed

    :return: raw encoding of ECDSA signature
    :rtype: tuple(bytes, bytes)
    """
    if s > order / 2:
        s = order - s
    return sigencode_strings(r, s, order)


def sigencode_string_canonize(r, s, order):
    """
    Encode the signature to raw format (:term:`raw encoding`)

    Makes sure that the signature is encoded in the canonical format, where
    the ``s`` parameter is always smaller than ``order / 2``.
    Most commonly used in bitcoin.

    It's expected that this function will be used as a ``sigencode=`` parameter
    in :func:`ecdsa.keys.SigningKey.sign` method.

    :param int r: first parameter of the signature
    :param int s: second parameter of the signature
    :param int order: the order of the curve over which the signature was
        computed

    :return: raw encoding of ECDSA signature
    :rtype: bytes
    """
    if s > order / 2:
        s = order - s
    return sigencode_string(r, s, order)


def sigencode_der_canonize(r, s, order):
    """
    Encode the signature into the ECDSA-Sig-Value structure using :term:`DER`.

    Makes sure that the signature is encoded in the canonical format, where
    the ``s`` parameter is always smaller than ``order / 2``.
    Most commonly used in bitcoin.

    Encodes the signature to the following :term:`ASN.1` structure::

        Ecdsa-Sig-Value ::= SEQUENCE {
            r       INTEGER,
            s       INTEGER
        }

    It's expected that this function will be used as a ``sigencode=`` parameter
    in :func:`ecdsa.keys.SigningKey.sign` method.

    :param int r: first parameter of the signature
    :param int s: second parameter of the signature
    :param int order: the order of the curve over which the signature was
        computed

    :return: DER encoding of ECDSA signature
    :rtype: bytes
    """
    if s > order / 2:
        s = order - s
    return sigencode_der(r, s, order)


class MalformedSignature(Exception):
    """
    Raised by decoding functions when the signature is malformed.

    Malformed in this context means that the relevant strings or integers
    do not match what a signature over provided curve would create. Either
    because the byte strings have incorrect lengths or because the encoded
    values are too large.
    """

    pass


def sigdecode_string(signature, order):
    """
    Decoder for :term:`raw encoding`  of ECDSA signatures.

    raw encoding is a simple concatenation of the two integers that comprise
    the signature, with each encoded using the same amount of bytes depending
    on curve size/order.

    It's expected that this function will be used as the ``sigdecode=``
    parameter to the :func:`ecdsa.keys.VerifyingKey.verify` method.

    :param signature: encoded signature
    :type signature: bytes like object
    :param order: order of the curve over which the signature was computed
    :type order: int

    :raises MalformedSignature: when the encoding of the signature is invalid

    :return: tuple with decoded ``r`` and ``s`` values of signature
    :rtype: tuple of ints
    """
    signature = normalise_bytes(signature)
    l = bytes_needed(order)
    if not len(signature) == 2 * l:
        raise MalformedSignature(
            f"Invalid length of signature, expected {2 * l} bytes long, provided string is {len(signature)} bytes long"
        )
    r = string_to_number_fixedlen(signature[:l], order)
    s = string_to_number_fixedlen(signature[l:], order)
    return r, s


def sigdecode_strings(rs_strings, order):
    """
    Decode the signature from two strings.

    First string needs to be a big endian encoding of ``r``, second needs to
    be a big endian encoding of the ``s`` parameter of an ECDSA signature.

    It's expected that this function will be used as the ``sigdecode=``
    parameter to the :func:`ecdsa.keys.VerifyingKey.verify` method.

    :param list rs_strings: list of two bytes-like objects, each encoding one
        parameter of signature
    :param int order: order of the curve over which the signature was computed

    :raises MalformedSignature: when the encoding of the signature is invalid

    :return: tuple with decoded ``r`` and ``s`` values of signature
    :rtype: tuple of ints
    """
    if not len(rs_strings) == 2:
        raise MalformedSignature(
            f"Invalid number of strings provided: {len(rs_strings)}, expected 2"
        )
    (r_str, s_str) = rs_strings
    r_str = normalise_bytes(r_str)
    s_str = normalise_bytes(s_str)
    l = bytes_needed(order)
    if not len(r_str) == l:
        raise MalformedSignature(
            "Invalid length of first string ('r' parameter), "
            f"expected {l} bytes long, provided string is {len(r_str)} "
            "bytes long"
        )
    if not len(s_str) == l:
        raise MalformedSignature(
            "Invalid length of second string ('s' parameter), "
            f"expected {l} bytes long, provided string is {len(s_str)} "
            "bytes long"
        )
    r = string_to_number_fixedlen(r_str, order)
    s = string_to_number_fixedlen(s_str, order)
    return r, s


def sigdecode_der(sig_der, order):
    """
    Decoder for DER format of ECDSA signatures.

    DER format of signature is one that uses the :term:`ASN.1` :term:`DER`
    rules to encode it as a sequence of two integers::

        Ecdsa-Sig-Value ::= SEQUENCE {
            r       INTEGER,
            s       INTEGER
        }

    It's expected that this function will be used as as the ``sigdecode=``
    parameter to the :func:`ecdsa.keys.VerifyingKey.verify` method.

    :param sig_der: encoded signature
    :type sig_der: bytes like object
    :param order: order of the curve over which the signature was computed
    :type order: int

    :raises UnexpectedDER: when the encoding of signature is invalid

    :return: tuple with decoded ``r`` and ``s`` values of signature
    :rtype: tuple of ints
    """
    sig_der = normalise_bytes(sig_der)
    # return der.encode_sequence(der.encode_integer(r), der.encode_integer(s))
    rs_strings, empty = der.remove_sequence(sig_der)
    if empty != b"":
        raise der.UnexpectedDER("trailing junk after DER sig: %s" % binascii.hexlify(empty))
    r, rest = der.remove_integer(rs_strings)
    s, empty = der.remove_integer(rest)
    if empty != b"":
        raise der.UnexpectedDER("trailing junk after DER numbers: %s" % binascii.hexlify(empty))
    return r, s


def int2byte(i):
    return i.to_bytes(1, "big")
