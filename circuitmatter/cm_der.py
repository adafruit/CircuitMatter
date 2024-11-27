# Derived from https://github.com/tlsfuzzer/python-ecdsa
# SPDX-FileCopyrightText: Copyright (c) 2010 Brian Warner
# SPDX-FileCopyrightText: Copyright (c) 2024 Dan Halbert for Adafruit Industries
#
# SPDX-License-Identifier: MIT

import binascii


def int2byte(i):
    return i.to_bytes(1, "big")


def encode_constructed(tag, value):
    return int2byte(0xA0 + tag) + encode_length(len(value)) + value


def encode_integer(r):
    assert r >= 0  # can't support negative numbers yet
    h = f"{r:x}".encode()
    if len(h) % 2:
        h = b"0" + h
    s = binascii.unhexlify(h)
    num = s[0]
    if num <= 0x7F:
        return b"\x02" + encode_length(len(s)) + s
    else:
        # DER integers are two's complement, so if the first byte is
        # 0x80-0xff then we need an extra 0x00 byte to prevent it from
        # looking negative.
        return b"\x02" + encode_length(len(s) + 1) + b"\x00" + s


def encode_bitstring(s, *, unused):
    """
    Encode a binary string as a BIT STRING using :term:`DER` encoding.

    Note, because there is no native Python object that can encode an actual
    bit string, this function only accepts byte strings as the `s` argument.
    The byte string is the actual bit string that will be encoded, padded
    on the right (least significant bits, looking from big endian perspective)
    to the first full byte. If the bit string has a bit length that is multiple
    of 8, then the padding should not be included. For correct DER encoding
    the padding bits MUST be set to 0.

    Number of bits of padding need to be provided as the `unused` parameter.
    In case they are specified as None, it means the number of unused bits
    is already encoded in the string as the first byte.

    Empty string must be encoded with `unused` specified as 0.

    :param s: bytes to encode
    :type s: bytes like object
    :param unused: number of bits at the end of `s` that are unused, must be
        between 0 and 7 (inclusive)
    :type unused: int or None

    :raises ValueError: when `unused` is too large or too small

    :return: `s` encoded using DER
    :rtype: bytes
    """
    encoded_unused = b""
    len_extra = 0
    if not 0 <= unused <= 7:
        raise ValueError("unused must be integer between 0 and 7")
    if unused:
        if not s:
            raise ValueError("unused is non-zero but s is empty")
        last = s[-1]
        if last & (2**unused - 1):
            raise ValueError("unused bits must be zeros in DER")
    encoded_unused = int2byte(unused)
    len_extra = 1
    return b"\x03" + encode_length(len(s) + len_extra) + encoded_unused + s


def encode_octet_string(s):
    return b"\x04" + encode_length(len(s)) + s


def encode_oid(first, second, *pieces):
    assert 0 <= first < 2 and 0 <= second <= 39 or first == 2 and 0 <= second
    body = bytearray(encode_number(40 * first + second))
    for p in pieces:
        body += encode_number(p)
    return b"\x06" + encode_length(len(body)) + body


def encode_sequence(*encoded_pieces):
    total_len = sum([len(p) for p in encoded_pieces])
    return b"\x30" + encode_length(total_len) + b"".join(encoded_pieces)


def encode_number(n):
    b128_digits = []
    while n:
        b128_digits.insert(0, (n & 0x7F) | 0x80)
        n >>= 7
    if not b128_digits:
        b128_digits.append(0)
    b128_digits[-1] &= 0x7F
    return b"".join([int2byte(d) for d in b128_digits])


def encode_length(l):
    assert l >= 0
    if l < 0x80:
        return int2byte(l)
    s = f"{l:x}".encode()
    if len(s) % 2:
        s = b"0" + s
    s = binascii.unhexlify(s)
    llen = len(s)
    return int2byte(0x80 | llen) + s
