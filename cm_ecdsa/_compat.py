# SPDX-FileCopyrightText: Copyright (c) 2010 Brian Warner
# SPDX-FileCopyrightText: Copyright (c) 2024 Dan Halbert for Adafruit Industries
#
# SPDX-License-Identifier: MIT
#
# Derived from https://github.com/tlsfuzzer/python-ecdsa

import sys
import re
import binascii


def normalise_bytes(buffer_object):
    """Cast the input into array of bytes."""
    return memoryview(buffer_object).cast("B")

def remove_whitespace(text):
    """Removes all whitespace from passed in string"""
    return re.sub(r"\s+", "", text, flags=re.UNICODE)

def a2b_hex(val):
    try:
        return bytearray(binascii.a2b_hex(bytearray(val, "ascii")))
    except Exception as e:
        raise ValueError("base16 error: %s" % e)

# pylint: disable=invalid-name
# pylint is stupid here and doesn't notice it's a function, not
# constant
bytes_to_int = int.from_bytes
# pylint: enable=invalid-name

def int_to_bytes(val, length=None, byteorder="big"):
    """Convert integer to bytes."""
    if length is None:
        length = byte_length(val)
    return bytearray(val.to_bytes(length=length, byteorder=byteorder))


def byte_length(val):
    """Return number of bytes necessary to represent an integer."""
    length = val.bit_length()
    return (length + 7) // 8

def int2byte(i):
    return i.to_bytes(1, 'big')
