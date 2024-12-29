# SPDX-FileCopyrightText: Copyright (c) 2024 Dan Halbert for Adafruit Industries
#
# SPDX-License-Identifier: MIT

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESCCM
except ImportError:
    # Provide an exception raised by cryptography.
    class InvalidTag(Exception):
        pass

    # Use a CircuitPython implementation.
    from cm_aesccm_aesio import new

    def AESCCM(key, *, tag_length=16):
        return new(key, mac_len=tag_length)
