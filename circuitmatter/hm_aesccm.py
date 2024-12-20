# SPDX-FileCopyrightText: Copyright (c) 2024 Dan Halbert for Adafruit Industries
#
# SPDX-License-Identifier: MIT

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESCCM
    from cryptography.exceptions import InvalidTag
except ImportError:
    # Provide an exception raised by cryptography.
    class InvalidTag(Exception):
        pass

    # Use a CircuitPython implementation.
    from hm_aesccm_aesio import *
