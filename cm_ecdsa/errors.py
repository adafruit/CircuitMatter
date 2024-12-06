# SPDX-FileCopyrightText: Copyright (c) 2010 Brian Warner
# SPDX-FileCopyrightText: Copyright (c) 2024 Dan Halbert for Adafruit Industries
#
# SPDX-License-Identifier: MIT
#
# Derived from https://github.com/tlsfuzzer/python-ecdsa

class MalformedPointError(AssertionError):
    """Raised in case the encoding of private or public key is malformed."""

    pass
