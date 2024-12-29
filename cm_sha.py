# SPDX-FileCopyrightText: Copyright (c) 2024 Dan Halbert for Adafruit Industries
#
# SPDX-License-Identifier: MIT

import hashlib

try:
    sha1 = hashlib.sha1
except AttributeError:
    # CircuitPython hashlib does not have shortcut constructors.
    def sha1(data=b""):
        return hashlib.new("sha1", data)


try:
    sha256 = hashlib.sha256
except AttributeError:
    # CircuitPython hashlib does not support sha256. Use the Python equivalent.
    import adafruit_hashlib

    def sha256(data=b""):
        return adafruit_hashlib.new("sha256", data)
