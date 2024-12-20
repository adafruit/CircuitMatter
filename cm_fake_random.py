# SPDX-FileCopyrightText: Copyright (c) 2024 Dan Halbert for Adafruit Industries
#
# SPDX-License-Identifier: MIT

import random

# Always start at the same place
random.seed(0)

def urandom(nbytes):
    return random.randbytes(nbytes)

def randbelow(n):
    return random.randrange(n)
