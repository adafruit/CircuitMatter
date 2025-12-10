# SPDX-FileCopyrightText: Copyright (c) 2024 Dan Halbert for Adafruit Industries
#
# SPDX-License-Identifier: MIT

import random

# Always start at the same place
random.seed(0)


def urandom(nbytes):
    b = bytearray(nbytes)
    for i in range(nbytes):
        b[i] = random.randint(0, 255)
    return b


def randbelow(n):
    return random.randrange(n)
