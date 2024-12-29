# SPDX-FileCopyrightText: Copyright (c) 2024 Dan Halbert for Adafruit Industries
#
# SPDX-License-Identifier: MIT

try:
    from enum import Enum, IntEnum, IntFlag
except ImportError:

    class Enum:
        pass

    class IntEnum(Enum):
        pass

    class IntFlag(Enum):
        pass
