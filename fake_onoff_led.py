# SPDX-FileCopyrightText: Copyright (c) 2024 Scott Shawcroft for Adafruit Industries
#
# SPDX-License-Identifier: MIT

"""Simple fake LED on and off as a light."""

import circuitmatter as cm
from circuitmatter.device_types.lighting import on_off


class LED(on_off.OnOffLight):
    def __init__(self, name):
        super().__init__(name)
        self._name = name
        self.state = False

    def on(self):
        self.state = True
        print("Led %s is On", self._name)

    def off(self):
        self.state = False
        print("Led %s is Off", self._name)


matter = cm.CircuitMatter()
led1 = LED("led1")
matter.add_device(led1)
led2 = LED("led2")
matter.add_device(led2)
while True:
    matter.process_packets()
