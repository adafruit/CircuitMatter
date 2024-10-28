# SPDX-FileCopyrightText: Copyright (c) 2024 Scott Shawcroft for Adafruit Industries
#
# SPDX-License-Identifier: MIT

"""Simple fake LED on and off as a light."""

import circuitmatter as cm
from circuitmatter.device_types.lighting import on_off


class LED(on_off.OnOffLight):
    def __init__(self, name, led):
        super().__init__(name)
        self._name = name
        self._led = led

    def on(self):
        self._led.value = True
        print("Led %s is On", self._name)

    def off(self):
        self._led.value = False
        print("Led %s is Off", self._name)


matter = cm.CircuitMatter()
led = LED("led1")
matter.add_device(led)
led = LED("led2")
matter.add_device(led)
while True:
    matter.process_packets()
