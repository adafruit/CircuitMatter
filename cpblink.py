# SPDX-FileCopyrightText: Copyright (c) 2024 Dan Halbert for Adafruit Industries
#
# SPDX-License-Identifier: MIT

"""Simple LED on and off as a light."""

import os

import board
import digitalio

import circuitmatter as cm
import cm_fake_random
from circuitmatter.device_types.lighting import on_off

import adafruit_connection_manager
import mdns
import wifi

try:
    print("removing matter-device-state.json if present")
    os.remove("matter-device-state.json")
except OSError:
    pass


class LED(on_off.OnOffLight):
    def __init__(self, name, led):
        super().__init__(name)
        # self._led = led
        # self._led.direction = digitalio.Direction.OUTPUT

    def on(self):
        print("_led set to on")
        # self._led.value = True

    def off(self):
        print("_led set to off")
        # self._led.value = False


matter = cm.CircuitMatter(
    socketpool=adafruit_connection_manager.get_radio_socketpool(wifi.radio),
    mdns_server=mdns.Server(wifi.radio),
    random_source=cm_fake_random,
)
# led = LED("led1", digitalio.DigitalInOut(board.D13))
led = LED("led1", None)
matter.add_device(led)
while True:
    matter.process_packets()
