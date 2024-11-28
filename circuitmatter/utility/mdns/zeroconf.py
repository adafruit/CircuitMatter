# SPDX-FileCopyrightText: Copyright (c) 2024 Scott Shawcroft for Adafruit Industries
#
# SPDX-License-Identifier: MIT

import socket

from zeroconf import IPVersion, ServiceInfo, Zeroconf


class ZeroConf:
    def __init__(self):
        self.zeroconf = Zeroconf(ip_version=IPVersion.All)
        self.service_infos = {}

    def advertise_service(
        self,
        service_type,
        protocol,
        port,
        txt_records={},
        subtypes=[],
        instance_name="",
    ):
        txt_records = [f"{key}={value}" for key, value in txt_records.items()]
        main_info = ServiceInfo(
            f"{service_type}.{protocol}.local",
            instance_name,
            addresses=[socket.inet_aton("0.0.0.0")],
            port=port,
            properties=txt_records,
        )

        sub_info = ServiceInfo(
            subtypes,
            instance_name,
            addresses=[socket.inet_aton("0.0.0.0")],
            port=port,
            properties=txt_records,
        )

        self.zeroconf.register_service(main_info)
        self.zeroconf.register_service(sub_info)
        self.service_infos[service_type + instance_name] = main_info
        self.service_infos[subtypes + instance_name] = sub_info

    def __del__(self):
        for service_info in self.service_infos.values():
            self.zeroconf.unregister_service(service_info)
        self.zeroconf.close()
