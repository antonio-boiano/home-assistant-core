#!/usr/bin/env python3

"""
zbdump - a tcpdump-like tool for ZigBee/IEEE 802.15.4 networks
Compatible with Wireshark 1.1.2 and later (jwright@willhackforsushi.com)
The -p flag adds CACE PPI headers to the PCAP (ryan@rmspeers.com)
"""

import logging
import subprocess
import sys


_LOGGER = logging.getLogger(__name__)

logging.basicConfig(level=logging.DEBUG)


def install(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])


try:
    from killerbee import kbutils
except ImportError:
    _LOGGER.warning("killerbee NOT installed, try to installing it")
    install("git+https://github.com/riverloopsec/killerbee.git#egg=killerbee")


class devList:
    def __init__(self, dev_path, dev_desc) -> None:
        self.dev_path = dev_path
        self.dev_desc = dev_desc
        self.manufacturer: str | None = None


class zbId:


    def __init__(self) -> None:
        self.dev_desc: str | None = None
        self.dev_path: str | None = None


    def devlist(self):
        dev_list = kbutils.devlist()
        if dev_list:
            list = []
            for x in dev_list:
                list.append(devList(x[0], x[1]))
            return list
        return None
