#!/usr/bin/env python3

"""
zbdump - a tcpdump-like tool for ZigBee/IEEE 802.15.4 networks
Compatible with Wireshark 1.1.2 and later (jwright@willhackforsushi.com)
The -p flag adds CACE PPI headers to the PCAP (ryan@rmspeers.com)
"""

import asyncio
import logging
import subprocess
import sys

from homeassistant.core import HomeAssistant

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

    hass: HomeAssistant

    def __init__(self) -> None:
        self.dev_desc: str | None = None
        self.dev_path: str | None = None

    """Not Used"""
    # @contextlib.asynccontextmanager
    async def detect_radio_devices(self) -> bool:
        loop = asyncio.get_event_loop()
        dev_list = await loop.run_in_executor(None, kbutils.devlist, None)
        if dev_list:
            for x in dev_list:
                self.device_path = x[0]
                self.dev_desc = x[1]

            return True

        return False

    def devlist(self):
        dev_list = kbutils.devlist()
        if dev_list:
            list = []
            for x in dev_list:
                list.append(devList(x[0], x[1]))
            return list
        return None
