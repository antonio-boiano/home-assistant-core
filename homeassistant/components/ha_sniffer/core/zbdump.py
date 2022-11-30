#!/usr/bin/env python3

"""
zbdump - a tcpdump-like tool for ZigBee/IEEE 802.15.4 networks
Compatible with Wireshark 1.1.2 and later (jwright@willhackforsushi.com)
The -p flag adds CACE PPI headers to the PCAP (ryan@rmspeers.com)
"""
import logging
import subprocess
import sys
import time
from typing import Any, Optional, Union

from scapy.all import Dot15d4FCS  # type: ignore

_LOGGER = logging.getLogger(__name__)

logging.basicConfig(level=logging.DEBUG)


def install(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])


try:
    from killerbee import *
    from killerbee.scapy_extensions import *
except ImportError:
    _LOGGER.warning("killerbee NOT installed, try to installing it")
    install("git+https://github.com/riverloopsec/killerbee.git#egg=killerbee")


class ZbDump:
    def __init__(
        self,
        channel,
        pcapfile,
        devstring,
        device,
        ppi=0,
        subghz_page=0,
        pan_id_hex=None,
        count=-1,
    ) -> None:
        self.packetcount: int = 0
        self.kb: Optional[KillerBee] = None
        self.pcap_dumper: Optional[PcapDumper] = None
        self.daintree_dumper: Optional[DainTreeDumper] = None
        self.unbuffered: Optional[Any] = None
        self.channel = channel
        self.pcapfile = pcapfile
        self.devstring = devstring
        self.device = device
        self.subghz_page = subghz_page
        self.pan_id_hex = pan_id_hex
        self.count = count
        self.ppi = ppi

    def close(self) -> None:
        self.kb.sniffer_off()
        self.kb.close()

        if self.pcap_dumper is not None:
            self.pcap_dumper.close()
        if self.daintree_dumper is not None:
            self.daintree_dumper.close()

    def dump_packets(self, timeout):

        if self.pan_id_hex:
            panid: Optional[int] = int(self.pan_id_hex, 16)
        else:
            panid = None

        rf_freq_mhz = self.kb.frequency(self.channel, self.subghz_page) / 1000.0

        print(
            "zbdump: listening on '{}', channel {}, page {} ({} MHz), link-type DLT_IEEE802_15_4, capture size 127 bytes".format(
                self.devstring, self.channel, self.subghz_page, rf_freq_mhz
            )
        )

        if timeout > 0:

            timeout_start = time.time()

            while time.time() < timeout_start + timeout:

                packet: Optional[dict[Union[int, str], Any]] = self.kb.pnext()

                if packet is None:
                    continue

                if panid is not None:
                    pan, layer = kbgetpanid(Dot15d4FCS(packet["bytes"]))

                if panid is None or panid == pan:
                    self.packetcount += 1

                    if self.pcap_dumper is not None:
                        self.pcap_dumper.pcap_dump(
                            packet["bytes"], ant_dbm=packet["dbm"], freq_mhz=rf_freq_mhz
                        )
                    if self.daintree_dumper is not None:
                        self.daintree_dumper.pwrite(packet["bytes"])
        else:

            while (self.count != self.packetcount) and (
                time.time() < timeout_start + timeout
            ):

                packet: Optional[dict[Union[int, str], Any]] = self.kb.pnext()

                if packet is None:
                    continue

                if panid is not None:
                    pan, layer = kbgetpanid(Dot15d4FCS(packet["bytes"]))

                if panid is None or panid == pan:
                    self.packetcount += 1

                    if self.pcap_dumper is not None:
                        self.pcap_dumper.pcap_dump(
                            packet["bytes"], ant_dbm=packet["dbm"], freq_mhz=rf_freq_mhz
                        )
                    if self.daintree_dumper is not None:
                        self.daintree_dumper.pwrite(packet["bytes"])

    def capture(self, timeout=-1):

        if self.pcapfile is not None:
            self.pcap_dumper = PcapDumper(DLT_IEEE802_15_4, self.pcapfile, ppi=self.ppi)

        if self.devstring is None:
            print(
                "Autodetection features will be deprecated - please include interface string (e.g. -i /dev/ttyUSB0)"
            )
        if self.device is None:
            print(
                "Autodetection features will be deprecated - please include device string (e.g. -d apimote)"
            )

        self.kb = KillerBee(device=self.devstring, hardware=self.device)

        if not self.kb.is_valid_channel(self.channel, self.subghz_page):
            print(
                "ERROR: Must specify a valid IEEE 802.15.4 channel for the selected device."
            )
            self.kb.close()

        self.kb.set_channel(self.channel, self.subghz_page)
        self.kb.sniffer_on()

        self.dump_packets(timeout)

        self.kb.sniffer_off()
        self.kb.close()
        if self.pcap_dumper is not None:
            self.pcap_dumper.close()
        if self.daintree_dumper is not None:
            self.daintree_dumper.close()

        print(f"{self.packetcount} packets captured")
