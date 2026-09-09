#!/usr/bin/env python3
"""Generate a synthetic 802.11 pcap so the whole pipeline can be tested
without any radio hardware.  Run:  python tests/make_fixture.py
"""
import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from scapy.all import RadioTap, wrpcap
from scapy.layers.dot11 import (Dot11, Dot11Beacon, Dot11Elt, Dot11AssoReq,
                                Dot11ProbeReq, Dot11Deauth)
from scapy.packet import Raw

OUT = os.path.join(os.path.dirname(__file__), "fixture.pcap")

RSN_WPA2 = bytes.fromhex("0100000fac040100000fac040100000fac020000")
RSN_WPA3 = bytes.fromhex("0100000fac040100000fac040100000fac08c000")

NETS = [
    # ssid, bssid, channel, freq, rssi, rsn, wps, clients
    ("HomeFiber-5G", "F0:9F:C2:11:22:33", 44, 5220, -48, RSN_WPA3, False,
     ["AC:BC:32:01:02:03", "DC:A6:32:AA:BB:CC", "8C:BE:BE:44:55:66"]),
    ("HomeFiber", "F0:9F:C2:11:22:34", 6, 2437, -52, RSN_WPA2, True,
     ["FC:F5:C4:12:34:56", "B8:27:EB:99:88:77", "34:23:87:DE:AD:01",
      "0A:1B:2C:3D:4E:5F"]),
    ("CafeGuest", "50:C7:BF:AA:00:11", 11, 2462, -71, None, False,
     ["78:1F:DB:00:11:22", "44:65:0D:33:44:55"]),
    ("Neighbour_2.4", "20:E5:2A:BE:EF:01", 1, 2412, -83, RSN_WPA2, False,
     ["06:AA:BB:CC:DD:EE"]),
    ("CafeGuest", "00:11:22:33:44:55", 11, 2462, -60, None, False, []),  # evil twin
]


def beacon(ssid, bssid, ch, freq, rssi, rsn, wps):
    rt = RadioTap(present="dBm_AntSignal+Channel",
                  dBm_AntSignal=rssi, ChannelFrequency=freq)
    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff",
                  addr2=bssid, addr3=bssid)
    cap = 0x1111 if rsn else 0x0001
    p = rt / dot11 / Dot11Beacon(cap=cap, beacon_interval=100)
    p /= Dot11Elt(ID=0, info=ssid.encode())
    p /= Dot11Elt(ID=1, info=bytes([0x82, 0x84, 0x8b, 0x96, 0x24, 0x30, 0x48, 0x6c]))
    p /= Dot11Elt(ID=3, info=bytes([ch]))
    p /= Dot11Elt(ID=5, info=bytes([0, 2, 0, 0]))
    p /= Dot11Elt(ID=7, info=b"US ")
    p /= Dot11Elt(ID=11, info=bytes([3, 0, 90]))
    p /= Dot11Elt(ID=45, info=bytes([0x02] + [0] * 25))
    if freq > 5000:
        p /= Dot11Elt(ID=191, info=bytes(12))
        p /= Dot11Elt(ID=192, info=bytes([1, 0, 0, 0, 0]))
    if rsn:
        p /= Dot11Elt(ID=48, info=rsn)
    if wps:
        p /= Dot11Elt(ID=221, info=b"\x00\x50\xf2\x04" + b"\x10\x4a\x00\x01\x10")
    return p


def main():
    pkts = []
    for ssid, bssid, ch, freq, rssi, rsn, wps, clients in NETS:
        for _ in range(6):
            pkts.append(beacon(ssid, bssid, ch, freq, rssi, rsn, wps))
        for c in clients:
            crssi = rssi - random.randint(2, 20)
            rt = RadioTap(present="dBm_AntSignal+Channel",
                          dBm_AntSignal=crssi, ChannelFrequency=freq)
            pkts.append(rt / Dot11(type=0, subtype=0, addr1=bssid, addr2=c,
                                   addr3=bssid) / Dot11AssoReq()
                        / Dot11Elt(ID=0, info=ssid.encode()))
            for i in range(random.randint(4, 25)):     # STA -> AP data
                pkts.append(RadioTap(present="dBm_AntSignal+Channel",
                                     dBm_AntSignal=crssi, ChannelFrequency=freq)
                            / Dot11(type=2, subtype=0, FCfield="to_DS",
                                    addr1=bssid, addr2=c, addr3="ff:ff:ff:ff:ff:ff")
                            / (b"\x00" * random.randint(60, 900)))
            for i in range(random.randint(2, 15)):     # AP -> STA data
                pkts.append(RadioTap(present="dBm_AntSignal+Channel",
                                     dBm_AntSignal=rssi, ChannelFrequency=freq)
                            / Dot11(type=2, subtype=0, FCfield="from_DS",
                                    addr1=c, addr2=bssid, addr3=bssid)
                            / (b"\x00" * random.randint(60, 1400)))
            eapol_key = b"\x02\x03\x00\x5d\x02\x01\x8a\x00\x10" + b"\x00" * 80
            pkts.append(RadioTap() / Dot11(type=2, subtype=8, FCfield="to_DS",
                                           addr1=bssid, addr2=c, addr3=bssid)
                        / Raw(load=b"\xaa\xaa\x03\x00\x00\x00\x88\x8e" + eapol_key))

    # unassociated devices probing for their known networks
    for mac, probes in (("F4:F5:E8:AA:11:22", ["HomeOffice", "Starbucks"]),
                        ("9E:12:34:56:78:9A", ["AirportFree"]),
                        ("64:09:80:CA:FE:01", ["HomeFiber"])):
        for pr in probes:
            pkts.append(RadioTap(present="dBm_AntSignal+Channel",
                                 dBm_AntSignal=-74, ChannelFrequency=2437)
                        / Dot11(type=0, subtype=4, addr1="ff:ff:ff:ff:ff:ff",
                                addr2=mac, addr3="ff:ff:ff:ff:ff:ff")
                        / Dot11ProbeReq() / Dot11Elt(ID=0, info=pr.encode()))

    # a deauth burst (attack indicator)
    for _ in range(9):
        pkts.append(RadioTap() / Dot11(type=0, subtype=12,
                                       addr1="ff:ff:ff:ff:ff:ff",
                                       addr2="50:C7:BF:AA:00:11",
                                       addr3="50:C7:BF:AA:00:11")
                    / Dot11Deauth(reason=7))

    random.shuffle(pkts)
    wrpcap(OUT, pkts)
    print(f"wrote {len(pkts)} frames -> {OUT}")


if __name__ == "__main__":
    main()
