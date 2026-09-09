"""Passive 802.11 monitor-mode sniffer.

This is the component that answers "how many devices are connected to that
Wi-Fi?" *without connecting to it*.  It never transmits a single frame - it
only listens to management/control/data frames already in the air and maps
client stations (STAs) to their access points (BSSIDs) by inspecting the
To-DS / From-DS address fields of every 802.11 header.

Requires: root + a card that supports monitor mode + scapy.
"""
from __future__ import annotations

import os
import threading
import time
from typing import Callable, Dict, List, Optional

from ..models import (AccessPoint, Station, band_of, channel_to_freq,
                      freq_to_channel)
from ..oui import is_multicast, is_randomized, lookup as oui_lookup, normalize
from ..util import is_root, log, os_name, run, which

BROADCAST = "FF:FF:FF:FF:FF:FF"
_IGNORE_PREFIXES = ("01:00:5E", "33:33", "01:80:C2", "FF:FF:FF")

CHANNELS_24 = [1, 6, 11, 2, 7, 3, 8, 4, 9, 5, 10, 12, 13]
CHANNELS_5 = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116,
              120, 124, 128, 132, 136, 140, 149, 153, 157, 161, 165]
CHANNELS_6 = [1, 5, 9, 13, 17, 21, 25, 29, 33, 37, 41, 45, 49, 53, 57, 61,
              65, 69, 73, 77, 81, 85, 89, 93]


def scapy_available() -> bool:
    try:
        import scapy.all  # noqa: F401
        return True
    except Exception:
        return False


# ------------------------------------------------------------- monitor mode

class MonitorMode:
    """Context manager that puts an interface into monitor mode and restores it."""

    def __init__(self, iface: str, use_airmon: bool = False):
        self.iface = iface
        self.mon_iface = iface
        self.use_airmon = use_airmon
        self._changed = False

    def __enter__(self) -> str:
        if os_name() != "linux":
            log.warning("automatic monitor mode is only implemented on Linux; "
                        "assuming %s is already in monitor mode", self.iface)
            return self.iface
        if not is_root():
            raise PermissionError("monitor mode requires root (run with sudo)")
        if self.use_airmon and which("airmon-ng"):
            run(["airmon-ng", "check", "kill"], timeout=20)
            rc, so, _ = run(["airmon-ng", "start", self.iface], timeout=30)
            for cand in (f"{self.iface}mon", "mon0", self.iface):
                rc2, so2, _ = run(["iw", "dev", cand, "info"], timeout=10)
                if rc2 == 0:
                    self.mon_iface = cand
                    break
            self._changed = True
            log.info("monitor mode enabled via airmon-ng on %s", self.mon_iface)
            return self.mon_iface
        run(["ip", "link", "set", self.iface, "down"], timeout=15)
        rc, _, se = run(["iw", "dev", self.iface, "set", "monitor", "control"], timeout=15)
        if rc != 0:
            run(["iw", "dev", self.iface, "set", "type", "monitor"], timeout=15)
        run(["ip", "link", "set", self.iface, "up"], timeout=15)
        self._changed = True
        log.info("monitor mode enabled on %s", self.iface)
        return self.iface

    def __exit__(self, *exc) -> None:
        if not self._changed or os_name() != "linux":
            return
        try:
            if self.use_airmon and which("airmon-ng") and self.mon_iface != self.iface:
                run(["airmon-ng", "stop", self.mon_iface], timeout=30)
            else:
                run(["ip", "link", "set", self.iface, "down"], timeout=15)
                run(["iw", "dev", self.iface, "set", "type", "managed"], timeout=15)
                run(["ip", "link", "set", self.iface, "up"], timeout=15)
            run(["systemctl", "restart", "NetworkManager"], timeout=20)
            log.info("interface %s restored to managed mode", self.iface)
        except Exception as exc:                                  # pragma: no cover
            log.warning("could not restore interface: %s", exc)


def set_channel(iface: str, channel: int, band: str = "") -> bool:
    if which("iw"):
        args = ["iw", "dev", iface, "set", "channel", str(channel)]
        if band == "6GHz":
            freq = channel_to_freq(channel, "6GHz")
            args = ["iw", "dev", iface, "set", "freq", str(freq)]
        rc, _, _ = run(args, timeout=8)
        if rc == 0:
            return True
    if which("iwconfig"):
        rc, _, _ = run(["iwconfig", iface, "channel", str(channel)], timeout=8)
        return rc == 0
    return False


# ----------------------------------------------------------------- sniffer

class MonitorSniffer:
    """Passive 802.11 collector: builds AP -> client maps from raw frames."""

    def __init__(self, iface: str, channels: Optional[List[int]] = None,
                 hop_interval: float = 0.35, bands=("2.4GHz", "5GHz"),
                 lock_bssid: str = "", on_update: Optional[Callable] = None):
        self.iface = iface
        self.hop_interval = hop_interval
        self.bands = bands
        self.lock_bssid = normalize(lock_bssid)
        self.on_update = on_update
        self.channels = channels or self._default_channels()
        self.aps: Dict[str, AccessPoint] = {}
        self.unassociated: Dict[str, Station] = {}
        self.frames = 0
        self.frames_by_type: Dict[str, int] = {}
        self.handshakes: Dict[str, int] = {}
        self.deauths = 0
        self._stop = threading.Event()
        self._hopper: Optional[threading.Thread] = None
        self.current_channel: Optional[int] = None
        self.started_at = 0.0

    def _default_channels(self) -> List[int]:
        ch: List[int] = []
        if "2.4GHz" in self.bands:
            ch += CHANNELS_24
        if "5GHz" in self.bands:
            ch += CHANNELS_5
        return ch or CHANNELS_24

    # ------------------------------------------------------------ hopping

    def _hop(self) -> None:
        i = 0
        while not self._stop.is_set():
            ch = self.channels[i % len(self.channels)]
            if set_channel(self.iface, ch):
                self.current_channel = ch
            i += 1
            self._stop.wait(self.hop_interval)

    # ------------------------------------------------------------- parsing

    def _get_ap(self, bssid: str) -> AccessPoint:
        bssid = normalize(bssid)
        ap = self.aps.get(bssid)
        if ap is None:
            ap = AccessPoint(bssid=bssid, vendor=oui_lookup(bssid), source="monitor")
            self.aps[bssid] = ap
        return ap

    @staticmethod
    def _radiotap(pkt):
        """Extract (rssi_dbm, freq_mhz, noise) from the radiotap header."""
        rssi = freq = noise = None
        try:
            rssi = int(pkt.dBm_AntSignal)
        except Exception:
            pass
        try:
            freq = int(pkt.ChannelFrequency)
        except Exception:
            pass
        try:
            noise = int(pkt.dBm_AntNoise)
        except Exception:
            pass
        return rssi, freq, noise

    def _parse_beacon_ies(self, ap: AccessPoint, pkt) -> None:
        from scapy.layers.dot11 import Dot11Elt
        rsn_seen = wpa_seen = False
        el = pkt.getlayer(Dot11Elt)
        rates: List[float] = []
        while el is not None:
            try:
                _id, info = el.ID, bytes(el.info)
            except Exception:
                break
            if _id == 0:                                            # SSID
                try:
                    s = info.decode("utf-8", "replace")
                except Exception:
                    s = ""
                if s and s.strip("\x00"):
                    ap.ssid = s
                    ap.hidden = False
                elif not ap.ssid:
                    ap.hidden = True
            elif _id in (1, 50):                                    # rates
                rates += [b / 2 for b in info]
            elif _id == 3 and info:                                 # DS param
                ap.channel = info[0]
                ap.frequency = ap.frequency or channel_to_freq(info[0])
            elif _id == 5 and len(info) >= 2:                       # TIM
                ap.dtim = info[1]
            elif _id == 7 and len(info) >= 2:                       # Country
                ap.country = info[:2].decode("ascii", "ignore")
            elif _id == 11 and len(info) >= 3:                      # BSS Load
                ap.raw["bss_load_sta_count"] = int.from_bytes(info[0:2], "little")
                ap.raw["channel_utilization_pct"] = round(info[2] / 255 * 100, 1)
            elif _id == 45:                                         # HT cap
                ap.phy_modes.append("n")
                if len(info) >= 1 and info[0] & 0x02:
                    ap.width_mhz = max(ap.width_mhz or 20, 40)
            elif _id == 61 and len(info) >= 2:                      # HT operation
                ap.channel = ap.channel or info[0]
            elif _id == 191:                                        # VHT cap
                ap.phy_modes.append("ac")
                ap.width_mhz = max(ap.width_mhz or 20, 80)
            elif _id == 192 and len(info) >= 1:                     # VHT operation
                if info[0] in (1, 2, 3):
                    ap.width_mhz = max(ap.width_mhz or 20, 80 if info[0] == 1 else 160)
            elif _id == 48:                                         # RSN
                rsn_seen = True
                self._parse_rsn(ap, info)
            elif _id == 221 and len(info) >= 4:                     # vendor
                oui, typ = info[:3], info[3]
                if oui == b"\x00\x50\xf2":
                    if typ == 1:
                        wpa_seen = True
                        self._parse_rsn(ap, info[4:], wpa1=True)
                    elif typ == 4:
                        ap.wps = True
                elif oui == b"\x50\x6f\x9a" and typ == 0x1B:
                    ap.phy_modes.append("ax")
            elif _id == 255 and info:                               # extension
                if info[0] == 35:
                    ap.phy_modes.append("ax")
                elif info[0] == 108:
                    ap.phy_modes.append("be")
            elif _id == 114:                                        # mesh ID
                ap.is_mesh = True
            el = el.payload.getlayer(Dot11Elt)

        if rates:
            ap.max_rate_mbps = max(ap.max_rate_mbps or 0, max(rates))
        if rsn_seen:
            ap.security.append("WPA2")
        if wpa_seen:
            ap.security.append("WPA")
        if not rsn_seen and not wpa_seen:
            try:
                privacy = bool(pkt.cap & 0x10) if isinstance(pkt.cap, int) else "privacy" in str(pkt.cap)
            except Exception:
                privacy = "privacy" in str(getattr(pkt, "cap", ""))
            ap.security.append("WEP" if privacy else "OPEN")
        sec = set(ap.security)
        sec.discard("OPEN") if len(sec) > 1 else None
        akms = set(ap.auth_suites)
        # WPA3-only (SAE without a PSK AKM) is not a WPA2 transition network.
        if akms & {"SAE", "FT-SAE"} and not (akms & {"PSK", "PSK-SHA256", "FT-PSK"}):
            sec.discard("WPA2")
        if akms & {"OWE"}:
            sec.discard("OPEN")
        ap.security = sorted(sec, reverse=True)
        ap.ciphers = sorted(set(ap.ciphers))
        ap.auth_suites = sorted(set(ap.auth_suites))
        ap.phy_modes = sorted(set(ap.phy_modes))
        if ap.beacon_interval is None:
            ap.beacon_interval = getattr(pkt, "beacon_interval", None)
        if not ap.width_mhz:
            ap.width_mhz = 20

    @staticmethod
    def _raw_eapol(d) -> bool:
        """EAPOL detection for captures scapy left as raw bytes."""
        try:
            raw = bytes(d.payload)
        except Exception:
            return False
        if not raw:
            return False
        if raw[:3] == b"\xaa\xaa\x03":
            raw = raw[8:]
        return len(raw) >= 4 and raw[0] in (1, 2) and raw[1] == 3

    @staticmethod
    def _parse_rsn(ap: AccessPoint, data: bytes, wpa1: bool = False) -> None:
        """Parse an RSN/WPA information element for ciphers, AKMs and PMF."""
        CIPHERS = {0: "GROUP", 1: "WEP40", 2: "TKIP", 4: "CCMP", 5: "WEP104",
                   8: "GCMP", 9: "GCMP-256", 10: "CCMP-256"}
        AKMS = {1: "802.1X", 2: "PSK", 3: "FT-802.1X", 4: "FT-PSK",
                5: "802.1X-SHA256", 6: "PSK-SHA256", 8: "SAE", 9: "FT-SAE",
                11: "802.1X-SUITE-B", 12: "802.1X-SUITE-B-192", 18: "OWE"}
        try:
            i = 2                                       # skip version
            if len(data) < i + 4:
                return
            gc = data[i:i + 4]; i += 4
            ap.ciphers.append(CIPHERS.get(gc[3], f"0x{gc[3]:02x}"))
            n = int.from_bytes(data[i:i + 2], "little"); i += 2
            for _ in range(min(n, 8)):
                if len(data) < i + 4:
                    return
                ap.ciphers.append(CIPHERS.get(data[i + 3], f"0x{data[i+3]:02x}"))
                i += 4
            n = int.from_bytes(data[i:i + 2], "little"); i += 2
            for _ in range(min(n, 8)):
                if len(data) < i + 4:
                    return
                akm = AKMS.get(data[i + 3], f"0x{data[i+3]:02x}")
                ap.auth_suites.append(akm)
                if akm in ("SAE", "FT-SAE"):
                    ap.security.append("WPA3")
                if akm == "OWE":
                    ap.security.append("OWE")
                i += 4
            if not wpa1 and len(data) >= i + 2:
                caps = int.from_bytes(data[i:i + 2], "little")
                mfpr, mfpc = bool(caps & 0x40), bool(caps & 0x80)
                ap.pmf = "required" if mfpr else ("optional" if mfpc else "disabled")
        except Exception:
            pass

    def _handle(self, pkt) -> None:
        from scapy.layers.dot11 import (Dot11, Dot11Beacon, Dot11ProbeResp,
                                        Dot11ProbeReq, Dot11AssoReq,
                                        Dot11ReassoReq, Dot11Deauth,
                                        Dot11Disas, Dot11Elt)
        from scapy.layers.eap import EAPOL
        if not pkt.haslayer(Dot11):
            return
        d = pkt.getlayer(Dot11)
        self.frames += 1
        rssi, freq, noise = self._radiotap(pkt)
        length = len(pkt)
        ftype = d.type
        key = {0: "management", 1: "control", 2: "data"}.get(ftype, "other")
        self.frames_by_type[key] = self.frames_by_type.get(key, 0) + 1

        a1 = normalize(d.addr1 or "")
        a2 = normalize(d.addr2 or "")
        a3 = normalize(d.addr3 or "")

        def relevant(bssid: str) -> bool:
            return not self.lock_bssid or normalize(bssid) == self.lock_bssid

        # ---- beacons / probe responses: full AP fingerprint
        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            bssid = a3 or a2
            if not bssid or not relevant(bssid):
                return
            ap = self._get_ap(bssid)
            ap.observe_beacon(rssi)
            if freq:
                ap.frequency = freq
                ap.channel = freq_to_channel(freq) or ap.channel
            if noise is not None:
                ap.noise = noise
            try:
                self._parse_beacon_ies(ap, pkt)
            except Exception as exc:
                log.debug("IE parse error: %s", exc)
            return

        # ---- probe requests: unassociated devices + their known-network list
        if pkt.haslayer(Dot11ProbeReq):
            if not a2 or is_multicast(a2):
                return
            sta = self.unassociated.get(a2)
            if sta is None:
                sta = Station(mac=a2, vendor=oui_lookup(a2),
                              is_randomized=is_randomized(a2))
                self.unassociated[a2] = sta
            sta.observe(rssi, length=length, source="monitor",
                        evidence="probe-only")
            sta.channel = freq_to_channel(freq) if freq else sta.channel
            el = pkt.getlayer(Dot11Elt)
            if el is not None and el.ID == 0 and el.info:
                try:
                    name = el.info.decode("utf-8", "replace").strip("\x00")
                    if name:
                        sta.probed_ssids.add(name)
                except Exception:
                    pass
            return

        # ---- association / reassociation: definitive client->AP binding
        if pkt.haslayer(Dot11AssoReq) or pkt.haslayer(Dot11ReassoReq):
            bssid, client = a1, a2
            if relevant(bssid) and client and not is_multicast(client):
                ap = self._get_ap(bssid)
                sta = ap.stations.get(client) or Station(
                    mac=client, vendor=oui_lookup(client),
                    is_randomized=is_randomized(client))
                sta.observe(rssi, length=length, source="monitor",
                            evidence="assoc-request")
                ap.add_station(sta)
                self.unassociated.pop(client, None)
            return

        # ---- deauth / disassoc: attack or roam indicator
        if pkt.haslayer(Dot11Deauth) or pkt.haslayer(Dot11Disas):
            self.deauths += 1
            bssid = a3 or a2
            if bssid and relevant(bssid):
                self._get_ap(bssid).raw["deauths"] = \
                    self._get_ap(bssid).raw.get("deauths", 0) + 1
            return

        # ---- EAPOL: a 4-way handshake means a device just joined
        eapol_here = pkt.haslayer(EAPOL) or self._raw_eapol(d)
        if eapol_here:
            bssid = a3 or a1 or a2
            if bssid and relevant(bssid):
                self.handshakes[bssid] = self.handshakes.get(bssid, 0) + 1

        # ---- data / QoS frames: the main source of client<->AP mapping
        if ftype in (1, 2):
            to_ds, from_ds = int(d.FCfield) & 0x1, (int(d.FCfield) >> 1) & 0x1
            bssid = client = None
            direction = ""
            if to_ds and not from_ds:            # STA -> AP
                bssid, client = a1, a2
                direction = "up"
            elif from_ds and not to_ds:          # AP -> STA
                bssid, client = a2, a1
                direction = "down"
            elif not to_ds and not from_ds:      # ad-hoc / control
                bssid, client = a3, a2
            else:                                # WDS/mesh: 4-address frame
                bssid, client = a1, a2
                self._get_ap(normalize(bssid or "")).is_mesh = True if bssid else None
            if not bssid or not client:
                return
            bssid, client = normalize(bssid), normalize(client)
            if (client.startswith(_IGNORE_PREFIXES) or is_multicast(client)
                    or client == bssid or not relevant(bssid)
                    or bssid.startswith(_IGNORE_PREFIXES)):
                return
            ap = self._get_ap(bssid)
            ap.last_seen = time.time()
            if ftype == 2:
                ap.data_packets += 1
            sta = ap.stations.get(client)
            if sta is None:
                sta = Station(mac=client, bssid=bssid, ssid=ap.ssid,
                              vendor=oui_lookup(client),
                              is_randomized=is_randomized(client))
                ap.stations[client] = sta
                self.unassociated.pop(client, None)
            # Trust evidence (weaknesses #1/#9): direction proves data-bidi
            # over time; EAPOL on this BSS corroborates the binding.
            sta.observe(rssi, data=(ftype == 2), length=length,
                        source="monitor", direction=direction,
                        evidence="eapol" if eapol_here else "")
            if freq:
                sta.channel = freq_to_channel(freq)
            if self.on_update:
                self.on_update(self)

    # -------------------------------------------------------------- control

    def run(self, duration: float = 30.0, pcap_out: str = "",
            ring_segments: int = 0, rotate_mb: float = 0.0,
            on_packet: Optional[Callable] = None,
            snaplen: int = 0, secure_storage: bool = True) -> None:
        """Sniff for `duration` seconds (blocking).

        pcap_out:   write a capture file (streamed, never buffered in RAM).
        rotate_mb:  start a new file after N MB (forensic segmentation).
        ring_segments: keep only the last N files, overwriting the oldest —
                    a bounded, disk-safe ring buffer for 24/7 recording.
        snaplen:    truncate every captured frame to N bytes (weakness #5).
                    snaplen<=128 keeps 802.11 headers (client counting, IDS)
                    while discarding payloads — a privacy-preserving capture.
                    0 = full frames.
        secure_storage: chmod capture files 0600 (owner-only, weakness #5).
        """
        from scapy.all import sniff
        from ..privacy import secure_file
        self.started_at = time.time()
        if len(self.channels) > 1:
            self._hopper = threading.Thread(target=self._hop, daemon=True)
            self._hopper.start()

        writer, seg, seg_bytes = None, 0, 0
        base, ext = (os.path.splitext(pcap_out) if pcap_out else ("", ""))
        ext = ext or ".pcap"
        limit = int(rotate_mb * 1_000_000) if rotate_mb else 0
        wrote_paths: List[str] = []

        def seg_path(i: int) -> str:
            return pcap_out if i == 0 else f"{base}-{i % max(ring_segments, 1):03d}{ext}" \
                if ring_segments else f"{base}-{i:03d}{ext}"

        def open_writer(i: int):
            from scapy.all import PcapWriter
            path = seg_path(i)
            kwargs = {"sync": True}
            if snaplen and snaplen > 0:
                kwargs["snaplen"] = snaplen
            w = PcapWriter(path, **kwargs)
            wrote_paths.append(path)
            if secure_storage:
                secure_file(path)
            return w

        if pcap_out:
            writer = open_writer(0)
            if snaplen:
                log.info("privacy-preserving capture: frames truncated to %d "
                         "bytes (headers for counting/IDS, no payloads)", snaplen)

        def cb(pkt):
            nonlocal seg, seg_bytes, writer
            try:
                self._handle(pkt)
            except Exception as exc:
                log.debug("frame error: %s", exc)
            if on_packet:
                try:
                    on_packet(pkt)
                except Exception:
                    pass
            if writer is not None:
                writer.write(pkt)
                seg_bytes += len(bytes(pkt))
                if limit and seg_bytes >= limit:
                    writer.close()
                    seg += 1
                    writer = open_writer(seg)  # ring: overwrites oldest
                    log.info("rotated capture -> %s", seg_path(seg))
                    seg_bytes = 0

        log.info("sniffing on %s for %.0fs across %d channel(s)%s...",
                 self.iface, duration, len(self.channels),
                 f" -> {pcap_out}" if pcap_out else "")
        try:
            sniff(iface=self.iface, prn=cb, store=False, timeout=duration,
                  monitor=True)
        except Exception:
            sniff(iface=self.iface, prn=cb, store=False, timeout=duration)
        finally:
            self._stop.set()
            if self._hopper:
                self._hopper.join(timeout=2)
            if writer is not None:
                writer.close()
                if seg:
                    log.info("capture complete: segments %s-0..%d", base, seg)
                else:
                    log.info("wrote capture to %s", seg_path(0))

    def read_pcap(self, path: str) -> None:
        """Offline mode: analyse a previously captured pcap file."""
        from scapy.all import PcapReader
        self.started_at = time.time()
        n = 0
        with PcapReader(path) as rd:
            for pkt in rd:
                try:
                    self._handle(pkt)
                except Exception:
                    pass
                n += 1
        log.info("processed %d frames from %s", n, path)

    def stop(self) -> None:
        self._stop.set()

    # --------------------------------------------------------------- output

    def results(self) -> List[AccessPoint]:
        for bssid, cnt in self.handshakes.items():
            if bssid in self.aps:
                self.aps[bssid].raw["eapol_frames"] = cnt
        return list(self.aps.values())

    def stats(self) -> dict:
        return {
            "frames": self.frames,
            "frames_by_type": dict(self.frames_by_type),
            "access_points": len(self.aps),
            "clients": sum(len(a.stations) for a in self.aps.values()),
            "unassociated_devices": len(self.unassociated),
            "deauth_frames": self.deauths,
            "duration_s": round(time.time() - self.started_at, 1) if self.started_at else 0,
        }
