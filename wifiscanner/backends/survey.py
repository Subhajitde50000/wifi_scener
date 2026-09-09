"""Passive AP discovery backends for Linux, macOS and Windows.

Every backend returns a list of AccessPoint objects. Backends are tried in
order of information richness; results from several backends are merged by
the Engine so nothing is lost.
"""
from __future__ import annotations

import json
import re
from typing import List

from ..models import AccessPoint, band_of, channel_to_freq, freq_to_channel
from ..oui import lookup as oui_lookup
from ..util import log, os_name, run, which

# --------------------------------------------------------------- interfaces


def list_interfaces() -> List[dict]:
    """Enumerate wireless interfaces on this host."""
    out = []
    osn = os_name()
    if osn == "linux":
        if which("iw"):
            rc, so, _ = run(["iw", "dev"])
            cur = {}
            for line in so.splitlines():
                s = line.strip()
                if s.startswith("Interface"):
                    if cur:
                        out.append(cur)
                    cur = {"name": s.split()[1], "driver": "", "mode": "", "os": osn}
                elif s.startswith("type ") and cur:
                    cur["mode"] = s.split()[1]
                elif s.startswith("addr ") and cur:
                    cur["mac"] = s.split()[1]
                elif s.startswith("channel ") and cur:
                    cur["channel"] = s.split()[1]
            if cur:
                out.append(cur)
        if not out:
            rc, so, _ = run(["cat", "/proc/net/wireless"])
            for line in so.splitlines()[2:]:
                if ":" in line:
                    out.append({"name": line.split(":")[0].strip(), "os": osn})
    elif osn == "macos":
        rc, so, _ = run(["networksetup", "-listallhardwareports"])
        blocks = so.split("Hardware Port:")
        for b in blocks:
            if "Wi-Fi" in b or "AirPort" in b:
                m = re.search(r"Device:\s*(\S+)", b)
                if m:
                    out.append({"name": m.group(1), "os": osn})
        if not out:
            out.append({"name": "en0", "os": osn})
    elif osn == "windows":
        rc, so, _ = run(["netsh", "wlan", "show", "interfaces"])
        cur = {}
        for line in so.splitlines():
            if ":" not in line:
                continue
            k, _, v = line.partition(":")
            k, v = k.strip().lower(), v.strip()
            if k == "name":
                if cur:
                    out.append(cur)
                cur = {"name": v, "os": osn}
            elif k in ("physical address", "state", "radio type") and cur:
                cur[k.replace(" ", "_")] = v
        if cur:
            out.append(cur)
    return out


def available_backends() -> List[str]:
    osn, b = os_name(), []
    if osn == "linux":
        if which("nmcli"):
            b.append("nmcli")
        if which("iw"):
            b.append("iw")
        if which("iwlist"):
            b.append("iwlist")
    elif osn == "macos":
        b.append("airport")
        if which("system_profiler"):
            b.append("system_profiler")
    elif osn == "windows":
        b.append("netsh")
    return b


# ------------------------------------------------------------ Linux: nmcli

_NMCLI_FIELDS = ("BSSID,SSID,MODE,CHAN,FREQ,SIGNAL,SECURITY,WPA-FLAGS,"
                 "RSN-FLAGS,ACTIVE,RATE,BARS")


def _parse_security(sec: str, wpa_flags: str = "", rsn_flags: str = ""):
    sec_u = (sec or "").upper()
    proto, ciphers, auth, pmf = [], [], [], ""
    if "WPA3" in sec_u or "SAE" in sec_u or "sae" in (rsn_flags or ""):
        proto.append("WPA3")
    if "WPA2" in sec_u or "RSN" in sec_u:
        proto.append("WPA2")
    if re.search(r"\bWPA\b", sec_u) and "WPA2" not in sec_u and "WPA3" not in sec_u:
        proto.append("WPA")
    if "WEP" in sec_u:
        proto.append("WEP")
    if "OWE" in sec_u:
        proto.append("OWE")
    if not proto:
        proto.append("OPEN")
    flags = f"{wpa_flags} {rsn_flags}".lower()
    for c, name in (("ccmp", "CCMP"), ("tkip", "TKIP"), ("gcmp", "GCMP"),
                    ("wep40", "WEP40"), ("wep104", "WEP104")):
        if c in flags:
            ciphers.append(name)
    for a, name in (("psk", "PSK"), ("802.1x", "802.1X"), ("sae", "SAE"),
                    ("owe", "OWE"), ("eap", "EAP")):
        if a in flags or a in sec_u.lower():
            auth.append(name)
    if "WPA3" in proto:
        pmf = "required" if "WPA2" not in proto else "optional"
    return proto, sorted(set(ciphers)), sorted(set(auth)), pmf


def scan_nmcli(iface: str = "", rescan: bool = True) -> List[AccessPoint]:
    if not which("nmcli"):
        return []
    if rescan:
        cmd = ["nmcli", "device", "wifi", "rescan"]
        if iface:
            cmd += ["ifname", iface]
        run(cmd, timeout=20)
    cmd = ["nmcli", "-t", "-f", _NMCLI_FIELDS, "device", "wifi", "list"]
    if iface:
        cmd += ["ifname", iface]
    rc, so, se = run(cmd, timeout=30)
    if rc != 0:
        log.debug("nmcli failed: %s", se.strip()[:200])
        return []
    aps = []
    for line in so.splitlines():
        if not line.strip():
            continue
        # BSSID octets are escaped as '\:' by nmcli -t
        parts = re.split(r"(?<!\\):", line)
        parts = [p.replace("\\:", ":") for p in parts]
        if len(parts) < 8:
            continue
        (bssid, ssid, mode, chan, freq, signal, security,
         wpaf, rsnf, active, rate, bars) = (parts + [""] * 12)[:12]
        bssid = bssid.upper()
        if len(bssid) != 17:
            continue
        try:
            ch = int(chan)
        except ValueError:
            ch = None
        f = None
        m = re.search(r"(\d+)", freq or "")
        if m:
            f = int(m.group(1))
        try:                                        # nmcli SIGNAL is 0-100
            q = int(signal)
            rssi = int(q / 2 - 100)
        except ValueError:
            rssi = None
        proto, ciphers, auth, pmf = _parse_security(security, wpaf, rsnf)
        rate_m = None
        mr = re.search(r"(\d+)", rate or "")
        if mr:
            rate_m = float(mr.group(1))
        ap = AccessPoint(
            bssid=bssid, ssid=ssid, channel=ch or freq_to_channel(f),
            frequency=f or channel_to_freq(ch or 0), rssi=rssi,
            security=proto, ciphers=ciphers, auth_suites=auth, pmf=pmf,
            max_rate_mbps=rate_m, hidden=(ssid == ""),
            is_mesh=(mode.lower() == "mesh"),
            vendor=oui_lookup(bssid), source="nmcli",
            raw={"mode": mode, "active": active, "bars": bars, "security": security},
        )
        ap.rssi_min = ap.rssi_max = rssi
        aps.append(ap)
    return aps


# --------------------------------------------------------------- Linux: iw

def scan_iw(iface: str) -> List[AccessPoint]:
    if not which("iw") or not iface:
        return []
    rc, so, se = run(["iw", "dev", iface, "scan"], timeout=45)
    if rc != 0:
        rc, so, se = run(["sudo", "-n", "iw", "dev", iface, "scan"], timeout=45)
    if rc != 0 or not so.strip():
        log.debug("iw scan failed: %s", se.strip()[:200])
        return []
    return _parse_iw(so)


def _parse_iw(text: str) -> List[AccessPoint]:
    aps, ap = [], None
    for raw_line in text.splitlines():
        line = raw_line.strip()
        m = re.match(r"BSS ([0-9a-fA-F:]{17})", line)
        if m:
            if ap:
                aps.append(ap)
            b = m.group(1).upper()
            ap = AccessPoint(bssid=b, vendor=oui_lookup(b), source="iw")
            continue
        if ap is None:
            continue
        if line.startswith("SSID:"):
            ap.ssid = line[5:].strip()
            ap.hidden = not ap.ssid
        elif line.startswith("freq:"):
            try:
                ap.frequency = int(float(line.split(":", 1)[1]))
                ap.channel = freq_to_channel(ap.frequency)
            except ValueError:
                pass
        elif line.startswith("signal:"):
            m2 = re.search(r"(-?\d+\.?\d*)\s*dBm", line)
            if m2:
                ap.rssi = int(float(m2.group(1)))
                ap.rssi_min = ap.rssi_max = ap.rssi
        elif line.startswith("beacon interval:"):
            m2 = re.search(r"(\d+)", line)
            if m2:
                ap.beacon_interval = int(m2.group(1))
        elif "DTIM Period" in line:
            # iw prints "TIM: DTIM Count 0 DTIM Period 2 ..." (no colon)
            m2 = re.search(r"DTIM Period:?\s*(\d+)", line)
            if m2:
                ap.dtim = int(m2.group(1))
        elif line.startswith("DS Parameter set: channel"):
            m2 = re.search(r"channel (\d+)", line)
            if m2:
                ap.channel = int(m2.group(1))
        elif line.startswith("Country:"):
            ap.country = line.split(":", 1)[1].strip().split()[0]
        elif line.startswith("RSN:"):
            ap.security.append("WPA2")
        elif line.startswith("WPA:"):
            ap.security.append("WPA")
        elif "Authentication suites:" in line:
            suites = line.split(":", 1)[1].split()
            for s in suites:
                ap.auth_suites.append(s)
                if s.upper() == "SAE":
                    ap.security.append("WPA3")
        elif "Pairwise ciphers:" in line or "Group cipher:" in line:
            for c in line.split(":", 1)[1].split():
                ap.ciphers.append(c.replace("00-0f-ac:", ""))
        elif "Capabilities:" in line and "MFP-required" in line:
            ap.pmf = "required"
        elif "Capabilities:" in line and "MFP-capable" in line and not ap.pmf:
            ap.pmf = "optional"
        elif line.startswith("WPS:"):
            ap.wps = True
        elif "Privacy" in line and not ap.security:
            ap.security.append("WEP")
        # NB: order matters - "VHT capabilities" also contains "HT capabilities"
        elif "EHT capabilities" in line or "EHT Capabilities" in line:
            ap.phy_modes.append("be")
        elif "VHT capabilities" in line or "VHT Capabilities" in line:
            ap.phy_modes.append("ac")
        elif "HE capabilities" in line or "HE Capabilities" in line:
            ap.phy_modes.append("ax")
        elif "HT capabilities" in line or "HT Capabilities" in line:
            ap.phy_modes.append("n")
        elif line.startswith("Supported rates:") or line.startswith("Extended supported rates:"):
            rates = re.findall(r"(\d+\.?\d*)\*?", line.split(":", 1)[1])
            if rates:
                mx = max(float(r) for r in rates)
                ap.max_rate_mbps = max(ap.max_rate_mbps or 0, mx)
        elif "STA count:" in line:
            m2 = re.search(r"STA count:\s*(\d+)", line)
            if m2:
                ap.raw["bss_load_sta_count"] = int(m2.group(1))
        elif "channel utilisation" in line or "channel utilization" in line:
            m2 = re.search(r"(\d+)/255", line)
            if m2:
                ap.raw["channel_utilization_pct"] = round(int(m2.group(1)) / 255 * 100, 1)
        elif "* secondary channel offset" in line or "STA channel width" in line:
            if "40 MHz" in line or "above" in line or "below" in line:
                ap.width_mhz = max(ap.width_mhz or 0, 40)
        elif "channel width:" in line:
            if "80+80" in line:
                ap.width_mhz = 160
            elif "160" in line:
                ap.width_mhz = 160
            elif "80" in line:
                ap.width_mhz = max(ap.width_mhz or 0, 80)
    if ap:
        aps.append(ap)
    for a in aps:
        sec, akms = set(a.security), {s.upper() for s in a.auth_suites}
        # SAE without PSK means WPA3-only, not a WPA2 transition network.
        if akms & {"SAE", "FT-SAE"} and not (akms & {"PSK", "FT-PSK"}):
            sec.discard("WPA2")
        a.security = sorted(sec, reverse=True) or ["OPEN"]
        a.ciphers = sorted(set(a.ciphers))
        a.auth_suites = sorted(set(a.auth_suites))
        a.phy_modes = sorted(set(a.phy_modes))
        if not a.width_mhz:
            a.width_mhz = 20
    return aps


# ------------------------------------------------------------ Linux: iwlist

def scan_iwlist(iface: str) -> List[AccessPoint]:
    if not which("iwlist") or not iface:
        return []
    rc, so, _ = run(["iwlist", iface, "scanning"], timeout=45)
    if rc != 0:
        rc, so, _ = run(["sudo", "-n", "iwlist", iface, "scanning"], timeout=45)
    if rc != 0:
        return []
    aps, ap = [], None
    for raw in so.splitlines():
        line = raw.strip()
        m = re.search(r"Address:\s*([0-9A-Fa-f:]{17})", line)
        if m:
            if ap:
                aps.append(ap)
            b = m.group(1).upper()
            ap = AccessPoint(bssid=b, vendor=oui_lookup(b), source="iwlist")
            continue
        if ap is None:
            continue
        if "ESSID:" in line:
            ap.ssid = line.split("ESSID:", 1)[1].strip().strip('"')
            ap.hidden = ap.ssid in ("", "\\x00")
        elif "Frequency:" in line:
            m2 = re.search(r"Frequency:([\d.]+) GHz", line)
            if m2:
                ap.frequency = int(float(m2.group(1)) * 1000)
                ap.channel = freq_to_channel(ap.frequency)
            m3 = re.search(r"Channel[ :](\d+)", line)
            if m3:
                ap.channel = int(m3.group(1))
        elif "Signal level=" in line:
            m2 = re.search(r"Signal level=(-?\d+)", line)
            if m2:
                ap.rssi = int(m2.group(1))
                ap.rssi_min = ap.rssi_max = ap.rssi
            m3 = re.search(r"Noise level=(-?\d+)", line)
            if m3:
                ap.noise = int(m3.group(1))
        elif "Encryption key:on" in line:
            if not ap.security:
                ap.security.append("WEP")
        elif "IE: IEEE 802.11i/WPA2" in line:
            ap.security = [s for s in ap.security if s != "WEP"] + ["WPA2"]
        elif "IE: WPA Version 1" in line:
            ap.security = [s for s in ap.security if s != "WEP"] + ["WPA"]
        elif "Authentication Suites" in line and "SAE" in line.upper():
            ap.security.append("WPA3")
        elif "Bit Rates:" in line:
            for r in re.findall(r"([\d.]+) Mb/s", line):
                ap.max_rate_mbps = max(ap.max_rate_mbps or 0, float(r))
    if ap:
        aps.append(ap)
    for a in aps:
        a.security = sorted(set(a.security), reverse=True) or ["OPEN"]
    return aps


# ----------------------------------------------------------- macOS: airport

AIRPORT = ("/System/Library/PrivateFrameworks/Apple80211.framework/Versions/"
           "Current/Resources/airport")


def scan_airport() -> List[AccessPoint]:
    import os
    if not os.path.exists(AIRPORT):
        return _scan_macos_profiler()
    rc, so, _ = run([AIRPORT, "-s"], timeout=45)
    if rc != 0 or not so.strip():
        return _scan_macos_profiler()
    aps = []
    lines = so.splitlines()
    if not lines:
        return []
    header = lines[0]
    bssid_col = header.find("BSSID")
    for line in lines[1:]:
        if len(line) < bssid_col + 17:
            continue
        ssid = line[:bssid_col].strip()
        rest = line[bssid_col:].split()
        if not rest:
            continue
        bssid = rest[0].upper()
        # airport prints single-digit octets unpadded; normalise
        bssid = ":".join(p.zfill(2) for p in bssid.split(":"))
        try:
            rssi = int(rest[1]); ch_raw = rest[2]
        except (IndexError, ValueError):
            continue
        ch = int(re.split(r"[,+-]", ch_raw)[0])
        width = 20
        if "+1" in ch_raw or "-1" in ch_raw:
            width = 40
        sec = " ".join(rest[5:]) if len(rest) > 5 else ""
        proto, ciphers, auth, pmf = _parse_security(sec, "", sec)
        f = channel_to_freq(ch)
        aps.append(AccessPoint(
            bssid=bssid, ssid=ssid, channel=ch, frequency=f, rssi=rssi,
            rssi_min=rssi, rssi_max=rssi, width_mhz=width, security=proto,
            ciphers=ciphers, auth_suites=auth, pmf=pmf, hidden=not ssid,
            vendor=oui_lookup(bssid), source="airport", raw={"security": sec}))
    return aps


def _scan_macos_profiler() -> List[AccessPoint]:
    rc, so, _ = run(["system_profiler", "-json", "SPAirPortDataType"], timeout=60)
    if rc != 0:
        return []
    try:
        data = json.loads(so)
    except json.JSONDecodeError:
        return []
    aps = []

    def walk(obj):
        if isinstance(obj, dict):
            name = obj.get("_name")
            sig = obj.get("spairport_signal_noise")
            if name and sig:
                rssi = noise = None
                m = re.search(r"(-?\d+)\s*dBm\s*/\s*(-?\d+)", str(sig))
                if m:
                    rssi, noise = int(m.group(1)), int(m.group(2))
                ch_raw = str(obj.get("spairport_network_channel", ""))
                cm = re.search(r"(\d+)", ch_raw)
                ch = int(cm.group(1)) if cm else None
                sec = str(obj.get("spairport_security_mode", ""))
                proto, ciphers, auth, pmf = _parse_security(sec)
                bssid = str(obj.get("spairport_network_bssid", "")).upper() or f"SSID:{name}"
                aps.append(AccessPoint(
                    bssid=bssid, ssid=name, channel=ch,
                    frequency=channel_to_freq(ch or 0), rssi=rssi, noise=noise,
                    security=proto, ciphers=ciphers, auth_suites=auth, pmf=pmf,
                    vendor=oui_lookup(bssid), source="system_profiler"))
            for v in obj.values():
                walk(v)
        elif isinstance(obj, list):
            for v in obj:
                walk(v)

    walk(data)
    return aps


# ---------------------------------------------------------- Windows: netsh

def scan_netsh() -> List[AccessPoint]:
    rc, so, _ = run(["netsh", "wlan", "show", "networks", "mode=bssid"], timeout=45)
    if rc != 0:
        return []
    aps, ssid, auth_s, enc_s = [], "", "", ""
    cur = None
    for raw in so.splitlines():
        line = raw.strip()
        m = re.match(r"SSID \d+\s*:\s*(.*)", line)
        if m:
            if cur:
                aps.append(cur); cur = None
            ssid = m.group(1).strip()
            continue
        if line.startswith("Authentication"):
            auth_s = line.split(":", 1)[1].strip()
        elif line.startswith("Encryption"):
            enc_s = line.split(":", 1)[1].strip()
        m = re.match(r"BSSID \d+\s*:\s*([0-9a-fA-F:]{17})", line)
        if m:
            if cur:
                aps.append(cur)
            b = m.group(1).upper()
            proto, ciphers, auth, pmf = _parse_security(f"{auth_s} {enc_s}", "", auth_s)
            if enc_s.upper() == "CCMP":
                ciphers = ["CCMP"]
            elif enc_s.upper() == "TKIP":
                ciphers = ["TKIP"]
            cur = AccessPoint(bssid=b, ssid=ssid, hidden=not ssid, security=proto,
                              ciphers=ciphers, auth_suites=auth, pmf=pmf,
                              vendor=oui_lookup(b), source="netsh",
                              raw={"auth": auth_s, "enc": enc_s})
            continue
        if cur is None:
            continue
        if line.startswith("Signal"):
            m2 = re.search(r"(\d+)%", line)
            if m2:
                cur.rssi = int(int(m2.group(1)) / 2 - 100)
                cur.rssi_min = cur.rssi_max = cur.rssi
        elif line.startswith("Channel"):
            m2 = re.search(r"(\d+)", line)
            if m2:
                cur.channel = int(m2.group(1))
                cur.frequency = channel_to_freq(cur.channel)
        elif line.startswith("Radio type"):
            rt = line.split(":", 1)[1].strip().lower()
            for tag, mode in (("802.11be", "be"), ("802.11ax", "ax"),
                              ("802.11ac", "ac"), ("802.11n", "n"),
                              ("802.11g", "g"), ("802.11a", "a"),
                              ("802.11b", "b")):
                if tag in rt:
                    cur.phy_modes.append(mode)
        elif "Basic rates" in line or "Other rates" in line:
            for r in re.findall(r"([\d.]+)", line.split(":", 1)[-1]):
                cur.max_rate_mbps = max(cur.max_rate_mbps or 0, float(r))
    if cur:
        aps.append(cur)
    return aps


# ------------------------------------------------------------------ driver

def survey_networks(iface: str = "", backend: str = "auto",
                    rescan: bool = True) -> List[AccessPoint]:
    """Run the best available AP-discovery backend(s) for this platform."""
    osn = os_name()
    results: List[AccessPoint] = []
    if backend not in ("auto", ""):
        fn = {"nmcli": lambda: scan_nmcli(iface, rescan),
              "iw": lambda: scan_iw(iface),
              "iwlist": lambda: scan_iwlist(iface),
              "airport": scan_airport,
              "netsh": scan_netsh}.get(backend)
        if not fn:
            raise ValueError(f"unknown backend: {backend}")
        return fn()

    if osn == "linux":
        results += scan_iw(iface) if iface else []
        nm = scan_nmcli(iface, rescan)
        results += nm
        if not results:
            results += scan_iwlist(iface or "wlan0")
    elif osn == "macos":
        results += scan_airport()
    elif osn == "windows":
        results += scan_netsh()
    else:
        log.warning("unsupported platform: %s", osn)
    return results
