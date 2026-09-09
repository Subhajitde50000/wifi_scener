"""Local-network device inventory for the Wi-Fi you are *currently* joined to.

Complements the passive sniffer: when you are legitimately on a network this
resolves IP addresses, hostnames and open ports for every device, which the
over-the-air view alone cannot give you.
"""
from __future__ import annotations

import ipaddress
import re
import socket
import time
import concurrent.futures as cf
from typing import Dict, List, Optional

from ..models import Station
from ..oui import is_randomized, lookup as oui_lookup, normalize
from ..util import log, os_name, run, which

COMMON_PORTS = [21, 22, 23, 53, 80, 139, 443, 445, 554, 1883, 3389, 5000,
                5353, 6668, 8008, 8080, 8443, 9100, 62078]


def default_gateway() -> Optional[str]:
    osn = os_name()
    if osn == "linux":
        rc, so, _ = run(["ip", "route", "show", "default"])
        m = re.search(r"default via (\S+)", so)
        if m:
            return m.group(1)
    elif osn == "macos":
        rc, so, _ = run(["route", "-n", "get", "default"])
        m = re.search(r"gateway:\s*(\S+)", so)
        if m:
            return m.group(1)
    elif osn == "windows":
        rc, so, _ = run(["ipconfig"])
        m = re.search(r"Default Gateway[ .]*:\s*([\d.]+)", so)
        if m:
            return m.group(1)
    return None


def local_subnet() -> Optional[str]:
    osn = os_name()
    if osn == "linux":
        rc, so, _ = run(["ip", "-o", "-f", "inet", "addr", "show"])
        for line in so.splitlines():
            m = re.search(r"inet (\d+\.\d+\.\d+\.\d+/\d+)", line)
            if m and not m.group(1).startswith("127."):
                return str(ipaddress.ip_network(m.group(1), strict=False))
    else:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return str(ipaddress.ip_network(ip + "/24", strict=False))
        except OSError:
            return None
    return None


def _ping(ip: str) -> bool:
    flag = "-n" if os_name() == "windows" else "-c"
    wflag = "-w" if os_name() == "windows" else "-W"
    wval = "500" if os_name() == "windows" else "1"
    rc, _, _ = run(["ping", flag, "1", wflag, wval, ip], timeout=4)
    return rc == 0


def arp_table() -> Dict[str, str]:
    """Return {ip: mac} from the kernel neighbour/ARP cache."""
    table: Dict[str, str] = {}
    if which("ip"):
        rc, so, _ = run(["ip", "neigh", "show"])
        for line in so.splitlines():
            m = re.match(r"(\S+).*lladdr (\S+)", line)
            if m and "FAILED" not in line and "INCOMPLETE" not in line:
                table[m.group(1)] = normalize(m.group(2))
    if not table:
        rc, so, _ = run(["arp", "-a"], timeout=15)
        for line in so.splitlines():
            m = re.search(r"[\(\s](\d+\.\d+\.\d+\.\d+)[\)\s].*?"
                          r"([0-9a-fA-F]{1,2}(?::|-)(?:[0-9a-fA-F]{1,2}[:-]){4}"
                          r"[0-9a-fA-F]{1,2})", line)
            if m:
                mac = ":".join(p.zfill(2) for p in
                               normalize(m.group(2)).split(":"))
                table[m.group(1)] = mac
    return table


def _scan_ports(ip: str, ports: List[int], timeout: float = 0.35) -> List[int]:
    open_ports = []
    for p in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((ip, p)) == 0:
                    open_ports.append(p)
        except OSError:
            pass
    return open_ports


def _hostname(ip: str) -> str:
    try:
        socket.setdefaulttimeout(1.0)
        return socket.gethostbyaddr(ip)[0]
    except (OSError, socket.herror):
        return ""


def lan_inventory(subnet: str = "", do_ports: bool = False,
                  workers: int = 128, use_nmap: bool = True) -> List[Station]:
    """Discover every device on the local subnet (requires being connected)."""
    subnet = subnet or local_subnet() or ""
    if not subnet:
        log.warning("could not determine local subnet")
        return []
    log.info("sweeping %s for live hosts...", subnet)

    if use_nmap and which("nmap"):
        stations = _nmap_scan(subnet, do_ports)
        if stations:
            return stations

    net = ipaddress.ip_network(subnet, strict=False)
    hosts = list(net.hosts())
    if len(hosts) > 4096:
        log.warning("subnet %s too large (%d hosts); limiting to first 4096",
                    subnet, len(hosts))
        hosts = hosts[:4096]
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        list(ex.map(lambda h: _ping(str(h)), hosts))

    gw = default_gateway()
    table = arp_table()
    stations: List[Station] = []
    for ip, mac in table.items():
        try:
            if ipaddress.ip_address(ip) not in net:
                continue
        except ValueError:
            continue
        sta = Station(mac=mac, ip_address=ip, vendor=oui_lookup(mac),
                      is_randomized=is_randomized(mac))
        if ip == gw:
            sta.hostname = "(gateway/router)"
        stations.append(sta)

    with cf.ThreadPoolExecutor(max_workers=min(workers, 64)) as ex:
        names = list(ex.map(lambda s: _hostname(s.ip_address), stations))
    for sta, name in zip(stations, names):
        sta.hostname = sta.hostname or name

    if do_ports and stations:
        log.info("port-scanning %d hosts...", len(stations))
        with cf.ThreadPoolExecutor(max_workers=min(workers, 32)) as ex:
            res = list(ex.map(lambda s: _scan_ports(s.ip_address, COMMON_PORTS),
                              stations))
        for sta, ports in zip(stations, res):
            sta.open_ports = ports
    log.info("found %d devices on %s", len(stations), subnet)
    return stations


def _nmap_scan(subnet: str, do_ports: bool) -> List[Station]:
    args = ["nmap", "-sn", "-n", "--host-timeout", "8s", subnet]
    if do_ports:
        args = ["nmap", "-sS" if os_name() != "windows" else "-sT", "-F",
                "-n", "--host-timeout", "20s", subnet]
    rc, so, _ = run(args, timeout=300)
    if rc != 0:
        return []
    stations, cur_ip, cur_ports = [], None, []
    gw = default_gateway()
    for line in so.splitlines():
        m = re.search(r"Nmap scan report for (?:\S+ \()?(\d+\.\d+\.\d+\.\d+)", line)
        if m:
            cur_ip, cur_ports = m.group(1), []
            continue
        m = re.search(r"MAC Address: ([0-9A-Fa-f:]{17})\s*(?:\((.*)\))?", line)
        if m and cur_ip:
            mac = normalize(m.group(1))
            sta = Station(mac=mac, ip_address=cur_ip,
                          vendor=(m.group(2) or oui_lookup(mac)),
                          is_randomized=is_randomized(mac),
                          open_ports=cur_ports,
                          hostname="(gateway/router)" if cur_ip == gw else "")
            stations.append(sta)
            cur_ip = None
        m = re.match(r"(\d+)/tcp\s+open", line)
        if m:
            cur_ports.append(int(m.group(1)))
    return stations


def own_ap_clients(iface: str = "") -> List[Station]:
    """Authoritative client list straight from YOUR OWN access point.

    If this machine hosts the AP (router / Pi with hostapd), the kernel soft
    AP keeps the real association table, which is far better than anything
    observable over the air: exact station list, bytes, signal, uptime.
    Works only for an interface in AP mode — that is, your own network.
    """
    stations: List[Station] = []
    ifaces = [iface] if iface else [i["name"] for i in _ap_interfaces()]
    for ifn in ifaces:
        rc, so, _ = run(["iw", "dev", ifn, "station", "dump"])
        cur: Optional[Station] = None
        for line in (so or "").splitlines():
            m = re.match(r"Station (\S+) \(on (\S+)\)", line.strip())
            if m:
                if cur:
                    stations.append(cur)
                mac = normalize(m.group(1))
                cur = Station(mac=mac, vendor=oui_lookup(mac),
                              is_randomized=is_randomized(mac),
                              bssid=normalize(_iface_mac(ifn) or ""),
                              ssid=ifn)
                continue
            if cur is None:
                continue
            m = re.search(r"signal:\s*(-?\d+)\s*dBm", line)
            if m:
                cur.observe(int(m.group(1)))
            m = re.search(r"(tx|rx) bytes:\s*(\d+)", line)
            if m:
                cur.bytes_seen += int(m.group(2))
            m = re.search(r"connected time:\s*(\d+)", line)
            if m:
                cur.first_seen = time.time() - int(m.group(1))
        if cur:
            stations.append(cur)
    if stations:
        log.info("own-AP association table: %d clients", len(stations))
    return stations


def _ap_interfaces() -> List[dict]:
    rc, so, _ = run(["iw", "dev"])
    out, name = [], None
    for line in so.splitlines():
        m = re.search(r"^\s*Interface (\S+)$", line)
        if m:
            name = m.group(1)
        elif name and re.search(r"type AP", line):
            out.append({"name": name})
    return out


def _iface_mac(iface: str) -> str:
    rc, so, _ = run(["ip", "link", "show", iface])
    m = re.search(r"link/ether (\S+)", so)
    return m.group(1) if m else ""


def current_connection() -> dict:

    """Details about the Wi-Fi network this host is currently joined to."""
    info: dict = {}
    osn = os_name()
    if osn == "linux" and which("nmcli"):
        rc, so, _ = run(["nmcli", "-t", "-f", "ACTIVE,SSID,BSSID,CHAN,RATE,SIGNAL,SECURITY",
                         "device", "wifi", "list"])
        for line in so.splitlines():
            if line.startswith("yes:"):
                parts = [p.replace("\\:", ":") for p in re.split(r"(?<!\\):", line)]
                keys = ["active", "ssid", "bssid", "channel", "rate", "signal", "security"]
                info = dict(zip(keys, parts))
                break
    elif osn == "macos":
        from .survey import AIRPORT
        rc, so, _ = run([AIRPORT, "-I"])
        for line in so.splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                info[k.strip()] = v.strip()
    elif osn == "windows":
        rc, so, _ = run(["netsh", "wlan", "show", "interfaces"])
        for line in so.splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                info[k.strip().lower().replace(" ", "_")] = v.strip()
    info["gateway"] = default_gateway() or ""
    info["subnet"] = local_subnet() or ""
    return info
