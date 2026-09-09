"""MAC address utilities: vendor (OUI) lookup and randomisation detection.

Uses a built-in table of common vendors and, if present, the system IEEE OUI
database (/usr/share/ieee-data, /var/lib/ieee-data, nmap-mac-prefixes) or a
user-supplied CSV cache at ~/.cache/wifiscanner/oui.csv.
"""
from __future__ import annotations

import csv
import os
import re
from functools import lru_cache

_MAC_RE = re.compile(r"^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$")

BUILTIN = {
    "00:1A:11": "Google", "3C:5A:B4": "Google", "F4:F5:E8": "Google",
    "00:03:93": "Apple", "AC:BC:32": "Apple", "F0:18:98": "Apple",
    "DC:A6:32": "Raspberry Pi", "B8:27:EB": "Raspberry Pi", "E4:5F:01": "Raspberry Pi",
    "00:1D:0F": "TP-Link", "50:C7:BF": "TP-Link", "A4:2B:B0": "TP-Link",
    "00:18:E7": "Cameo/Netgear", "20:E5:2A": "Netgear", "A0:40:A0": "Netgear",
    "00:0C:29": "VMware", "00:50:56": "VMware", "08:00:27": "VirtualBox",
    "00:1B:63": "Apple", "00:26:BB": "Apple", "D0:81:7A": "Apple",
    "00:16:6C": "Samsung", "34:23:87": "Samsung", "78:1F:DB": "Samsung",
    "FC:F5:C4": "Espressif", "24:6F:28": "Espressif", "A4:CF:12": "Espressif",
    "00:1E:58": "D-Link", "1C:7E:E5": "D-Link", "C8:BE:19": "D-Link",
    "00:23:69": "Cisco-Linksys", "C0:56:27": "Belkin", "94:10:3E": "Belkin",
    "00:14:6C": "Netgear", "E0:CB:4E": "ASUSTek", "2C:56:DC": "ASUSTek",
    "00:26:5A": "D-Link", "38:2C:4A": "ASUSTek", "70:4D:7B": "ASUSTek",
    "60:E3:27": "TP-Link", "98:DA:C4": "TP-Link", "50:D2:F5": "Huawei",
    "00:E0:FC": "Huawei", "10:47:80": "Huawei", "48:5B:39": "ASUSTek",
    "00:9A:CD": "Huawei", "8C:FD:F0": "Qualcomm", "00:A0:C6": "Qualcomm",
    "00:1F:3B": "Intel", "34:02:86": "Intel", "F8:94:C2": "Intel",
    "00:24:D7": "Intel", "7C:B2:7D": "Intel", "94:65:2D": "OnePlus",
    "58:CB:52": "Google", "1C:F2:9A": "Google", "44:07:0B": "Google",
    "B4:E6:2D": "Espressif", "CC:50:E3": "Espressif", "84:F3:EB": "Espressif",
    "18:FE:34": "Espressif", "5C:CF:7F": "Espressif", "60:01:94": "Espressif",
    "00:11:22": "CIMSYS", "00:0D:3A": "Microsoft", "7C:1E:52": "Microsoft",
    "28:16:AD": "Intel", "AC:DE:48": "Private", "00:15:5D": "Microsoft Hyper-V",
    "40:B0:76": "ASUSTek", "AC:9E:17": "ASUSTek", "D8:50:E6": "ASUSTek",
    "C4:6E:1F": "TP-Link", "14:CC:20": "TP-Link", "EC:08:6B": "TP-Link",
    "B0:BE:76": "TP-Link", "54:AF:97": "TP-Link", "9C:A2:F4": "TP-Link",
    "00:25:9C": "Cisco-Linksys", "68:7F:74": "Cisco-Linksys",
    "F0:9F:C2": "Ubiquiti", "24:A4:3C": "Ubiquiti", "78:8A:20": "Ubiquiti",
    "44:D9:E7": "Ubiquiti", "E0:63:DA": "Ubiquiti", "68:D7:9A": "Ubiquiti",
    "00:27:22": "Ubiquiti", "80:2A:A8": "Ubiquiti", "FC:EC:DA": "Ubiquiti",
    "18:E8:29": "Ubiquiti", "74:83:C2": "Ubiquiti", "B4:FB:E4": "Ubiquiti",
    "00:09:0F": "Fortinet", "90:6C:AC": "Fortinet", "00:0B:86": "Aruba/HPE",
    "6C:F3:7F": "Aruba/HPE", "94:B4:0F": "Aruba/HPE", "20:4C:03": "Aruba/HPE",
    "00:1C:B3": "Apple", "40:CB:C0": "Apple", "68:AB:BC": "Apple",
    "A8:66:7F": "Apple", "F0:99:BF": "Apple", "8C:85:90": "Apple",
    "B8:78:2E": "Apple", "9C:04:EB": "Apple", "E0:AC:CB": "Apple",
    "00:1F:5B": "Apple", "C8:2A:14": "Apple", "60:FB:42": "Apple",
    "40:9F:38": "Xiaomi", "64:09:80": "Xiaomi", "F8:A4:5F": "Xiaomi",
    "8C:BE:BE": "Xiaomi", "50:8F:4C": "Xiaomi", "28:6C:07": "Xiaomi",
    "34:CE:00": "Xiaomi", "78:11:DC": "Xiaomi", "AC:C1:EE": "Xiaomi",
    "00:1D:D8": "Microsoft", "50:1A:C5": "Microsoft", "00:12:5A": "Microsoft",
    "44:65:0D": "Amazon", "F0:27:2D": "Amazon", "68:37:E9": "Amazon",
    "74:C2:46": "Amazon", "0C:47:C9": "Amazon", "38:F7:3D": "Amazon",
    "B0:47:BF": "Amazon", "84:D6:D0": "Amazon", "AC:63:BE": "Amazon",
}

SYSTEM_DBS = [
    "/usr/share/ieee-data/oui.txt",
    "/var/lib/ieee-data/oui.txt",
    "/usr/share/nmap/nmap-mac-prefixes",
    "/usr/share/wireshark/manuf",
    os.path.expanduser("~/.cache/wifiscanner/oui.csv"),
]


def normalize(mac: str) -> str:
    return (mac or "").replace("-", ":").upper().strip()


def is_valid(mac: str) -> bool:
    return bool(_MAC_RE.match(mac or ""))


def is_randomized(mac: str) -> bool:
    """True if the MAC is locally administered (privacy / randomised MAC)."""
    mac = normalize(mac)
    if len(mac) < 2:
        return False
    try:
        first = int(mac[:2], 16)
    except ValueError:
        return False
    return bool(first & 0b10) and not bool(first & 0b1)


def is_multicast(mac: str) -> bool:
    mac = normalize(mac)
    try:
        return bool(int(mac[:2], 16) & 1)
    except ValueError:
        return False


def classify_mac(mac: str) -> tuple[str, str]:
    """Classify an observed MAC for identity honesty (weakness #2).

    Returns (identity_class, note):

    * ``stable-mac`` — burned-in OUI address; a stable radio identifier.
    * ``rotating-privacy-mac`` — locally-administered address that the OS
      rotates. Distinct rotating addresses must never be claimed to be
      distinct devices — nor the same device. Both are unknowable passively.
    * ``multicast`` — group/broadcast address; never a device identity.
    """
    mac = normalize(mac)
    if is_multicast(mac):
        return ("multicast",
                "group/broadcast address — never count as a device")
    if is_randomized(mac):
        return ("rotating-privacy-mac",
                "privacy address rotates: one observation, not one device; "
                "do not equate distinct rotating addresses with distinct "
                "devices (or with each other)")
    return ("stable-mac", "burned-in address: stable identifier for this radio")


@lru_cache(maxsize=1)
def _load_db() -> dict:
    db = dict(BUILTIN)
    for path in SYSTEM_DBS:
        if not os.path.exists(path):
            continue
        try:
            with open(path, "r", errors="ignore") as fh:
                if path.endswith(".csv"):
                    for row in csv.reader(fh):
                        if len(row) >= 2:
                            db.setdefault(normalize(row[0])[:8], row[1].strip())
                    continue
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "(hex)" in line:                      # IEEE oui.txt
                        pre, _, name = line.partition("(hex)")
                        db.setdefault(normalize(pre)[:8], name.strip())
                    else:                                    # nmap / manuf
                        parts = line.split(None, 1)
                        if len(parts) == 2 and len(parts[0]) >= 6:
                            pre = normalize(parts[0])
                            if ":" not in pre and len(pre) >= 6:
                                pre = ":".join(pre[i:i + 2] for i in range(0, 6, 2))
                            db.setdefault(pre[:8], parts[1].split("\t")[0].strip())
        except OSError:
            continue
    return db


def lookup(mac: str) -> str:
    """Return the vendor for a MAC address ('' if unknown)."""
    mac = normalize(mac)
    if len(mac) < 8:
        return ""
    if is_randomized(mac):
        return "(randomized MAC)"
    return _load_db().get(mac[:8], "")


def db_size() -> int:
    return len(_load_db())
