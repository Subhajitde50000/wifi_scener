"""WPA/WPA2/WPA3 decryption laboratory.

A teaching module built around *real* cryptography and *laboratory*
captures: students load a pcap produced by isolated, instructor-controlled
Wi-Fi infrastructure (or synthesised on the spot with
``wifiscanner wpa-lab make-fixture``), inventory its 802.11 frames and
4-way handshakes, then perform **authorised decryption using
laboratory-controlled key material** (the passphrase/PSK/PMK the
instructor hands out — never anything else).

The module deliberately demonstrates, byte for byte:

* WPA/WPA2 PSK derivation (PBKDF2-SHA1) and the 802.11 4-way handshake
  (ANonce/SNonce/PTK/KCK/KEK/TK), including MIC verification of a
  candidate key against handshake message 2 — the exact mechanism that
  tells you a key is correct *before* any data frame is touched;
* CCMP-128 (WPA2), CCMP-256 and GCMP per-frame decryption of protected
  data frames, including group-key (GTK) extraction from the wrapped
  key-data field of handshake message 3, so broadcast/multicast frames
  (e.g. ARP) decrypt too;
* CCMP-256 / GCMP-256 (WPA3-style cipher sizes) and detection of
  WPA3-SAE authentication exchanges, with an honest explanation that
  SAE stops the passphrase-equivalence shortcut — for SAE captures the
  instructor supplies the PMK directly (``--pmk``);
* what is visible **before** decryption (MAC addresses, frame sizes,
  timing, direction) versus **after** (IPs, ARP, DNS names, HTTP
  requests) — and why a capture without the handshake cannot be
  decrypted even with the right passphrase;
* failure cases: wrong passphrase (MIC mismatch), missing handshake,
  corrupt frames, unsupported/deprecated TKIP bodies.

Everything is stdlib-only, deterministic and offline. There is no
passive-sniffing glue here on purpose: the RF capture side of a real lab
(`wifiscanner capture`/`monitor` on the instructor's own AP) is already
covered by the rest of the project — this module starts at the capture
file.
"""
from __future__ import annotations

import html
import json
import os
import secrets as _secrets
import sqlite3
import string
import struct
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import wcrypto
from .privacy import ensure_secure_storage, secure_file
from .util import log

# ---------------------------------------------------------------- constants

LINKTYPE_RADIOTAP = 127
LINKTYPE_DOT11 = 105
LINKTYPE_ETHERNET = 1
ETHERTYPE_EAPOL = 0x888E
SNAP_HDR = b"\xaa\xaa\x03\x00\x00\x00"

_CIPHERS = {0: "group", 1: "wep40", 2: "tkip", 4: "ccmp", 5: "wep104",
            8: "gcmp", 9: "ccmp-256", 10: "gcmp-256"}
_AKMS = {1: "802.1X", 2: "PSK", 3: "FT-802.1X", 4: "FT-PSK",
         5: "802.1X-sha256", 6: "PSK-sha256", 8: "SAE", 9: "FT-SAE",
         11: "SuiteB", 12: "SuiteB-192", 18: "OWE"}
_GENERATIONS = (("sae", "WPA3"), ("802.1X", "WPA2-Enterprise"),
                ("PSK", "WPA2"), ("PSK-sha256", "WPA2"))


def _oui_type(raw: bytes):
    if len(raw) < 4:
        return None
    if raw[:3] in (b"\x00\x0f\xac", b"\x00\x50\xf2"):
        return raw[3]
    return None


# ------------------------------------------------------------- pcap io

class PcapError(ValueError):
    pass


def read_pcap(path: str):
    """Minimal stdlib pcap reader → (linktype, [RawTs...])."""
    with open(path, "rb") as fh:
        blob = fh.read()
    if len(blob) < 24:
        raise PcapError("file too small to be a pcap")
    magic = blob[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        order, nsec = "<", False
    elif magic == b"\xa1\xb2\xc3\xd4":
        order, nsec = ">", False
    elif magic == b"\x4d\x3c\xb2\xa1":
        order, nsec = "<", True
    elif magic == b"\xa1\xb2\x3c\x4d":
        order, nsec = ">", True
    else:
        raise PcapError(f"unsupported magic {magic.hex()} "
                        f"(pcapng not supported — convert with editcap)")
    _vmaj, _vmin, _tz, _sg, _snap, linktype = struct.unpack(
        order + "HHIIII", blob[4:24])
    frames = []
    off = 24
    while off + 16 <= len(blob):
        ts_s, ts_f, incl, _orig = struct.unpack_from(order + "IIII", blob, off)
        off += 16
        if off + incl > len(blob):
            break
        frames.append((ts_s + ts_f / (1e9 if nsec else 1e6),
                       blob[off:off + incl]))
        off += incl
    return linktype, frames


def write_pcap(path: str, records, linktype: int = LINKTYPE_RADIOTAP) -> str:
    """records: [(ts_float, bytes), ...]."""
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535,
                             linktype))
        for ts, data in records:
            sec = int(ts)
            usec = round((ts - sec) * 1e6)
            fh.write(struct.pack("<IIII", sec, usec, len(data), len(data)))
            fh.write(data)
    secure_file(path)
    return path


def strip_radiotap(data: bytes):
    """Return the 802.11 frame after a RadioTap header (or None)."""
    if len(data) < 8 or data[0] != 0:
        return None
    length = int.from_bytes(data[2:4], "little")
    if length < 8 or length > len(data):
        return None
    return data[length:]


# ------------------------------------------------------------- 802.11 model

_TYPE_NAMES = {0: "mgmt", 1: "ctrl", 2: "data"}
_MGMT = {0: "assoc-req", 1: "assoc-resp", 2: "reassoc-req", 3: "reassoc-resp",
         4: "probe-req", 5: "probe-resp", 8: "beacon", 9: "atim",
         10: "disassoc", 11: "auth", 12: "deauth", 13: "action"}


class Frame80211:
    __slots__ = ("raw", "fc0", "fc1", "ftype", "subtype", "flags", "to_ds",
                 "from_ds", "protected", "retry", "more_data", "a1", "a2",
                 "a3", "a4", "sc", "ts", "hdrlen", "payload", "valid")

    def __init__(self, raw: bytes, ts: float = 0.0):
        self.raw, self.ts = raw, ts
        self.valid = len(raw) >= 24
        if not self.valid:
            return
        self.fc0, self.fc1 = raw[0], raw[1]
        self.ftype = (self.fc0 >> 2) & 3
        self.subtype = (self.fc0 >> 4) & 0xF
        self.flags = self.fc1
        self.to_ds = bool(self.fc1 & 0x01)
        self.from_ds = bool(self.fc1 & 0x02)
        self.retry = bool(self.fc1 & 0x08)
        self.more_data = bool(self.fc1 & 0x20)
        self.protected = bool(self.fc1 & 0x40)
        self.a1, self.a2, self.a3 = raw[4:10], raw[10:16], raw[16:22]
        self.sc = int.from_bytes(raw[22:24], "little")
        hdr = 24
        self.a4 = b""
        if self.ftype == 2:
            if self.to_ds and self.from_ds:
                self.a4 = raw[24:30]
                hdr += 6
            if self.subtype & 0x08:                    # QoS data
                hdr += 2
        self.hdrlen = hdr
        self.valid = len(raw) >= hdr
        self.payload = raw[hdr:] if self.valid else b""

    # -- helpers ---------------------------------------------------------
    @staticmethod
    def _fmt(mac: bytes) -> str:
        return ":".join(f"{b:02x}" for b in mac).upper() if mac else ""

    @property
    def qos(self) -> bool:
        return self.ftype == 2 and bool(self.subtype & 0x08)

    @property
    def tid(self) -> int:
        if not self.qos or not self.valid:
            return 0
        pos = 24 + (6 if (self.to_ds and self.from_ds) else 0)
        return self.raw[pos] & 0x0F

    @property
    def seq(self) -> int:
        return self.sc >> 4

    @property
    def da(self) -> bytes:
        if self.ftype != 2:
            return self.a1
        if self.to_ds:
            return self.a3
        if self.from_ds:
            return self.a1
        return self.a1

    @property
    def sa(self) -> bytes:
        if self.ftype != 2:
            return self.a2
        if self.to_ds and self.from_ds:
            return self.a4
        if self.to_ds:
            return self.a2
        if self.from_ds:
            return self.a3
        return self.a2

    @property
    def bssid(self) -> bytes:
        if self.ftype != 2:
            return self.a3
        if self.to_ds and not self.from_ds:
            return self.a1
        if self.from_ds and not self.to_ds:
            return self.a2
        return self.a3

    @property
    def is_eapol(self) -> bool:
        return (self.ftype == 2 and not self.protected
                and self.payload.startswith(SNAP_HDR + b"\x88\x8e"))

    @property
    def type_name(self) -> str:
        if self.ftype == 0:
            return _MGMT.get(self.subtype, f"mgmt-{self.subtype}")
        if self.ftype == 2:
            if self.is_eapol:
                return "eapol-key"
            return "qos-data" if self.qos else "data"
        return _TYPE_NAMES.get(self.ftype, "?")


def parse_capture(path: str):
    """pcap → list[Frame80211]. Raises PcapError on trouble."""
    linktype, raws = read_pcap(path)
    frames = []
    if linktype == LINKTYPE_RADIOTAP:
        for ts, raw in raws:
            body = strip_radiotap(raw)
            if body is not None:
                frames.append(Frame80211(body, ts))
    elif linktype == LINKTYPE_DOT11:
        frames = [Frame80211(raw, ts) for ts, raw in raws]
    else:
        raise PcapError(f"unsupported link type {linktype} "
                        f"(need 127 radiotap or 105 802.11)")
    return [f for f in frames if f.valid]


# ------------------------------------------------------- IEs / security

def walk_ies(payload: bytes):
    off = 0
    while off + 2 <= len(payload):
        i, ln = payload[off], payload[off + 1]
        if off + 2 + ln > len(payload):
            break
        yield i, payload[off + 2:off + 2 + ln]
        off += 2 + ln


def parse_rsn(data: bytes, vendor: bool = False) -> dict:
    """RSN (48) or legacy WPA vendor (221) element → security profile."""
    out = {"version": None, "group": "", "pairwise": [], "akm": [],
           "pmf_capable": False, "pmf_required": False, "vendor_wpa": vendor}
    if vendor:
        if len(data) < 6 or data[:4] != b"\x00\x50\xf2\x01":
            return out
        data = data[4:]
        out["vendor_wpa"] = True
    if len(data) < 2:
        return out
    out["version"] = int.from_bytes(data[0:2], "little")
    off = 2

    def _cipher(raw):
        t = _oui_type(raw)
        return _CIPHERS.get(t, f"cipher-{t}") if t is not None else "?"

    def _akm(raw):
        t = _oui_type(raw)
        return _AKMS.get(t, f"akm-{t}") if t is not None else "?"

    if len(data) >= off + 4:
        out["group"] = _cipher(data[off:off + 4])
        off += 4
    if len(data) >= off + 2:
        n = int.from_bytes(data[off:off + 2], "little")
        off += 2
        for _ in range(n):
            if len(data) < off + 4:
                break
            out["pairwise"].append(_cipher(data[off:off + 4]))
            off += 4
    if len(data) >= off + 2:
        n = int.from_bytes(data[off:off + 2], "little")
        off += 2
        for _ in range(n):
            if len(data) < off + 4:
                break
            out["akm"].append(_akm(data[off:off + 4]))
            off += 4
    if len(data) >= off + 2:
        caps = int.from_bytes(data[off:off + 2], "little")
        out["pmf_capable"] = bool(caps & 0x80)
        out["pmf_required"] = bool(caps & 0x40)
    return out


def security_label(profile: dict) -> str:
    akm = " ".join(profile.get("akm") or [])
    cip = " ".join(profile.get("pairwise") or [])
    if profile.get("vendor_wpa"):
        return "WPA"
    if "SAE" in akm or "FT-SAE" in akm:
        return "WPA3-SAE" if "PSK" not in akm else "WPA3-transition"
    if "802.1X" in akm:
        return "WPA2-Ent"
    if akm or cip:
        return "WPA2"
    return "OPEN"


def beacon_info(frame: Frame80211) -> dict:
    """Beacon/probe-resp → {ssid, channel, security, cipher, akm, pmf}."""
    if frame.type_name not in ("beacon", "probe-resp"):
        return {}
    body = frame.payload
    if len(body) < 12:
        return {}
    info = {"ssid": "", "channel": None, "security": "OPEN", "cipher": "",
            "akm": [], "pmf": ""}
    for ie_id, data in walk_ies(body[12:]):
        if ie_id == 0:
            info["ssid"] = data.decode("utf-8", "ignore")
        elif ie_id == 3 and data:
            info["channel"] = data[0]
        elif ie_id == 48:
            prof = parse_rsn(data)
            info["security"] = security_label(prof)
            info["cipher"] = (prof["pairwise"][0] if prof["pairwise"]
                              else prof["group"])
            info["akm"] = prof["akm"]
            info["pmf"] = ("required" if prof["pmf_required"]
                           else "capable" if prof["pmf_capable"] else "off")
        elif ie_id == 221 and data[:4] == b"\x00\x50\xf2\x01":
            prof = parse_rsn(data, vendor=True)
            if info["security"] == "OPEN":
                info["security"] = "WPA"
                info["cipher"] = (prof["pairwise"][0] if prof["pairwise"]
                                  else prof["group"])
                info["akm"] = prof["akm"] or ["PSK"]
    return info


# --------------------------------------------------------------- EAPOL

class KeyMsg:
    __slots__ = ("frame", "desc", "info", "replay", "nonce", "mic",
                 "key_data", "eapol_raw", "mic_offset", "ap", "sta", "ts",
                 "num")

    def __init__(self, frame: Frame80211):
        self.frame = frame
        p = frame.payload[len(SNAP_HDR) + 2:]        # skip LLC + ethertype
        self.eapol_raw = p
        ln = int.from_bytes(p[2:4], "big")
        body = p[4:4 + ln]
        self.desc = body[0]
        self.info = int.from_bytes(body[1:3], "big")
        self.replay = int.from_bytes(body[5:13], "big")
        self.nonce = body[13:45]
        self.mic = body[77:93]
        kdlen = int.from_bytes(body[93:95], "big")
        self.key_data = body[95:95 + kdlen]
        self.mic_offset = 4 + 77                     # within eapol_raw
        # message numbering via flag fields
        ack = self.info >> 7 & 1
        micset = self.info >> 8 & 1
        secure = self.info >> 9 & 1
        if not micset:
            self.num = 1
        elif ack:
            self.num = 3
        else:
            self.num = 4 if secure else 2
        # endpoints: transmitter=a2 is the sender
        if self.num in (1, 3):
            self.ap, self.sta = frame.a2, frame.a1
        else:
            self.ap, self.sta = frame.a1, frame.a2

    @property
    def desc_version(self) -> int:
        return self.info & 7

    @property
    def key_data_encrypted(self) -> bool:
        return bool(self.info >> 12 & 1)

    @property
    def mic_frame_zeroed(self) -> bytes:
        b = bytearray(self.eapol_raw)
        b[self.mic_offset:self.mic_offset + 16] = b"\x00" * 16
        return bytes(b)


def collect_handshakes(frames):
    """Group EAPOL-Key messages per (ap, sta); returns list of bundles."""
    bundles = {}
    for f in frames:
        if not f.is_eapol or f.ftype != 2:
            continue
        try:
            msg = KeyMsg(f)
        except Exception:
            continue
        key = (Frame80211._fmt(msg.ap), Frame80211._fmt(msg.sta))
        bnd = bundles.setdefault(key, {"ap": msg.ap, "sta": msg.sta,
                                       "msgs": [], "anonce": None,
                                       "snonce": None, "mic": None,
                                       "mic_frame": b"", "desc_ver": 2,
                                       "replay": [], "raw": []})
        bnd["msgs"].append(msg.num)
        bnd["replay"].append(msg.replay)
        bnd["raw"].append(msg)
        if msg.num in (1, 3) and bnd["anonce"] is None:
            bnd["anonce"] = msg.nonce
        if msg.num == 2 and bnd["snonce"] is None:
            bnd["snonce"] = msg.nonce
            bnd["mic"] = msg.mic
            bnd["mic_frame"] = msg.mic_frame_zeroed
            bnd["desc_ver"] = msg.desc_version
        elif msg.num == 4 and bnd["snonce"] and bnd["mic"] is None:
            bnd["mic"] = msg.mic
            bnd["mic_frame"] = msg.mic_frame_zeroed
            bnd["desc_ver"] = msg.desc_version
    out = []
    for bnd in bundles.values():
        bnd["complete"] = bnd["anonce"] is not None and bnd["mic"] is not None
        bnd["ap_s"] = Frame80211._fmt(bnd["ap"])
        bnd["sta_s"] = Frame80211._fmt(bnd["sta"])
        out.append(bnd)
    return out


# ------------------------------------------------------------- key ring

def _mac_bytes(mac: str) -> bytes:
    return bytes(int(x, 16) for x in mac.split(":"))


class LabKey:
    """One item of laboratory key material.

    kind: 'passphrase' (+ssid) | 'pmk' (32-byte hex) — for PSK networks the
    PSK *is* the PMK, so raw 64-hex plugs straight in, which is also how an
    instructor injects a WPA3-SAE-derived PMK.
    """

    def __init__(self, raw: str, ssid: str = "", label: str = ""):
        raw = raw.strip()
        self.ssid = ssid.strip()
        if len(raw) == 64 and all(c in string.hexdigits for c in raw):
            self.kind = "pmk"
            self.pmk = bytes.fromhex(raw)
            self.label = label or f"PMK/PSK {raw[:12]}…"
        else:
            self.kind = "passphrase"
            if not self.ssid:
                raise ValueError("a passphrase candidate needs the network "
                                 "SSID (keys are derived from name+password)")
            self.pmk = wcrypto.pmk_from_passphrase(raw, self.ssid)
            self.label = label or f"passphrase {raw!r} @ {self.ssid!r}"

    def as_dict(self):
        return {"kind": self.kind, "ssid": self.ssid, "label": self.label,
                "pmk": self.pmk.hex()}


def load_key_file(path: str) -> list:
    """One key per line: 'passphrase here' or 'ssid=NAME,pass=phrase' or
    64-hex PMK; '#' comments. Used for authorized instructor keyrings."""
    keys = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.lower().startswith("ssid=") and ",pass=" in line.lower():
                ssid, pw = line[5:].split(",pass=", 1)
                keys.append(LabKey(pw, ssid=ssid.strip()))
            else:
                keys.append(LabKey(line))
    return keys


class SessionKey:
    """A verified session: the handshake proved this key material is right."""

    def __init__(self, ap: bytes, sta: bytes, ptk: dict, cipher: str,
                 source: LabKey):
        self.ap, self.sta = ap, sta
        self.kck, self.kek, self.tk = ptk["kck"], ptk["kek"], ptk["tk"]
        self.cipher = cipher
        self.source = source
        self.gtk = b""

    def as_dict(self):
        return {"ap": Frame80211._fmt(self.ap),
                "sta": Frame80211._fmt(self.sta), "cipher": self.cipher,
                "source": self.source.label,
                "ptk": self.tk.hex()[:16] + "…",
                "gtk": bool(self.gtk)}


def try_key_on_bundle(bundle: dict, key: LabKey, cipher: str = "ccmp"):
    """The key-verification core: derive PTK, MIC-check against handshake.

    Returns SessionKey on success, None when the MIC does not verify
    (wrong or unusable key), raises LabError if the bundle lacks the
    nonces/MIC needed (e.g. handshake not captured).
    """
    if not bundle.get("complete"):
        raise LabError("4-way handshake incomplete — without ANonce+SNonce "
                       "and a MIC'd message the PTK cannot be derived. "
                       "Start the lab capture BEFORE the client joins, or "
                       "ask the instructor for the PMK directly.")
    ptk = wcrypto.derive_ptk(key.pmk, bundle["ap"], bundle["sta"],
                             bundle["anonce"], bundle["snonce"], cipher)
    calc = wcrypto.handshake_mic(ptk["kck"], bundle["mic_frame"],
                                 bundle.get("desc_ver", 2))
    if not _secrets.compare_digest(calc, bundle["mic"]):
        return None
    sess = SessionKey(bundle["ap"], bundle["sta"], ptk, cipher, key)
    # If msg 3 carried encrypted key data it holds the GTK (802.11 wraps it
    # with the KEK): grab it so broadcast/multicast frames decrypt too.
    for msg in bundle["raw"]:
        if msg.num == 3 and msg.key_data and msg.key_data_encrypted:
            try:
                plain = wcrypto.kwp_unwrap(sess.kek, msg.key_data)
                for ie_id, data in walk_ies(plain):
                    if ie_id == 0xDD and len(data) >= 7 \
                            and data[:3] == b"\x00\x0f\xac" and data[3] == 1:
                        sess.gtk = data[6:22]
            except wcrypto.CryptoError:
                pass
    return sess


class LabError(RuntimeError):
    pass


# --------------------------------------------------------- per-frame crypto

def ccmp_aead_params(frame: Frame80211):
    """Nonce + AAD for a CCMP/GCMP 802.11 data frame (shared by enc/dec)."""
    hdr = frame.raw
    pn_bytes = frame.payload[:8]
    pn = (pn_bytes[0] | pn_bytes[1] << 8 | pn_bytes[4] << 16
          | pn_bytes[5] << 24 | pn_bytes[6] << 32 | pn_bytes[7] << 40)
    nonce_ccm = bytes([frame.tid]) + frame.a2 + pn.to_bytes(6, "big")
    nonce_gcm = frame.a2 + pn.to_bytes(6, "big")
    aad = bytes([frame.fc0 & 0x8F, frame.fc1 & 0xC7]) \
        + frame.a1 + frame.a2 + frame.a3 \
        + bytes([frame.raw[22] & 0xF0, 0])
    if frame.to_ds and frame.from_ds:
        aad += frame.raw[24:30]
    if frame.qos:
        aad += bytes([frame.tid & 0x0F, 0])
    return pn, nonce_ccm, nonce_gcm, aad


def decrypt_frame(frame: Frame80211, sess: SessionKey):
    """Decrypt one protected data frame with a verified session key.

    Returns plaintext LLC payload, or raises CryptoError. Group-addressed
    frames use the GTK recovered from message 3.
    """
    group = bool(frame.da and frame.da[0] & 1)
    tk = sess.gtk if group and sess.gtk else sess.tk
    if frame.type_name != "data" and not frame.qos:
        raise wcrypto.CryptoError("not a data frame")
    body = frame.payload[8:]
    pn, nonce_ccm, nonce_gcm, aad = ccmp_aead_params(frame)
    ciph = sess.cipher
    if ciph.startswith("gcmp"):
        return wcrypto.gcm_decrypt(tk, nonce_gcm, body, aad, tag_len=16)
    if ciph.startswith("ccmp"):
        return wcrypto.ccm_decrypt(tk, nonce_ccm, body, aad, mic_len=8)
    raise wcrypto.CryptoError(
        f"{ciph}: TKIP/WEP body decryption is not implemented — TKIP is "
        f"broken by design (that's part of the lesson); use CCMP/GCMP "
        f"captures for the decrypt exercises")


def encrypt_frame(frame_fields: dict, plain_llc: bytes, tk: bytes, pn: int,
                  cipher: str = "ccmp") -> bytes:
    """Inverse of decrypt_frame — used by the lab *fixture generator* to
    produce captures whose crypto is genuinely the WPA2/WPA3 construction."""
    fc0, fc1 = frame_fields["fc0"], frame_fields["fc1"]
    hdr = bytes([fc0, fc1]) + frame_fields["dur"] \
        + frame_fields["a1"] + frame_fields["a2"] + frame_fields["a3"] \
        + struct.pack("<H", frame_fields["sc"])
    if frame_fields.get("a4"):
        hdr += frame_fields["a4"]
    if frame_fields.get("qos") is not None:
        hdr += frame_fields["qos"]
    pn_bytes = bytes([pn & 0xFF, (pn >> 8) & 0xFF, 0, 0x20,
                      (pn >> 16) & 0xFF, (pn >> 24) & 0xFF,
                      (pn >> 32) & 0xFF, (pn >> 40) & 0xFF])
    pseudo = Frame80211(hdr + pn_bytes + plain_llc)   # for aad/nonce reuse
    _, nonce_ccm, nonce_gcm, aad = ccmp_aead_params(pseudo)
    if cipher.startswith("gcmp"):
        ct = wcrypto.gcm_encrypt(tk, nonce_gcm, plain_llc, aad, 16)
    else:
        ct = wcrypto.ccm_encrypt(tk, nonce_ccm, plain_llc, aad, 8)
    return hdr + pn_bytes + ct



# --------------------------------------------------- plaintext summariser

def _ip4(x: bytes) -> str:
    return ".".join(str(b) for b in x)


def summarize_plain(b: bytes) -> dict:
    """LLC/SNAP payload → {kind, src, dst, proto, sport, dport, info}."""
    out = {"kind": "unknown", "src": "", "dst": "", "proto": "",
           "sport": "", "dport": "", "info": ""}
    if b.startswith(SNAP_HDR) and len(b) >= 8:
        ethertype = int.from_bytes(b[6:8], "big")
        b = b[8:]
        out["ethertype"] = f"0x{ethertype:04x}"
    else:
        return {**out, "kind": "non-snap",
                "info": f"{len(b)}B LLC/other payload"}
    if ethertype == 0x0806 and len(b) >= 28:               # ARP
        op = int.from_bytes(b[6:8], "big")
        sip, tip = _ip4(b[14:18]), _ip4(b[24:28])
        tmac = Frame80211._fmt(b[18:24])
        out.update(kind="ARP", proto="arp", src=sip, dst=tip)
        out["info"] = ("who-has " + tip if op == 1 else
                       tip + " is-at " + tmac) if op in (1, 2) else f"op {op}"
        return out
    if ethertype != 0x0800 or len(b) < 20:                 # not IPv4
        return {**out, "kind": f"ethertype-0x{ethertype:04x}",
                "info": f"{len(b)}B"}
    ihl = (b[0] & 0x0F) * 4
    proto = b[9]
    out.update(src=_ip4(b[12:16]), dst=_ip4(b[16:20]))
    if proto == 6 and len(b) >= ihl + 20:                  # TCP
        sport, dport = struct.unpack(">HH", b[ihl:ihl + 4])
        off = ihl + ((b[ihl + 12] >> 4) & 0xF) * 4
        payload = b[off:]
        info = f"tcp {len(payload)}B"
        if payload.startswith(b"GET ") or payload.startswith(b"POST ") \
                or payload.startswith(b"HEAD ") or payload.startswith(b"PUT "):
            line = payload.split(b"\r\n", 1)[0].decode("utf-8", "ignore")
            host = ""
            for ln in payload.split(b"\r\n")[1:]:
                if ln.lower().startswith(b"host:"):
                    host = ln.split(b":", 1)[1].strip().decode("utf-8", "ignore")
                    break
            info = "HTTP " + line + (f" (Host: {host})" if host else "")
        elif payload.startswith(b"HTTP/"):
            info = "HTTP response: " + payload.split(b"\r\n", 1)[0]\
                .decode("utf-8", "ignore")
            body0 = payload.split(b"\r\n\r\n", 1)
            if len(body0) == 2 and body0[1]:
                info += " → " + body0[1][:80].decode("utf-8", "ignore") \
                    .replace("\n", " ")
        out.update(kind="TCP", proto="tcp", sport=sport, dport=dport,
                   info=info)
        return out
    if proto == 17 and len(b) >= ihl + 8:                  # UDP
        sport, dport = struct.unpack(">HH", b[ihl:ihl + 4])
        payload = b[ihl + 8:]
        info = f"udp {len(payload)}B"
        kind = "UDP"
        if (sport == 53 or dport == 53) and len(payload) >= 12:
            qd = int.from_bytes(payload[4:6], "big")
            if qd:
                name, off = [], 12
                while off < len(payload) and payload[off]:
                    ln = payload[off]
                    name.append(payload[off + 1:off + 1 + ln]
                                .decode("utf-8", "ignore"))
                    off += 1 + ln
                qr = "response" if payload[2] & 0x80 else "query"
                info = f"DNS {qr}: {'.'.join(name)}"
                if qr == "response" and payload[6:8] != b"\x00\x00":
                    an = int.from_bytes(payload[6:8], "big")
                    info += f" ({an} answer{'s' if an != 1 else ''})"
                kind = "DNS"
        out.update(kind=kind, proto="udp", sport=sport, dport=dport, info=info)
        return out
    if proto == 1 and len(b) >= ihl + 4:                   # ICMP
        typ = b[ihl]
        names = {0: "echo-reply", 8: "echo-request", 3: "dest-unreachable"}
        out.update(kind="ICMP", proto="icmp",
                   info=names.get(typ, f"type {typ}"))
        return out
    out.update(kind="IPv4", proto=str(proto), info=f"{len(b) - ihl}B L4")
    return out


# ------------------------------------------------------------ full analysis

def analyze_capture(frames):
    """First-pass parse: AP security profiles, handshakes, frames."""
    aps = {}
    for f in frames:
        if f.type_name in ("beacon", "probe-resp"):
            info = beacon_info(f)
            if info:
                bssid = Frame80211._fmt(f.bssid or f.a3)
                aps[bssid] = {**info, "bssid": bssid}
    handshakes = collect_handshakes(frames)
    return {"frames": frames, "aps": aps, "handshakes": handshakes}


def frame_rows(analysis):
    frames = analysis["frames"]
    aps = analysis["aps"]
    rows = []
    eapol_names = {1: "handshake M1 (ANonce)", 2: "handshake M2 (SNonce+MIC)",
                   3: "handshake M3 (Install+GTK)", 4: "handshake M4 (ack)"}
    for i, f in enumerate(frames):
        row = {"idx": i, "ts": f.ts, "type": f.type_name,
               "sa": Frame80211._fmt(f.sa), "da": Frame80211._fmt(f.da),
               "bssid": Frame80211._fmt(f.bssid), "len": len(f.raw),
               "protected": f.protected, "status": "cleartext",
               "plain_kind": "", "info": "", "cipher": ""}
        if f.ftype == 0:
            row["status"] = "management"
            if f.type_name in ("beacon", "probe-resp"):
                info = beacon_info(f)
                if info:
                    row["info"] = (f"ssid={info['ssid']!r} "
                                   f"{info['security']} ch{info['channel']}")
            elif f.type_name == "auth" and len(f.payload) >= 2:
                alg = int.from_bytes(f.payload[0:2], "little")
                row["info"] = {0: "open-system", 3: "SAE (WPA3)"}\
                    .get(alg, f"alg {alg}")
        elif f.is_eapol:
            try:
                msg = KeyMsg(f)
                row.update(status="eapol", plain_kind="EAPOL-Key",
                           info=eapol_names.get(msg.num, "?"))
            except Exception:
                row.update(status="eapol", info="EAPOL")
        elif f.ftype == 2:
            if not f.protected:
                s = summarize_plain(f.payload)
                row.update(status="cleartext", plain_kind=s["kind"],
                           info=s["info"])
            else:
                row["cipher"] = aps.get(row["bssid"], {}).get("cipher", "")
                row["status"] = "locked"
                row["info"] = "encrypted — key required"
        else:
            row["status"] = "control"
        rows.append(row)
    return rows


def decrypt_capture(analysis, keys):
    """Try every lab key against every handshake; decrypt what verifies.

    Returns (result_dict). Raises nothing on wrong keys — failures are
    first-class teaching output.
    """
    frames, aps, handshakes = (analysis["frames"], analysis["aps"],
                               analysis["handshakes"])
    sessions = {}
    verdicts = []
    for bundle in handshakes:
        ap_s, sta_s = bundle["ap_s"], bundle["sta_s"]
        cipher = aps.get(ap_s, {}).get("cipher") or "ccmp"
        for key in keys:
            try:
                sess = try_key_on_bundle(bundle, key, cipher)
            except LabError as exc:
                verdicts.append({"key": key.label, "pair": f"{sta_s}@{ap_s}",
                                 "verdict": "no-handshake", "detail": str(exc)})
                break
            if sess:
                sessions[(ap_s, sta_s)] = sess
                verdicts.append({"key": key.label, "pair": f"{sta_s}@{ap_s}",
                                 "verdict": "accepted",
                                 "detail": "handshake MIC verified — this key "
                                           "IS the network key (or the "
                                           "instructor's PMK)"})
                break
            verdicts.append({"key": key.label, "pair": f"{sta_s}@{ap_s}",
                             "verdict": "wrong-key",
                             "detail": "MIC mismatch — passphrase/PMK is NOT "
                                       "correct for this pair"})
    rows = frame_rows(analysis)
    plain_records = []
    n_dec = 0
    for i, f in enumerate(frames):
        row = rows[i]
        if row["status"] != "locked":
            continue
        ap_s = row["bssid"]
        other_macs = {row["sa"], row["da"]}
        sess = next((sessions[k] for k in sessions
                     if k[0] == ap_s and k[1] in other_macs), None)
        if not sess:
            # group-addressed (broadcast/multicast) frames belong to the AP's
            # whole cell, not to one station's session: try any verified
            # session on this BSSID (GTK was recovered with its PTK).
            sess = next((v for (a, _s), v in sessions.items() if a == ap_s),
                        None)
        if not sess:
            if not any(h["complete"] for h in handshakes
                       if h["ap_s"] == ap_s):
                row["status"] = "no-handshake"
                row["info"] = "encrypted + no usable handshake in capture"
            continue
        try:
            plain = decrypt_frame(f, sess)
        except wcrypto.CryptoError as exc:
            row["status"] = "decrypt-failed"
            row["info"] = f"crypto rejected this frame ({exc})"
            continue
        s = summarize_plain(plain)
        row.update(status="decrypted", plain_kind=s["kind"], info=s["info"],
                   plain=plain, cipher=sess.cipher)
        n_dec += 1
        if plain.startswith(SNAP_HDR) and len(plain) >= 8:
            et = plain[6:8]
            eth = f.da + f.sa + et + plain[8:]
            plain_records.append((f.ts, eth))
    flows = [r for r in rows if r["status"] == "decrypted"]
    return {"sessions": {f"{k[1]}@{k[0]}": v for k, v in sessions.items()},
            "verdicts": verdicts, "rows": rows, "decrypted": n_dec,
            "plain_records": plain_records}


# ------------------------------------------------------------------ exports

def export_lab(path, analysis, result, outdir, prefix="wpa_lab"):
    os.makedirs(outdir, exist_ok=True)
    files = []
    import csv as _csv

    def _csv_out(name, fields, rows):
        p = os.path.join(outdir, f"{prefix}_{name}.csv")
        with open(p, "w", newline="", encoding="utf-8-sig") as fh:
            w = _csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
            w.writeheader()
            for r in rows:
                w.writerow(r)
        secure_file(p)
        files.append(p)

    rows = result["rows"]
    _csv_out("frames",
             ["idx", "ts", "type", "sa", "da", "bssid", "len", "protected",
              "cipher", "status", "plain_kind", "info"],
             [{**r, "ts": f"{r['ts']:.6f}"} for r in rows])
    if result["plain_records"]:
        p = os.path.join(outdir, f"{prefix}_decrypted.pcap")
        write_pcap(p, result["plain_records"], LINKTYPE_ETHERNET)
        files.append(p)
    payload = {
        "capture": os.path.abspath(path),
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "aps": list(analysis["aps"].values()),
        "handshakes": [{"ap": h["ap_s"], "sta": h["sta_s"],
                        "messages": h["msgs"], "complete": h["complete"]}
                       for h in analysis["handshakes"]],
        "verdicts": result["verdicts"],
        "sessions": {k: v.as_dict() for k, v in result["sessions"].items()},
        "counts": {"frames": len(rows),
                   "decrypted": result["decrypted"],
                   "locked": sum(r["status"] in ("locked", "no-handshake")
                                 for r in rows)}}
    p = os.path.join(outdir, f"{prefix}.json")
    with open(p, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=1, default=str)
    secure_file(p)
    files.append(p)
    p = os.path.join(outdir, f"{prefix}_report.md")
    with open(p, "w", encoding="utf-8") as fh:
        fh.write(_report_md(path, analysis, result))
    secure_file(p)
    files.append(p)
    return files


def _report_md(path, analysis, result) -> str:
    rows = result["rows"]
    n_locked = sum(r["status"] in ("locked", "no-handshake") for r in rows)
    n_clear = sum(r["status"] == "cleartext" for r in rows)
    ses = list(result["sessions"].values())
    lines = [
        f"# WPA lab decryption report",
        f"",
        f"- capture: `{os.path.abspath(path)}`",
        f"- frames: **{len(rows)}**  ·  cleartext/data pre-decryption: "
        f"**{n_clear}**  ·  encrypted: **{n_locked}**  ·  decrypted now: "
        f"**{result['decrypted']}**",
        f""]
    lines.append("## Networks observed")
    lines.append("")
    for ap in analysis["aps"].values():
        lines.append(f"- `{ap['bssid']}` **{ap['ssid'] or '(hidden)'}** — "
                     f"{ap['security']} ({ap['cipher']}), PMF: {ap['pmf'] or '?'},"
                     f" channel {ap['channel']}")
    lines += ["", "## 4-way handshakes", ""]
    for h in analysis["handshakes"]:
        what = "COMPLETE — keys derivable offline" if h["complete"] else \
            "INCOMPLETE — decryption impossible without the missing nonces"
        lines.append(f"- AP `{h['ap_s']}` ⇄ client `{h['sta_s']}`: "
                     f"messages {sorted(set(h['msgs']))} → **{what}**")
    if not analysis["handshakes"]:
        lines.append("- (none found — start captures before clients join)")
    lines += ["", "## Key verdicts", ""]
    for v in result["verdicts"]:
        mark = {"accepted": "✅", "wrong-key": "❌",
                "no-handshake": "🚫"}[v["verdict"]]
        lines.append(f"- {mark} `{v['verdict']}` — {v['key']} vs "
                     f"{v['pair']}: {v['detail']}")
    lines += ["", "## Sessions (authorized decryption)", ""]
    for s in ses:
        lines.append(f"- `{s.sta.hex(':').upper()}` ⇄ `{s.ap.hex(':').upper()}`"
                     f" — {s.cipher}, via {s.source.label}; GTK available: "
                     f"{'yes' if s.gtk else 'no'}")
    lines += ["", "## Decrypted traffic (visible only with the key)", ""]
    for r in rows:
        if r["status"] == "decrypted":
            lines.append(f"- frame {r['idx']}: `{r['sa']}` → `{r['da']}` "
                         f"**{r['plain_kind']}** — {r['info']}")
    lines += ["", "## Before vs after — the lesson in one table", "",
              "| metric | before decryption | after |",
              "|---|---|---|",
              f"| data frames readable | 0 of {n_locked} "
              f"| {result['decrypted']} of {n_locked} |",
              "| identifiers visible | MAC addresses only | + IP addresses, "
              "hostnames, URLs |",
              "| protocols | opaque blobs | ARP/DNS/HTTP/TCP/ICMP spelled "
              "out |", ""]
    return "\n".join(lines)


# ------------------------------------------------------------- fixture gen

_RADIOTAP8 = b"\x00\x00\x08\x00\x00\x00\x00\x00"
LAB_AP = "02:11:22:33:44:55"
LAB_STA = "02:66:77:88:99:aa"


def _beacon_frame(ap: bytes, ssid: str, cipher: str, channel: int) -> bytes:
    caps = b"\x11\x04"
    fixed = b"\x00" * 8 + b"\x64\x00" + caps
    ies = bytes([0, len(ssid)]) + ssid.encode()
    ies += bytes([3, 1, channel])
    if cipher == "tkip":
        # legacy WPA vendor IE (00:50:F2 01) with pairwise TKIP, AKM PSK
        body = (b"\x00\x50\xf2\x01\x01\x00" + b"\x00\x50\xf2\x02"
                + b"\x01\x00\x00\x50\xf2\x02" + b"\x01\x00\x00\x50\xf2\x02")
        ies += bytes([221, len(body)]) + body
    elif cipher == "open":
        pass                                  # open network: no RSN IE
    else:
        pair, akm = (4, 2) if cipher in ("ccmp", "ccmp-256", "gcmp") else (4, 2)
        code = {"ccmp": 4, "ccmp-256": 9, "gcmp": 8, "gcmp-256": 10,
                "tkip": 2}[cipher]
        oui = b"\x00\x0f\xac"
        rsn_body = (b"\x01\x00" + oui + bytes([code])
                    + b"\x01\x00" + oui + bytes([code])
                    + b"\x01\x00" + oui + bytes([akm])
                    + b"\x00\x00")
        ies += bytes([48, len(rsn_body)]) + rsn_body
    fc = b"\x80\x00"
    return (fc + b"\x00\x00" + b"\xff" * 6 + ap + ap + b"\x10\x00"
            + fixed + ies)


def make_fixture(path: str, ssid: str = "LabNet-PSK",
                 password: str = "lab-passphrase-07", cipher: str = "ccmp",
                 channel: int = 6, include_handshake: bool = True,
                 include_plaintext_tail: bool = True, seed: int = 7042):
    """Generate a cryptographically-real lab capture.

    The handshake MICs, the CCMP/GCMP frame protection and the KEK-wrapped
    GTK in message 3 are computed with the same published-vector-verified
    primitives the decryptor uses, so the capture behaves exactly like one
    taken off instructor hardware — no radio needed.
    """
    import random
    rnd = random.Random(seed)
    rand_bytes = (lambda n: rnd.randbytes(n)) if hasattr(rnd, "randbytes") \
        else (lambda n: bytes(rnd.getrandbits(8) for _ in range(n)))
    ap = _mac_bytes(LAB_AP)
    sta = _mac_bytes(LAB_STA)
    gw_mac = _mac_bytes("02:AA:BB:CC:DD:01")     # the lab gateway/dns box
    bcast = b"\xff" * 6
    pmk = wcrypto.pmk_from_passphrase(password, ssid)
    anonce, snonce = rand_bytes(32), rand_bytes(32)
    gtk = rand_bytes(16)
    records = []
    t = time.time() - 120

    def emit(raw80211: bytes, dt: float = 0.004):
        nonlocal t
        t += dt
        records.append((t, _RADIOTAP8 + raw80211))

    def mgmt(subtype_byte: int, a1: bytes, a2: bytes, a3: bytes,
             body: bytes, seq: int):
        emit(bytes([subtype_byte, 0x00]) + b"\x00\x00" + a1 + a2 + a3
             + struct.pack("<H", seq << 4) + body)

    # ---- 1) the AP announcing itself -----------------------------------
    for i in range(3):
        emit(_beacon_frame(ap, ssid, cipher, channel), 0.05)

    # ---- 2) open authentication + association (cleartext, realistically)
    auth_body = b"\x00\x00" + b"\x01\x00" + b"\x00\x00"
    mgmt(0xB0, ap, sta, ap, auth_body, 1)                    # auth sta→ap
    mgmt(0xB0, sta, ap, ap, auth_body, 2)                    # auth ap→sta
    assoc_body = b"\x31\x04\x0a\x00" + bytes([0, len(ssid)]) \
        + ssid.encode() + b"\x01\x08\x82\x84\x8b\x96\x24\x30\x48\x6c"
    mgmt(0x00, ap, sta, ap, assoc_body, 3)                # assoc-req sta→ap
    mgmt(0x10, sta, ap, ap, b"\x31\x04\x31\x04\x01\x00", 4)  # assoc-resp

    # ---- 3) the real 4-way handshake -----------------------------------
    ptk = wcrypto.derive_ptk(pmk, ap, sta, anonce, snonce, cipher)

    def data_hdr(a1: bytes, a2: bytes, a3: bytes, to_ds: bool,
                 protected: bool, seq: int) -> bytes:
        fc1 = (0x01 if to_ds else 0x02) | (0x40 if protected else 0x00)
        return (b"\x88" + bytes([fc1]) + b"\x3a\x01" + a1 + a2 + a3
                + struct.pack("<H", seq << 4) + b"\x00\x00")

    def eapol_msg(num: int, sta_to_ap: bool, nonce: bytes, info: int,
                  replay: int, key_data: bytes = b"", seq: int = 0):
        """Build a full 802.11 frame; MIC computed over the zeroed field."""
        body0 = (bytes([2]) + info.to_bytes(2, "big")
                 + (16 if num != 4 else 0).to_bytes(2, "big")
                 + replay.to_bytes(8, "big") + nonce
                 + b"\x00" * 16 + b"\x00" * 8 + b"\x00" * 8
                 + b"\x00" * 16 + len(key_data).to_bytes(2, "big")
                 + key_data)
        eap0 = bytes([1, 3]) + len(body0).to_bytes(2, "big") + body0
        # MIC covers the whole EAPOL frame, field zeroed (offset 4+77).
        mic = wcrypto.handshake_mic(ptk["kck"], eap0, info & 7)
        body = body0[:77] + mic + body0[93:]
        eap = bytes([1, 3]) + len(body).to_bytes(2, "big") + body
        pl = SNAP_HDR + b"\x88\x8e" + eap
        if sta_to_ap:
            hdr = data_hdr(ap, sta, ap, to_ds=True, protected=False,
                           seq=seq or (num + 20))
        else:
            hdr = data_hdr(sta, ap, ap, to_ds=False, protected=False,
                           seq=seq or (num + 20))
        return hdr + pl

    if include_handshake:
        PAIRWISE = 1 << 3
        emit(eapol_msg(1, False, anonce,          # M1: ack
                       2 | PAIRWISE | (1 << 7), 1), 0.06)
        rsn_ie = bytes([48, 20]) + b"\x01\x00\x00\x0f\xac\x04\x01\x00" \
            b"\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x02\x00\x00"
        emit(eapol_msg(2, True, snonce,           # M2: mic + RSN IE
                       2 | PAIRWISE | (1 << 8), 1, rsn_ie), 0.004)
        gtk_kde = b"\xdd\x16\x00\x0f\xac\x01\x00\x00" + gtk
        wrapped = wcrypto.kwp_wrap(ptk["kek"], rsn_ie + gtk_kde)
        emit(eapol_msg(3, False, anonce,          # M3: installs, wraps GTK
                       2 | PAIRWISE | (1 << 6) | (1 << 7) | (1 << 8)
                       | (1 << 9) | (1 << 12), 2, wrapped), 0.004)
        emit(eapol_msg(4, True, b"\x00" * 32,     # M4: final ack-less mic
                       2 | PAIRWISE | (1 << 8) | (1 << 9), 2), 0.004)

    # ---- 4) protected user traffic -------------------------------------
    sta_ip, gw_ip, srv_ip = "192.168.7.23", "192.168.7.1", "192.168.7.50"

    def ipv4(proto: int, src: str, dst: str, l4: bytes, ident: int) -> bytes:
        tot = 20 + len(l4)
        return (b"\x45" + bytes([0]) + tot.to_bytes(2, "big")
                + ident.to_bytes(2, "big") + b"\x00\x00" + b"\x40"
                + bytes([proto]) + b"\x00\x00"
                + bytes(int(x) for x in src.split("."))
                + bytes(int(x) for x in dst.split(".")) + l4)

    def udp_packet(sport, dport, payload):
        return struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) \
            + payload

    def tcp_packet(sport, dport, payload, flags=0x18):
        return struct.pack(">HHII", sport, dport, 2000, 1000) \
            + bytes([0x50, flags]) + b"\x20\x00\x00\x00\x00\x00" + payload

    def dns_msg(name: str, txid: int, answer_ip: str = ""):
        q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) \
            + b"\x00\x00\x01\x00\x01"
        flags = b"\x81\x80" if answer_ip else b"\x01\x00"
        answers = b"\x00\x01" if answer_ip else b"\x00\x00"
        body = txid.to_bytes(2, "big") + flags + b"\x00\x01" + answers \
            + b"\x00\x00\x00\x00" + q
        if answer_ip:
            body += b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" \
                + bytes(int(x) for x in answer_ip.split("."))
        return body

    pn = [0]

    def prot_frame(a1, a2, a3, ethertype: bytes, packet: bytes,
                   to_ds: bool, gtk_group=False):
        pn[0] += 1
        fc1 = (0x01 if to_ds else 0x02) | 0x40
        fields = {"fc0": 0x88, "fc1": fc1, "dur": b"\x3a\x01",
                  "a1": a1, "a2": a2, "a3": a3,
                  "sc": (pn[0] + 100) << 4, "qos": b"\x00\x00"}
        tk = gtk if gtk_group else ptk["tk"]
        return encrypt_frame(fields, SNAP_HDR + ethertype + packet,
                             tk, pn[0], cipher)

    # DNS query / response for a lab-internal host
    dq = ipv4(17, sta_ip, gw_ip, udp_packet(5353, 53,
              dns_msg("intranet.lab.example", 0x1234)), 1)
    emit(prot_frame(ap, sta, gw_mac, b"\x08\x00", dq, to_ds=True), 0.1)
    dr = ipv4(17, gw_ip, sta_ip, udp_packet(53, 5353,
              dns_msg("intranet.lab.example", 0x1234, srv_ip)), 2)
    emit(prot_frame(sta, ap, gw_mac, b"\x08\x00", dr, to_ds=False), 0.05)
    # HTTP GET + 200 with lab content
    get = ipv4(6, sta_ip, srv_ip, tcp_packet(49152, 80,
               b"GET /intranet/announcements.txt HTTP/1.1\r\n"
               b"Host: intranet.lab.example\r\n\r\n"), 3)
    emit(prot_frame(ap, sta, gw_mac, b"\x08\x00", get, to_ds=True), 0.05)
    resp = ipv4(6, srv_ip, sta_ip, tcp_packet(80, 49152,
                b"HTTP/1.1 200 OK\r\nContent-Length: 44\r\n\r\n"
                b"Lab quiz moved to Friday - bring your laptop!\n"), 4)
    emit(prot_frame(sta, ap, gw_mac, b"\x08\x00", resp, to_ds=False), 0.08)
    # ARP who-has (GROUP frame — decrypts only via the GTK from M3)
    arp = (b"\x00\x01\x08\x00\x06\x04\x00\x01" + sta
           + bytes(int(x) for x in sta_ip.split(".")) + b"\x00" * 6
           + bytes(int(x) for x in gw_ip.split(".")))
    emit(prot_frame(bcast, ap, ap, b"\x08\x06", arp, to_ds=False,
                    gtk_group=True), 0.07)
    # ICMP echo request
    icmp = b"\x08\x00\x00\x00\x00\x01\x00\x01" + b"LABPINGLABPING"
    emit(prot_frame(ap, sta, gw_mac, b"\x08\x00",
                    ipv4(1, sta_ip, gw_ip, icmp, 5), to_ds=True), 0.05)

    # ---- 5) contrast tail: same-ish traffic on an OPEN network ----------
    if include_plaintext_tail:
        open_ap = _mac_bytes("02:99:88:77:66:55")
        emit(_beacon_frame(open_ap, "LabNet-Open", "open", channel + 1), 0.1)
        open_sta = _mac_bytes("02:55:44:33:22:11")
        hc = ipv4(17, "10.9.9.9", "10.9.9.1", udp_packet(5354, 53,
                  dns_msg("time.lab.example", 0x4242)), 9)
        hdr = data_hdr(open_ap, open_sta, open_ap, to_ds=True,
                       protected=False, seq=7)
        emit(hdr + SNAP_HDR + b"\x08\x00" + hc)

    write_pcap(path, records, LINKTYPE_RADIOTAP)
    return {"path": path, "ssid": ssid, "password": password,
            "cipher": cipher, "pmk": pmk.hex(), "frames": len(records),
            "ap": LAB_AP, "sta": LAB_STA}


_SCHEMA = """
CREATE TABLE IF NOT EXISTS wpa_attempts(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL, ssid TEXT, candidate TEXT, verdict TEXT, detail TEXT,
  frames_decrypted INT, ip TEXT, ua TEXT);
CREATE TABLE IF NOT EXISTS wpa_events(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, kind TEXT, detail TEXT,
  ip TEXT);
"""


class WpaLabStore:
    """Owner-only training DB for the WPA lab (attempts + events)."""

    def __init__(self, path: str):
        self.path = path or "wpa_lab.sqlite"
        self.memory = self.path == ":memory:"
        self.lock = threading.RLock()
        if not self.memory:
            os.makedirs(os.path.dirname(os.path.abspath(self.path)) or ".",
                        exist_ok=True)
        self.db = sqlite3.connect(self.path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        with self.lock:
            if not self.memory:
                self.db.executescript("PRAGMA journal_mode=WAL;")
            self.db.executescript(_SCHEMA)
            self.db.commit()
        if not self.memory:
            ensure_secure_storage(self.path, fix=True)

    def close(self):
        with self.lock:
            self.db.commit()
            self.db.close()

    def event(self, kind, detail="", ip=""):
        with self.lock:
            self.db.execute("INSERT INTO wpa_events VALUES(NULL,?,?,?,?)",
                            (time.time(), str(kind)[:40], str(detail)[:400],
                             str(ip)[:45]))
            self.db.commit()

    def attempt(self, ssid, candidate, verdict, detail, frames_decrypted,
                ip="", ua=""):
        with self.lock:
            cur = self.db.execute(
                "INSERT INTO wpa_attempts VALUES(NULL,?,?,?,?,?,?,?,?)",
                (time.time(), str(ssid)[:80], str(candidate)[:80],
                 str(verdict)[:40], str(detail)[:400], frames_decrypted,
                 str(ip)[:45], str(ua)[:200]))
            self.db.commit()
            return cur.lastrowid

    def attempts(self, limit=500):
        with self.lock:
            rows = self.db.execute(
                "SELECT * FROM wpa_attempts ORDER BY ts DESC LIMIT ?",
                (limit,)).fetchall()
        out = [dict(r) for r in rows]
        for r in out:
            r["time"] = time.strftime("%H:%M:%S", time.localtime(r["ts"]))
        return out

    def events(self, limit=300):
        with self.lock:
            rows = self.db.execute(
                "SELECT * FROM wpa_events ORDER BY ts DESC LIMIT ?",
                (limit,)).fetchall()
        out = [dict(r) for r in rows]
        for r in out:
            r["time"] = time.strftime("%H:%M:%S", time.localtime(r["ts"]))
        return out

    def funnel(self):
        with self.lock:
            def _one(q, *a):
                return self.db.execute(q, a).fetchone()[0]
            return {"visits": _one("SELECT COUNT(*) FROM wpa_events "
                                   "WHERE kind='page-view'"),
                    "tries": _one("SELECT COUNT(*) FROM wpa_attempts"),
                    "successes": _one("SELECT COUNT(*) FROM wpa_attempts "
                                      "WHERE verdict='accepted'"),
                    "frames_decrypted":
                        _one("SELECT COALESCE(SUM(frames_decrypted),0) "
                             "FROM wpa_attempts")}

    def reset(self):
        n = 0
        with self.lock:
            for t in ("wpa_attempts", "wpa_events"):
                n += (self.db.execute(f"DELETE FROM {t}").rowcount or 0)
            self.db.commit()
        return n


# ------------------------------------------------------------ exercise text

def exercises_text(only: int = 0) -> str:
    ex = [
        ("1. Inventory the airspace",
         "Run `wpa-lab inventory` on the capture. Identify: the BSS and its "
         "security generation, the channel, every client, and the 4-way "
         "handshake messages. Q: which messages carry the ANonce / SNonce / "
         "MIC, and why do you need all three before any key can be tested?"),
        ("2. Prove a WRONG key fails",
         "Try `wpa-lab try --ssid <ssid> --password letmein123`. Watch the "
         "MIC verification fail. Q: the tool knew the key was wrong without "
         "decrypting a single data frame — explain how the handshake MIC is "
         "an offline key-verifier, and what that implies for attackers' "
         "offline password guesses (and why WPA3-SAE removes this shortcut)."),
        ("3. Authorized decryption with the lab key",
         "Now use the passphrase the instructor issued (or `--pmk` with the "
         "issued PMK). Watch the MIC verify, then the data frames decrypt. "
         "List every protocol/hostname/HTTP path that just became visible. "
         "Q: what could you see *before* the key (MACs, sizes, timing) and "
         "why is that metadata still privacy-relevant?"),
        ("4. The missing-handshake failure case",
         "Use the instructor's late-start capture (`make-fixture "
         "--no-handshake`, or trim the pcap). Even the correct passphrase "
         "now yields *no decryption*. Q: the PMK is the same — what is "
         "actually missing (fresh PTK needs both nonces)? Connect this to "
         "why the deauth-kick → forced-rejoin pattern exists in real "
         "attacks, and how `wifiscanner ids` detects it."),
        ("5. Group traffic and the GTK",
         "Check the ARP broadcast in the decrypted list. It decrypted even "
         "though your passphrase-PTK never touches it. Q: find where the GTK "
         "travelled (encrypted inside handshake message 3, wrapped by the "
         "KEK) and explain why anyone on the network can read broadcast "
         "traffic anyway."),
        ("6. Decrypt-against-Wireshark cross-check",
         "Open the exported `wpa_lab_decrypted.pcap` (Ethernet) in Wireshark "
         "and confirm the DNS/HTTP flow. Then load the ORIGINAL capture with "
         "the passphrase set in 802.11 decryption settings and confirm both "
         "tools agree frame-for-frame. Q: why do both demand SSID+password "
         "(or raw PSK) *and* the handshake?"),
    ]
    if only:
        return f"Exercise {only}:\n{ex[only - 1][0]}\n\n{ex[only - 1][1]}\n"
    out = ["WPA lab — guided exercises (instructor copies these to the "
           "worksheet)", ""]
    for t, body in ex:
        out += [f"■ {t}", body, ""]
    return "\n".join(out)


# ------------------------------------------------------------------ the web

_CSS = """
:root{--bg:#0f172a;--card:#1e293b;--ink:#e2e8f0;--mut:#94a3b8;--acc:#38bdf8;
--ok:#34d399;--warn:#fbbf24;--bad:#f87171;--line:#334155}
*{box-sizing:border-box}body{margin:0;font:15px/1.55 -apple-system,Segoe UI,
Roboto,Helvetica,Arial,sans-serif;background:var(--bg);color:var(--ink)}
a{color:var(--acc)}.wrap{max-width:1000px;margin:0 auto;padding:24px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;
padding:20px;margin:14px 0}
h1{font-size:22px;margin:6px 0}h2{font-size:17px;margin:18px 0 8px}
.small{color:var(--mut);font-size:12.5px}
table{width:100%;border-collapse:collapse;font-size:13px;margin-top:8px}
th,td{text-align:left;padding:5px 8px;border-bottom:1px solid var(--line);
vertical-align:top;font-family:ui-monospace,monospace}
th{color:var(--mut);font-weight:600;font-size:11.5px;text-transform:uppercase}
.ok{color:var(--ok);font-weight:600}.bad{color:var(--bad)}
.warn{color:var(--warn)}.lock{color:var(--warn)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
gap:10px;margin:12px 0}
.stat{background:#0b1220;border:1px solid var(--line);border-radius:10px;
padding:12px}.stat b{display:block;font-size:24px}
.btn{display:inline-block;background:var(--acc);color:#082f49;border:0;
border-radius:8px;padding:10px 16px;font-weight:600;cursor:pointer;
text-decoration:none;font-size:14px}
.btn.danger{background:var(--bad);color:#450a0a}
.btn.ghost{background:transparent;color:var(--acc);border:1px solid var(--acc)}
input[type=text],input[type=password]{width:100%;padding:10px 12px;margin:6px 0
12px;border-radius:8px;border:1px solid var(--line);background:#0b1220;
color:var(--ink);font-size:14px;font-family:ui-monospace,monospace}
code{background:#0b1220;padding:1px 5px;border-radius:4px}
.hero{background:#0b1220;border:1px dashed var(--warn);border-radius:10px;
padding:12px 14px;margin:14px 0}
"""


def _page(title, body):
    doc = ("<!doctype html><html lang='en'><head><meta charset='utf-8'>"
           "<meta name='viewport' content='width=device-width,initial-scale=1'>"
           f"<title>{html.escape(title)}</title><style>{_CSS}</style>"
           f"</head><body>{body}</body></html>")
    return doc.encode("utf-8")


class WpaWebApp:
    """Shared state for the lab web server."""

    def __init__(self, pcap_path, store: WpaLabStore, instructor_keys: list,
                 token: str):
        self.path = pcap_path
        self.store = store
        self.keys = list(instructor_keys)       # laboratory-controlled keys
        self.token = token
        self.started = time.time()
        self.lock = threading.RLock()
        self.analysis = analyze_capture(parse_capture(pcap_path))
        self.result = decrypt_capture_slow(self.analysis, [])   # only parses
        self.best = None                        # last successful decrypt

    def inventory(self):
        a = self.analysis
        hs = a["handshakes"]
        n_lock = sum(1 for f in a["frames"]
                     if f.ftype == 2 and f.protected)
        return {"file": os.path.basename(self.path),
                "frames": len(a["frames"]),
                "encrypted": n_lock,
                "eapol": sum(len(h["msgs"]) for h in hs),
                "handshakes": hs,
                "aps": list(a["aps"].values()),
                "unlocked": bool(self.result["sessions"])}


def decrypt_capture_slow(analysis, keys):
    return decrypt_capture(analysis, keys)


def _student_home(app: WpaWebApp) -> bytes:
    inv = app.inventory()
    ssid = inv["aps"][0]["ssid"] if inv["aps"] else "(unknown)"
    gen = inv["aps"][0]["security"] if inv["aps"] else "?"
    ch = inv["aps"][0]["channel"] if inv["aps"] else "?"
    hs_rows = ""
    for h in inv["handshakes"]:
        hs_rows += (f"<tr><td>{h['ap_s']}</td><td>{h['sta_s']}</td>"
                    f"<td>{sorted(set(h['msgs']))}</td><td>"
                    f"{'✅ complete' if h['complete'] else '⚠ incomplete'}"
                    f"</td></tr>")
    body = f"""
<div class='wrap'>
 <h1>🔐 WPA/WPA2/WPA3 decryption lab</h1>
 <p class='small'>capture: <code>{html.escape(inv['file'])}</code> ·
 LAN-isolated training exercise — laboratory keys only</p>
 <div class='grid'>
  <div class='stat'>frames<b>{inv['frames']}</b></div>
  <div class='stat'>encrypted data<b>{inv['encrypted']}</b></div>
  <div class='stat'>EAPOL messages<b>{inv['eapol']}</b></div>
  <div class='stat'>network<b>{html.escape(gen)}</b></div>
 </div>
 <div class='card'>
  <h2>The capture in one look</h2>
  <p>SSID <code>{html.escape(ssid)}</code> on channel {ch}, generation
  <b>{html.escape(gen)}</b>. Everything except management frames and the
  handshake below is sealed: you can see MAC addresses, frame sizes and
  timing — nothing else. That 'before' view is precisely what any
  eavesdropper gets without the key.</p>
  <table><tr><th>AP</th><th>Client</th><th>Messages seen</th>
  <th>Status</th></tr>{hs_rows}</table>
 </div>
 <div class='card'>
  <h2>Try your laboratory key</h2>
  <form method='POST' action='/try' autocomplete='off'>
   <label>SSID (the passphrase is stretched with it)</label>
   <input type='text' name='ssid' value='{html.escape(ssid)}'>
   <label>Candidate passphrase — or a 64-hex authorized PMK from your
   instructor</label>
   <input type='password' name='candidate' placeholder='what the teacher gave you'>
   <button class='btn'>Verify &amp; decrypt</button>
  </form>
  <p class='small'>Your candidate is verified against the handshake MIC
  <i>before</i> any data frame is touched; every attempt is logged for the
  instructor. {('🔓 This session is currently UNLOCKED — see '
                '<a href="/frames">the frames</a>.') if inv['unlocked'] else
               '🔒 This session is locked until a key verifies.'}</p>
 </div>
 <p><a class='btn ghost' href='/exercises'>📋 guided exercises</a>
 <a class='btn ghost' href='/frames'>🧾 frame list</a></p>
 <div class='hero'><b>Teaching note:</b> without authorisation (the key +
 handshake), the encrypted frames below are indistinguishable from noise.
 That is the entire point of WPA2/WPA3 — and of this lab.</div>
</div>"""
    return _page("WPA decryption lab", body)


def _result_page(app, verdict: dict, newly: int) -> bytes:
    ok = verdict["verdict"] == "accepted"
    inv = app.inventory()
    if ok:
        flows = [r for r in app.result["rows"] if r["status"] == "decrypted"]
        lis = "".join(
            f"<tr><td>{r['idx']}</td><td>{html.escape(r['sa'])}</td>"
            f"<td>{html.escape(r['da'])}</td><td class='ok'>"
            f"{html.escape(r['plain_kind'])}</td>"
            f"<td>{html.escape(r['info'][:120])}</td></tr>" for r in flows[:25])
        banner = (f"<div class='card' style='border-color:var(--ok)'>"
                  f"<h1>✅ Key verified — handshake MIC matched</h1>"
                  f"<p>{html.escape(verdict['detail'])}</p>"
                  f"<p><b>{newly}</b> previously-sealed frames decrypted. "
                  f"Below: what the attacker WITHOUT the key could never see."
                  f"</p><table><tr><th>#</th><th>From</th><th>To</th>"
                  f"<th>Proto</th><th>Revealed content</th></tr>"
                  f"{lis or '<tr><td colspan=5>(nothing extra)</td></tr>'}"
                  f"</table><p><a class='btn' href='/frames'>compare every "
                  f"frame, before vs after →</a></p></div>")
    else:
        why = verdict["detail"]
        banner = (f"<div class='card' style='border-color:var(--bad)'>"
                  f"<h1>❌ {html.escape(verdict['verdict'])}</h1>"
                  f"<p>{html.escape(why)}</p>"
                  f"<div class='hero'>The handshake message-2 MIC is an "
                  f"offline yes/no oracle for your candidate key. Nothing "
                  f"decrypted, nothing leaks — the network's encryption "
                  f"did its job. Check the worksheet and try again, or read "
                  f"<a href='/exercises'>exercise 2</a> to understand the "
                  f"mechanism.</div></div>")
    return _page("Lab result", banner + "<div class='wrap'><p>"
                 "<a href='/'>← back</a></p></div>")


def _frames_page(app) -> bytes:
    rows = app.result["rows"]
    trs = []
    for r in rows[:400]:
        if r["status"] == "decrypted":
            status, info = "<span class='ok'>DECRYPTED</span>", \
                f"{r['plain_kind']} — {html.escape(r['info'][:90])}"
        elif r["status"] in ("locked", "no-handshake"):
            status = "<span class='lock'>🔒 sealed</span>"
            info = html.escape(r["info"])
        else:
            status = html.escape(r["status"])
            info = html.escape((r["info"] or "")[:90])
        trs.append(f"<tr><td>{r['idx']}</td><td>{r['type']}</td>"
                   f"<td>{html.escape(r['sa'])}</td>"
                   f"<td>{html.escape(r['da'])}</td><td>{r['len']}</td>"
                   f"<td>{status}</td><td>{info}</td></tr>")
    body = f"""
<div class='wrap'>
 <h1>🧾 Frame list — before vs after</h1>
 <p class='small'>{len(rows)} frames · a '🔒 sealed' row is all anyone sees
 without the verified key; a 'DECRYPTED' row shows what the authorised key
 revealed in that exact frame.</p>
 <div class='card'><table>
 <tr><th>#</th><th>Type</th><th>From</th><th>To</th><th>Len</th>
 <th>Status</th><th>What it shows</th></tr>{''.join(trs)}</table></div>
 <p><a href='/'>← home</a></p></div>"""
    return _page("Frames — before/after", body)


def _exercises_page(app) -> bytes:
    body = ["<div class='wrap'><h1>📋 Guided exercises</h1>"]
    for block in exercises_text().split("■ ")[1:]:
        title, _, rest = block.partition("\n")
        body.append(f"<div class='card'><h2>{html.escape(title)}</h2>"
                    f"<p style='white-space:pre-wrap'>"
                    f"{html.escape(rest.strip())}</p></div>")
    body.append("<p><a href='/'>← home</a></p></div>")
    return _page("Exercises", "".join(body))


_DASH_JS = """
const TOKEN="__TOKEN__";
function td(t,p,c){const e=document.createElement('td');
 e.textContent=(t===null||t===undefined)?'-':String(t);if(c)e.className=c;
 p.appendChild(e);}
async function tick(){try{const r=await fetch('/api/state?token='+TOKEN);
 if(!r.ok)return;const d=await r.json();
 document.getElementById('s_v').textContent=d.funnel.visits;
 document.getElementById('s_t').textContent=d.funnel.tries;
 document.getElementById('s_s').textContent=d.funnel.successes;
 document.getElementById('s_d').textContent=d.funnel.frames_decrypted;
 const at=document.getElementById('tries');at.innerHTML='';
 d.attempts.forEach(a=>{const tr=document.createElement('tr');
  td(a.time,tr);td(a.ssid,tr);td(a.candidate,tr);
  td(a.verdict,tr,a.verdict==='accepted'?'ok':'bad');
  td(a.frames_decrypted,tr);td(a.ip,tr);at.appendChild(tr);});
 const ev=document.getElementById('ev');ev.innerHTML='';
 d.events.forEach(e=>{const tr=document.createElement('tr');
  td(e.time,tr);td(e.kind,tr);td(e.detail,tr);td(e.ip,tr);ev.appendChild(tr);});
 document.getElementById('stamp').textContent=
  'updated '+new Date().toLocaleTimeString();
}catch(e){}}
async function doReset(){if(!confirm('Wipe ALL attempts and events?'))return;
 await fetch('/api/reset?token='+TOKEN,{method:'POST'});tick();}
async function doUnlock(){if(!confirm('Unlock the session with the FIRST '
 +'instructor key (authorised lab decryption)?'))return;
 await fetch('/api/instructor-unlock?token='+TOKEN,{method:'POST'});tick();}
document.getElementById('resetBtn').addEventListener('click',doReset);
const ub=document.getElementById('unlockBtn');
if(ub) ub.addEventListener('click',doUnlock);
tick();setInterval(tick,3000);
"""


def _dashboard_page(app: WpaWebApp) -> bytes:
    js = _DASH_JS.replace("__TOKEN__", app.token)
    keys_lis = "".join(f"<li><code>{html.escape(k.label)}</code></li>"
                       for k in app.keys) or "<li>(none set — students only)</li>"
    ses = app.result["sessions"]
    unlock = ("<span class='ok'>UNLOCKED</span>: "
              + ", ".join(html.escape(k) for k in ses)) if ses \
        else "<span class='bad'>LOCKED</span>"
    body = f"""
<div class='wrap'>
 <h1>🎓 Instructor dashboard — WPA lab</h1>
 <p class='small'>capture <code>{html.escape(os.path.basename(app.path))}</code>
 · session state: {unlock} · <span id='stamp'>loading…</span></p>
 <div class='grid'>
  <div class='stat'>student page views<b id='s_v'>0</b></div>
  <div class='stat'>key attempts<b id='s_t'>0</b></div>
  <div class='stat'>verifications<b id='s_s'>0</b></div>
  <div class='stat'>frames unlocked<b id='s_d'>0</b></div>
 </div>
 <div class='card'><h2>Authorized key material (lab-controlled)</h2>
  <ul>{keys_lis}</ul>
  <p class='small'>Set at launch with --password/--psk/--pmk/--key-file.
  These values NEVER leave this server and are never shown to students.</p></div>
 <div class='card'><h2>Student key attempts (detection log)</h2>
  <table><tr><th>Time</th><th>SSID</th><th>Candidate</th><th>Verdict</th>
  <th>Frames</th><th>IP</th></tr><tbody id='tries'></tbody></table></div>
 <div class='card'><h2>Events</h2>
  <table><tr><th>Time</th><th>Kind</th><th>Detail</th><th>IP</th></tr>
  <tbody id='ev'></tbody></table></div>
 <div class='card'><h2>Controls</h2>
  <button class='btn' id='unlockBtn'>🔑 Authorised decrypt with lab key</button>
  <button class='btn danger' id='resetBtn'>🧹 Reset session</button>
  <a class='btn ghost' href='/'>student view</a>
  <p class='small'>CLI equivalents: <code>wifiscanner wpa-lab decrypt
  CAP.pcap --password … -o out</code> · restart the server to wipe the DB.</p>
 </div></div><script>{js}</script>"""
    return _page("Instructor dashboard", body)


_MAX_POST = 8192


class _Handler(BaseHTTPRequestHandler):
    server_version = "wifiscanner-wpalab"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        log.debug("wpalab http: " + fmt, *[str(a)[:80] for a in args])

    @property
    def app(self) -> WpaWebApp:
        return self.server.app

    def _send(self, body: bytes, status: int = 200,
              ctype: str = "text/html; charset=utf-8"):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, obj, status: int = 200):
        self._send(json.dumps(obj, indent=1, default=str).encode(), status,
                   "application/json; charset=utf-8")

    def _redirect(self, loc):
        self.send_response(303)
        self.send_header("Location", loc)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _client(self):
        return self.client_address[0]

    def _ua(self):
        return self.headers.get("User-Agent", "")[:200]

    def _tok_ok(self, u):
        tok = parse_qs(u.query).get("token", [""])[0]
        return bool(tok) and _secrets.compare_digest(tok, self.app.token)

    # ---------------- GET ----------------
    def do_GET(self):
        u = urlparse(self.path)
        path = u.path.rstrip("/") or "/"
        app = self.app
        if path == "/health":
            return self._json({"ok": True, "lab": "wpa"})
        if path == "/":
            app.store.event("page-view", "student home", self._client())
            return self._send(_student_home(app))
        if path == "/frames":
            app.store.event("page-view", "frames", self._client())
            return self._send(_frames_page(app))
        if path == "/exercises":
            app.store.event("page-view", "exercises", self._client())
            return self._send(_exercises_page(app))
        if path == "/favicon.ico":
            return self._send(b"", 204, "image/x-icon")
        if path == "/api/state":
            if not self._tok_ok(u):
                return self._json({"error": "not found"}, 404)
            return self._json({
                "inventory": {"frames": app.inventory()["frames"],
                              "encrypted": app.inventory()["encrypted"],
                              "unlocked": app.inventory()["unlocked"]},
                "funnel": app.store.funnel(),
                "attempts": app.store.attempts(300),
                "events": app.store.events(200),
                "sessions": {k: v.as_dict()
                             for k, v in app.result["sessions"].items()}})
        if path == "/i/" + app.token:
            app.store.event("page-view", "instructor dashboard",
                            self._client())
            return self._send(_dashboard_page(app))
        if path.startswith("/i/"):
            return self._json({"error": "not found"}, 404)
        return self._redirect("/")

    # ---------------- POST ----------------
    def do_POST(self):
        u = urlparse(self.path)
        path = u.path.rstrip("/") or "/"
        app = self.app
        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
        except ValueError:
            length = 0
        if length > _MAX_POST:
            return self._json({"error": "payload too large"}, 413)
        raw = self.rfile.read(length) if length else b""
        form = {k: v[0] for k, v in
                parse_qs(raw.decode("utf-8", "ignore"),
                         keep_blank_values=True).items()}

        if path == "/try":
            ssid = form.get("ssid", "").strip()
            cand = form.get("candidate", "")
            verdict = app_attempt(app, ssid, cand,
                                  self._client(), self._ua())
            log.info("wpalab attempt: candidate=%r ssid=%r -> %s",
                     cand, ssid, verdict["verdict"])
            return self._send(_result_page(app, verdict,
                                           app.result["decrypted"]))

        if path == "/api/reset":
            if not self._tok_ok(u):
                return self._json({"error": "not found"}, 404)
            with app.lock:
                removed = app.store.reset()
                app.result = decrypt_capture_slow(app.analysis, [])
            app.store.event("reset", f"{removed} rows wiped", self._client())
            return self._json({"ok": True, "removed": removed})

        if path == "/api/instructor-unlock":
            if not self._tok_ok(u):
                return self._json({"error": "not found"}, 404)
            with app.lock:
                app.result = decrypt_capture_slow(app.analysis, app.keys)
                n = app.result["decrypted"]
            app.store.event("instructor-unlock",
                            f"authorised decrypt: {n} frames with lab key",
                            self._client())
            return self._json({"ok": True, "decrypted": n})

        return self._json({"error": "not found"}, 404)


def app_attempt(app: WpaWebApp, ssid: str, cand: str, ip: str, ua: str) -> dict:
    """Student-facing attempt runner: verify candidate, decrypt on success,
    log it. Candidate may be a passphrase (needs ssid) or 64-hex PMK."""
    detail = ""
    try:
        key = LabKey(cand, ssid=ssid)
    except (ValueError, Exception) as exc:
        verdict = {"verdict": "invalid-input", "detail": str(exc)}
        app.store.attempt(ssid, cand, verdict["verdict"], verdict["detail"],
                          0, ip, ua)
        return verdict
    hs = app.analysis["handshakes"]
    if not hs:
        verdict = {"verdict": "no-handshake",
                   "detail": "this capture contains no EAPOL handshake — "
                             "even the right key cannot help (exercise 4)"}
    else:
        best = None
        for bundle in hs:
            cipher = app.analysis["aps"].get(bundle["ap_s"], {})\
                .get("cipher") or "ccmp"
            try:
                sess = try_key_on_bundle(bundle, key, cipher)
            except LabError as exc:
                verdict = {"verdict": "no-handshake", "detail": str(exc)}
                best = verdict
                continue
            if sess:
                best = {"verdict": "accepted",
                        "detail": f"MIC verified against handshake M2 of "
                                  f"{bundle['sta_s']}@{bundle['ap_s']}"}
                break
            best = {"verdict": "wrong-key",
                    "detail": "handshake MIC mismatch — this candidate "
                              "cannot be the network key"}
        verdict = best
    frames_n = 0
    if verdict["verdict"] == "accepted":
        with app.lock:
            app.result = decrypt_capture_slow(
                app.analysis, app.keys + [LabKey(cand, ssid=ssid)])
        frames_n = app.result["decrypted"]
    app.store.attempt(ssid, cand, verdict["verdict"], verdict["detail"],
                      frames_n, ip, ua)
    return verdict


class WpaLabServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, app: WpaWebApp):
        self.app = app
        super().__init__(address, _Handler)


def make_web_server(bind: str, port: int, app: WpaWebApp) -> WpaLabServer:
    return WpaLabServer((bind, int(port)), app)
