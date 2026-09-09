"""Authorized, defensive packet injection: verify YOUR sensors and YOUR PMF.

This is the *only* transmitting component of an otherwise 100% receive-only
toolkit. It exists so an operator can answer two defensive questions that
passive listening alone cannot:

1. "Do my passive IDS sensors actually HEAR the channels they claim to?"
   -> ``mode=canary``    transmits distinctive, harmless probe-request markers
      and lets you confirm every remote sensor logged them (coverage test).

2. "Does enabling PMF / 802.11w on MY router actually stop deauth kicks?"
   -> ``mode=pmf-test``  sends a tiny, bounded burst of deauthentication
      frames at ONE of your own clients, then observes whether the client
      stays associated (PMF works) or gets kicked and re-joins (PMF missing).

3. "Authorised deauthentication/disassociation testing of MY OWN network"
   -> ``mode=deauth``     a bounded, unicast, explicitly-acknowledged burst
      of deauth and/or disassociation frames aimed at ONE client you own, to
      validate client resilience, IDS response and roaming. Larger than the
      pmf-test probe but still hard-capped, one-shot, logged and target-
      restricted - a pen-test action, never a sustained attack.

4. "Does my IDS actually catch an Evil Twin / rogue AP beacons MY SSID?"
   -> ``mode=evil-twin``  a bounded, authorised *detection drill*: it
      transmits BEACON FRAMES ONLY that advertise a network name you own from
      a fresh, locally-administered BSSID, for a few seconds on one channel,
      so you can confirm your warden baseline / `ids` flags the spoofed BSSID
      and your `scan` rogue heuristics flag the same-SSID clone. There is
      deliberately NO association/authentication/EAPOL/DHCP/data path: the
      drill cannot accept a client, capture a handshake or credential, or
      relay traffic - a beaconing radio that never answers is not a working
      AP and cannot be used as one. It self-terminates after a hard-capped
      window and every beacon is audited.

``mode=probe`` is ordinary active scanning - byte-for-byte the same probe
requests every laptop/phone OS broadcasts while scanning for networks; it
makes the survey deterministic instead of waiting for beacons.

``mode=ids-selftest`` is fully OFFLINE: it synthesises the attack signatures
in memory (no radio at all) and confirms the IDS watchdog fires on each.
Use it in CI / before deploying a sensor.

Hard safety gates (every one enforced in code, not just documented)
-------------------------------------------------------------------
* root / admin privileges are required for ANY over-the-air transmission;
* NOTHING is transmitted unless BOTH ``--transmit`` and ``--authorized`` are
  passed - the default is a dry run that only builds and displays frames;
* the kick modes (``pmf-test`` AND ``deauth``) additionally require ``--yes``
  AND an explicit unicast ``--bssid`` and ``--client`` - broadcast/multicast
  or wildcard kicking is refused outright;
* burst sizes are hard-capped per mode and spaced by a minimum interval so a
  single run can never become a sustained flood/denial-of-service;
* every frame (or would-be frame) is recorded in an owner-only (0600) audit CSV.

What this module deliberately refuses to do
-------------------------------------------
unbounded or looped deauth/disassoc FLOODS, broadcast or wildcard kicking,
AP cloning or beacon forgery, channel jamming, replay of captured third-party
frames, evil-twin operation, or any transmission outside airspace you own or
are authorised to test. Those are attack tools, not defence tools, and they
do not belong in a sensor.
"""
from __future__ import annotations

import csv
import os
import threading
import time
from dataclasses import dataclass
from typing import Callable, List, Optional, Tuple

from .oui import is_multicast, normalize
from .privacy import secure_file
from .util import is_root, log

# ----------------------------------------------------------------- limits
# Hard ceilings. These cannot be raised from the CLI by design. The pmf-test
# stays deliberately below the IDS flood threshold (5 deauths/10 s at medium
# sensitivity -> max 4) so the *probe* traffic never looks like an attack.
# The explicit deauth/disassoc TEST mode is allowed a larger one-shot burst
# (an authorised pen-test that intentionally exercises IDS response and the
# client's resilience), but it remains bounded: a single run, a minimum
# inter-frame spacing, and never a loop - so it cannot become a sustained
# denial-of-service.
MAX_PROBE_PER_CHANNEL = 6
MAX_CANARY_PER_CHANNEL = 4
MAX_DEAUTH_BURST = 4              # pmf-test: < Watchdog.effective_flood_n (5)
MAX_KICK_BURST = 30              # deauth mode: hard one-shot total frame cap
MIN_FRAME_INTERVAL_S = 0.30       # floor between transmitted frames
DEFAULT_FRAME_INTERVAL_S = 0.45
KICK_FRAME_INTERVAL_S = 0.30      # kick bursts use the floor spacing
BEACON_INTERVAL_S = 0.30         # evil-twin drill: ~3 beacons/s, like a real AP
MAX_TWIN_DURATION_S = 60.0       # a drill self-terminates after this at most
DEFAULT_TWIN_DURATION_S = 20.0
MAX_TWIN_BEACONS = 240           # hard ceiling on total beacons per run
DEFAULT_DWELL_S = 2.5             # listen per channel after a probe burst
PMF_BASELINE_S = 5.0             # observe client activity before the burst
PMF_VERIFY_S = 8.0              # observe after the burst for re-association
DEAUTH_REASON = 7               # Class-3 frame from non-associated STA (standard)
DISASOC_REASON = 8            # Disassoc: disassociate due to STA leaving
BEACON_INTERVAL_TU = 100        # 100 TU ~= 0.102 s (advertised, not the TX gap)

# 802.11 management-frame subtypes (IEEE 802.11).
SUBTYPE_ASSOC_REQ = 0
SUBTYPE_DISASSOC = 10
SUBTYPE_AUTH = 11
SUBTYPE_DEAUTH = 12
SUBTYPE_REASSOC_REQ = 2

# Modes that need the extra --yes acknowledgement (any frame that could
# disconnect a client or present an impersonated network).
KICK_MODES = ("pmf-test", "deauth")
CONFIRM_MODES = ("pmf-test", "deauth", "evil-twin")
TWIN_SECURITIES = ("open", "wpa2")

BROADCAST = "FF:FF:FF:FF:FF:FF"
CANARY_PREFIX = "WIFISCANNER-CANARY-"


class InjectionError(Exception):
    """Raised when a safety gate refuses an injection request."""


# ------------------------------------------------------------ frame builders

def random_local_mac() -> str:
    """A random unicast, locally-administered MAC (privacy by default).

    Probe requests sent with a rotated LAA address look identical to the
    randomized probe MACs modern OSes already use, so active scanning here
    does not add a stable hardware fingerprint to the air.
    """
    import secrets
    val = secrets.randbits(48)
    val &= ~0x010000000000        # clear I/G (multicast) bit -> unicast
    val |= 0x020000000000        # set U/L bit -> locally administered
    return ":".join(f"{(val >> (8 * i)) & 0xFF:02X}" for i in range(5, -1, -1))


def new_canary_token() -> str:
    import secrets
    return CANARY_PREFIX + secrets.token_hex(3).upper()


def build_probe_request(src_mac: str, ssid: str = ""):
    """One 802.11 probe-request frame. Empty ``ssid`` = wildcard probe."""
    from scapy.all import Dot11, Dot11ProbeReq, Dot11Elt, RadioTap
    src = normalize(src_mac)
    pkt = (RadioTap()
           / Dot11(type=0, subtype=4, addr1=BROADCAST, addr2=src,
                   addr3=BROADCAST)
           / Dot11ProbeReq())
    pkt /= Dot11Elt(ID=0, info=(ssid or "").encode("utf-8", "replace"))
    # Supported rates (1/2/5.5/11/18/24/36/54 Mbps) + extended supported
    # rates - the identical IE set a normal client probes with.
    pkt /= Dot11Elt(ID=1, info=bytes([0x82, 0x84, 0x8B, 0x96,
                                      0x0C, 0x12, 0x18, 0x24]))
    pkt /= Dot11Elt(ID=50, info=bytes([0x30, 0x48, 0x60, 0x6C]))
    pkt /= Dot11Elt(ID=46, info=bytes([0x05, 0x04, 0x00, 0x04]))   # channels
    return pkt


def build_deauth(bssid: str, client: str, reason: int = DEAUTH_REASON,
                 direction: str = "ap-to-sta"):
    """One 802.11 deauthentication frame.

    direction="ap-to-sta" (default): the AP tells the client to leave
    (addr1=STA, addr2/3=BSSID) - what a spoofed AP kick looks like.
    direction="sta-to-ap": the client tells the AP it is leaving
    (addr1/3=BSSID, addr2=STA) - the spoofed-client direction.
    Authorised self-test on YOUR OWN BSS only; broadcast targets are refused.
    """
    from scapy.all import Dot11, Dot11Deauth, RadioTap
    bssid, client = normalize(bssid), normalize(client)
    if direction == "sta-to-ap":
        return (RadioTap()
                / Dot11(type=0, subtype=SUBTYPE_DEAUTH, addr1=bssid,
                        addr2=client, addr3=bssid)
                / Dot11Deauth(reason=reason))
    return (RadioTap()
            / Dot11(type=0, subtype=SUBTYPE_DEAUTH, addr1=client,
                    addr2=bssid, addr3=bssid)
            / Dot11Deauth(reason=reason))


def build_disassoc(bssid: str, client: str, reason: int = DISASOC_REASON,
                   direction: str = "ap-to-sta"):
    """One 802.11 disassociation frame (management subtype 10).

    Disassociation is the "polite" cousin of deauthentication: it asks a
    *currently associated* station to drop the association (it can re-associate
    without re-authenticating). Same two directions as build_deauth.
    """
    from scapy.all import Dot11, Dot11Disas, RadioTap
    bssid, client = normalize(bssid), normalize(client)
    if direction == "sta-to-ap":
        return (RadioTap()
                / Dot11(type=0, subtype=SUBTYPE_DISASSOC, addr1=bssid,
                        addr2=client, addr3=bssid)
                / Dot11Disas(reason=reason))
    return (RadioTap()
            / Dot11(type=0, subtype=SUBTYPE_DISASSOC, addr1=client,
                    addr2=bssid, addr3=bssid)
            / Dot11Disas(reason=reason))


# A minimal, valid WPA2-PSK/CCMP RSN information element (IE 48). It is only
# enough to make the *beacon* advertise "WPA2" so the clone is recognisable;
# there is no associated state machine to act on it.
_RSN_WPA2_PSK_CCMP = bytes.fromhex(
    "30140100000fac020200000fac040100000fac020c00")


def build_beacon(bssid: str, ssid: str, channel: int = 6,
                 security: str = "open"):
    """One 802.11 beacon that *advertises* a network (the Evil-Twin drill).

    Beacons are what every access point broadcasts ~10x/second to announce
    its presence. Emitting one is what a fake/rogue AP does to be SEEN - but
    a beacon alone cannot serve anyone: a real AP must also answer probe
    requests, authenticate, associate and run a DHCP/data path. This builder
    (and the injector) deliberately create ONLY the beacon, so the result is
    detectable as a rogue BSSID yet cannot accept a client or intercept
    traffic. ``security="open"`` advertises no RSN (the classic open-clone);
    ``security="wpa2"`` advertises WPA2-PSK/CCMP.
    """
    from scapy.all import Dot11, Dot11Beacon, Dot11Elt, RadioTap
    bssid = normalize(bssid)
    # cap ESS(0x1) + privacy bit for WPA2 (0x10)
    cap = 0x0011 if security == "wpa2" else 0x0001
    pkt = (RadioTap()
           / Dot11(type=0, subtype=8, addr1=BROADCAST, addr2=bssid,
                   addr3=bssid)
           / Dot11Beacon(cap=cap, beacon_interval=BEACON_INTERVAL_TU))
    pkt /= Dot11Elt(ID=0, info=(ssid or "").encode("utf-8", "replace"))
    pkt /= Dot11Elt(ID=1, info=bytes([0x82, 0x84, 0x8B, 0x96,
                                      0x0C, 0x12, 0x18, 0x24]))
    pkt /= Dot11Elt(ID=3, info=bytes([channel & 0xFF]))          # DS parameter
    if security == "wpa2":
        pkt /= Dot11Elt(ID=48, info=_RSN_WPA2_PSK_CCMP)
    return pkt


# ------------------------------------------------------------- frame anatomy

def frame_summary(pkt) -> str:
    """One-line human description of a built/observed 802.11 frame."""
    from scapy.all import Dot11
    from scapy.layers.dot11 import Dot11Deauth, Dot11Disas
    d = pkt.getlayer(Dot11)
    if d is None:
        return "non-802.11 frame"
    t, st = int(d.type), int(d.subtype)
    if t == 0 and st == 4:
        ssid = _elt_ssid(pkt)
        return f"probe-request  {d.addr2} -> broadcast  SSID={ssid or '<wildcard>'!r}"
    if t == 0 and st == 8:
        return f"beacon  {d.addr2} -> broadcast  SSID={_elt_ssid(pkt) or '<hidden>'!r}"
    if t == 0 and st == 5:
        return f"probe-response {d.addr2} -> {d.addr1}"
    if t == 0 and st in (SUBTYPE_DEAUTH, SUBTYPE_DISASSOC):
        layer = pkt.getlayer(Dot11Deauth) or pkt.getlayer(Dot11Disas)
        reason = getattr(layer, "reason", "?")
        kind = "deauth" if st == SUBTYPE_DEAUTH else "disassoc"
        return f"{kind}  {d.addr2} -> {d.addr1}  reason={reason}"
    if t == 0 and st in (SUBTYPE_ASSOC_REQ, SUBTYPE_REASSOC_REQ):
        return f"assoc-request  {d.addr2} -> {d.addr1}"
    if t == 2:
        return f"data  {d.addr2} -> {d.addr1}"
    return f"802.11 type={t} subtype={st}  {d.addr2} -> {d.addr1}"


def _elt_ssid(pkt) -> str:
    from scapy.layers.dot11 import Dot11Elt
    el = pkt.getlayer(Dot11Elt)
    while el is not None:
        try:
            if el.ID == 0:
                return bytes(el.info).decode("utf-8", "replace").strip("\x00")
        except Exception:
            return ""
        el = el.payload.getlayer(Dot11Elt)
    return ""


# ------------------------------------------------------------------- gating

def gate_transmission(mode: str, *, transmit: bool, authorized: bool,
                      confirmed: bool = False,
                      _root: Optional[bool] = None) -> None:
    """Refuse to transmit unless every consent / privilege gate is satisfied.

    Dry runs (``transmit=False``) never touch the radio and need no root -
    they only build frames in memory so the operator can preview an action.
    """
    root = is_root() if _root is None else _root
    if not transmit:
        return
    # Consent gates first, so a non-root user is still told what explicit
    # authorization a live transmission would require.
    if not authorized:
        raise InjectionError(
            "refusing to TRANSMIT: pass --authorized to confirm you own the "
            "target network (or are authorised in writing to test it), and "
            "--transmit to leave dry-run mode.")
    if mode in KICK_MODES and not confirmed:
        raise InjectionError(
            f"{mode} sends deauthentication/disassociation frames that will "
            "briefly disconnect the named client if management-frame "
            "protection is NOT in force. It requires --yes in addition to "
            "--authorized/--transmit, plus an explicit unicast --bssid "
            "(YOUR AP) and --client (YOUR test device).")
    if mode == "evil-twin" and not confirmed:
        raise InjectionError(
            "evil-twin transmits beacons that IMPERSONATE an SSID. This is "
            "a detection drill for a network name YOU own: it requires --yes "
            "in addition to --authorized/--transmit, and is beacon-only "
            "(it cannot accept clients or relay traffic).")
    if not root:
        raise InjectionError(
            "over-the-air injection requires root privileges (run with sudo). "
            "Re-run without --transmit for a dry run that sends nothing.")


def validate_kick_targets(bssid: str, client: str, mode: str = "pmf-test"
                          ) -> Tuple[str, str]:
    """A kick test may only aim a unicast burst at one named AP + one STA."""
    bssid, client = normalize(bssid or ""), normalize(client or "")
    if not bssid or not client:
        raise InjectionError(
            f"{mode} requires --bssid <your-AP-MAC> and --client <your-test-"
            "device-MAC>. A broadcast/wildcard target is refused outright.")
    for label, mac in (("bssid", bssid), ("client", client)):
        if is_multicast(mac):
            raise InjectionError(
                f"--{label} {mac} is a broadcast/multicast address. Kicking "
                "all clients is an attack, not a self-test: name ONE device.")
    return bssid, client


# Backwards-compatible alias (older callers/tests use the pmf-test name).
validate_pmf_targets = validate_kick_targets


def validate_twin(ssid: str, channel: int, security: str,
                  bssid: str = "") -> Tuple[str, int, str, str]:
    """Validate an evil-twin detection drill and resolve its advertised BSSID.

    The SSID must be a network name YOU own (the drill impersonates your own
    SSID to test YOUR sensors); an empty SSID is refused (hidden/blank clones
    serve no detection-drill purpose). BSSID defaults to a fresh random
    locally-administered address so it will NOT match the real AP's BSSID -
    that is precisely the anomaly the warden/rogue heuristics should catch.
    """
    ssid = (ssid or "").strip()
    if not ssid:
        raise InjectionError(
            "evil-twin drill requires --ssid <YOUR-OWN-network-name>. It "
            "beacons a spoofed BSSID advertising that SSID so your IDS/warden "
            "can be tested - blank SSIDs are refused.")
    if security not in TWIN_SECURITIES:
        raise InjectionError(
            f"unsupported --security {security!r}; use 'open' (the classic "
            "open-clone) or 'wpa2'.")
    channel = int(channel) if channel else 6
    if not (1 <= channel <= 196):
        raise InjectionError(f"invalid channel {channel}")
    if bssid:
        bssid = normalize(bssid)
        if is_multicast(bssid):
            raise InjectionError(
                f"--bssid {bssid} is broadcast/multicast; a beaconing BSSID "
                "must be a unicast address.")
    else:
        bssid = random_local_mac()
    return ssid, channel, security, bssid


def clamp_count(mode: str, count: int, *, per_channel: bool = False) -> int:
    cap = {"probe": MAX_PROBE_PER_CHANNEL,
           "canary": MAX_CANARY_PER_CHANNEL,
           "pmf-test": MAX_DEAUTH_BURST,
           "deauth": MAX_KICK_BURST,
           "evil-twin": MAX_TWIN_BEACONS}[mode]
    if count > cap:
        scope = "per channel" if per_channel else "per run"
        log.warning("requested %d frames capped to the hard safety limit of "
                    "%d (%s) for mode %s", count, cap, scope, mode)
    return max(1, min(int(count), cap))


def clamp_twin_duration(duration_s: float) -> float:
    d = max(1.0, float(duration_s or DEFAULT_TWIN_DURATION_S))
    if d > MAX_TWIN_DURATION_S:
        log.warning("evil-twin duration capped to %.0fs (a detection drill "
                    "self-terminates)", MAX_TWIN_DURATION_S)
    return min(d, MAX_TWIN_DURATION_S)


def parse_channels(spec: str, default: Optional[List[int]] = None) -> List[int]:
    if not spec:
        return list(default or [1, 6, 11])
    out = []
    for part in spec.split(","):
        part = part.strip()
        if part.isdigit():
            ch = int(part)
            if ch not in out:
                out.append(ch)
    return out or list(default or [1, 6, 11])


# ------------------------------------------------------------------- audit

class AuditLog:
    """Append-only CSV record of every frame considered; created 0600."""

    COLUMNS = ["ts", "time", "mode", "iface", "tx", "dry_run", "frame",
               "channel", "target", "detail"]

    def __init__(self, path: str):
        self.path = path
        self.rows: List[dict] = []
        d = os.path.dirname(os.path.abspath(path))
        os.makedirs(d, exist_ok=True)
        self._exists = os.path.exists(path)
        self.fh = open(path, "a", newline="", encoding="utf-8")
        self.writer = csv.DictWriter(self.fh, fieldnames=self.COLUMNS,
                                     extrasaction="ignore")
        if not self._exists or os.path.getsize(path) == 0:
            self.writer.writeheader()
        self.fh.flush()
        secure_file(path)

    def record(self, *, mode: str, iface: str, tx: bool, dry_run: bool,
               frame: str, channel: str = "", target: str = "",
               detail: str = "") -> None:
        now = time.time()
        row = {"ts": round(now, 3),
               "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now)),
               "mode": mode, "iface": iface, "tx": int(tx),
               "dry_run": int(dry_run), "frame": frame, "channel": channel,
               "target": target, "detail": detail}
        self.rows.append(row)
        self.writer.writerow(row)
        self.fh.flush()

    def close(self) -> None:
        try:
            self.fh.close()
        except Exception:
            pass
        secure_file(self.path)


# ----------------------------------------------------------- air monitoring

@dataclass
class AirEvent:
    ts: float
    kind: str           # probe | proberesp | deauth | assoc | eapol | data
    src: str
    dst: str
    bssid: str
    rssi: Optional[int] = None
    ssid: str = ""


def classify_frame(pkt) -> Optional[AirEvent]:
    """Reduce a scapy frame to the handful of fields the injection verifiers use."""
    from scapy.all import Dot11
    if not pkt.haslayer(Dot11):
        return None
    d = pkt.getlayer(Dot11)
    t, st = int(d.type), int(d.subtype)
    a1 = normalize(d.addr1 or "")
    a2 = normalize(d.addr2 or "")
    a3 = normalize(d.addr3 or "")
    rssi = None
    try:
        rssi = int(pkt.dBm_AntSignal)
    except Exception:
        pass
    if t == 0 and st == 4:
        return AirEvent(time.time(), "probe", a2, a1, a3, rssi, _elt_ssid(pkt))
    if t == 0 and st == 5:
        return AirEvent(time.time(), "proberesp", a2, a1, a3 or a2, rssi,
                        _elt_ssid(pkt))
    if t == 0 and st in (SUBTYPE_DEAUTH, SUBTYPE_DISASSOC):
        # Both deauth (12) and disassociation (10) are "kick" management
        # frames; tagged distinctly so the verdict can count either.
        kind = "deauth" if st == SUBTYPE_DEAUTH else "disassoc"
        return AirEvent(time.time(), kind, a2, a1, a3 or a2, rssi)
    if t == 0 and st in (SUBTYPE_ASSOC_REQ, SUBTYPE_REASSOC_REQ):
        return AirEvent(time.time(), "assoc", a2, a1, a3 or a1, rssi,
                        _elt_ssid(pkt))
    if t == 2:
        if _is_eapol(pkt, d):
            return AirEvent(time.time(), "eapol", a2, a1, a3 or a1, rssi)
        return AirEvent(time.time(), "data", a2, a1, a3 or a1, rssi)
    return None


def _is_eapol(pkt, d) -> bool:
    from scapy.all import EAPOL
    if pkt.haslayer(EAPOL):
        return True
    try:
        raw = bytes(d.payload)
        return raw[6:8] == b"\x88\x8e" and raw[:3] == b"\xaa\xaa\x03"
    except Exception:
        return False


class AirListener:
    """Background sniffer that records AirEvents (and optionally a pcap)."""

    def __init__(self, iface: str, duration: float,
                 on_packet: Optional[Callable] = None, pcap_path: str = ""):
        self.iface = iface
        self.duration = duration
        self.on_packet = on_packet
        self.pcap_path = pcap_path
        self.events: List[AirEvent] = []
        self.frames = 0
        self._th: Optional[threading.Thread] = None
        self._writer = None

    def _cb(self, pkt) -> None:
        ev = classify_frame(pkt)
        if ev is not None:
            self.events.append(ev)
            self.frames += 1
        if self._writer is not None:
            try:
                self._writer.write(pkt)
            except Exception:
                pass
        if self.on_packet is not None:
            try:
                self.on_packet(pkt)
            except Exception:
                pass

    def start(self) -> None:
        self._th = threading.Thread(target=self._run, daemon=True)
        self._th.start()

    def _run(self) -> None:
        from scapy.all import sniff, PcapWriter
        if self.pcap_path:
            self._writer = PcapWriter(self.pcap_path, sync=True)
            secure_file(self.pcap_path)
        try:
            try:
                sniff(iface=self.iface, prn=self._cb, store=False,
                      timeout=self.duration, monitor=True)
            except Exception:
                sniff(iface=self.iface, prn=self._cb, store=False,
                      timeout=self.duration)
        finally:
            if self._writer is not None:
                try:
                    self._writer.close()
                except Exception:
                    pass

    def join(self) -> None:
        if self._th is not None:
            self._th.join(timeout=self.duration + 10)


# ------------------------------------------------------------------ injector

class Injector:
    """Builds, logs and (only when authorised) transmits 802.11 frames."""

    def __init__(self, iface: str, *, mode: str, dry_run: bool = True,
                 audit: Optional[AuditLog] = None, src_mac: str = "",
                 interval: float = DEFAULT_FRAME_INTERVAL_S):
        self.iface = iface
        self.mode = mode
        self.dry_run = dry_run
        self.audit = audit
        self.src_mac = normalize(src_mac) or random_local_mac()
        self.interval = max(interval, MIN_FRAME_INTERVAL_S)
        self.sent = 0
        self.built = 0
        self._last_send = 0.0

    def _emit(self, pkt, *, frame: str, channel: str = "", target: str = "",
              detail: str = "") -> bool:
        """Log one frame; transmit it unless this is a dry run."""
        self.built += 1
        if self.audit is not None:
            self.audit.record(mode=self.mode, iface=self.iface,
                              tx=not self.dry_run, dry_run=self.dry_run,
                              frame=frame, channel=channel, target=target,
                              detail=detail)
        if self.dry_run:
            log.info("[dry-run] would send ch%s: %s",
                     channel or "-", frame_summary(pkt))
            return False
        now = time.time()
        wait = self.interval - (now - self._last_send)
        if wait > 0:
            time.sleep(wait)
        from scapy.all import sendp
        sendp(pkt, iface=self.iface, verbose=False)
        self.sent += 1
        self._last_send = time.time()
        log.debug("sent ch%s: %s", channel or "-", frame_summary(pkt))
        return True

    # ------------------------------------------------------- high-level TX

    def probe_sweep(self, channels: List[int], ssids: List[str],
                    count: int) -> None:
        for ch in channels:
            if not self.dry_run:                    # dry runs never touch the radio
                _set_channel(self.iface, ch)
            for ssid in ssids:
                for _ in range(count):
                    pkt = build_probe_request(self.src_mac, ssid)
                    self._emit(pkt, frame="probe-request", channel=str(ch),
                               target=BROADCAST,
                               detail=f"ssid={ssid or '<wildcard>'}")

    def canary_sweep(self, channels: List[int], token: str,
                     count: int) -> None:
        for ch in channels:
            if not self.dry_run:
                _set_channel(self.iface, ch)
            for _ in range(count):
                pkt = build_probe_request(self.src_mac, token)
                self._emit(pkt, frame="canary-probe", channel=str(ch),
                           target=BROADCAST, detail=f"token={token}")

    def kick_burst(self, bssid: str, client: str, count: int, *,
                   frame_type: str = "deauth",
                   direction: str = "ap-to-sta") -> None:
        """Send a bounded, unicast burst of deauth and/or disassoc frames.

        frame_type: "deauth" | "disassoc" | "both" (both alternates the two).
        Authorised self-test on YOUR OWN BSS/client only. The deauth/disassoc
        count and spacing are capped by the caller via clamp_count and the
        injector's minimum interval.
        """
        bssid, client = normalize(bssid), normalize(client)
        types = ["deauth", "disassoc"] if frame_type == "both" else [frame_type]
        for i in range(count):
            ftype = types[i % len(types)]
            if ftype == "disassoc":
                pkt = build_disassoc(bssid, client, direction=direction)
                reason = DISASOC_REASON
            else:
                pkt = build_deauth(bssid, client, direction=direction)
                reason = DEAUTH_REASON
            self._emit(pkt, frame=ftype, target=f"{bssid}->{client}",
                       detail=f"reason={reason} dir={direction}")

    def deauth_burst(self, bssid: str, client: str, count: int) -> None:
        """Backwards-compatible deauth-only burst used by the pmf-test."""
        self.kick_burst(bssid, client, count, frame_type="deauth")

    def twin_beacons(self, ssid: str, bssid: str, channel: int,
                     security: str, duration_s: float) -> int:
        """Transmit a bounded beacon train that *advertises* a cloned SSID.

        Detection drill only: sends beacon frames for ``duration_s`` (hard-
        capped, self-terminating), channel-locked, NO probe-response/assoc/
        auth/data path. Returns the number of beacons sent.
        """
        if not self.dry_run:
            _set_channel(self.iface, channel)
        end = time.time() + duration_s
        n = 0
        while n < MAX_TWIN_BEACONS and (self.dry_run or time.time() < end):
            pkt = build_beacon(bssid, ssid, channel, security)
            self._emit(pkt, frame="beacon", channel=str(channel),
                       target=bssid, detail=f"ssid={ssid} sec={security}")
            n += 1
            if self.dry_run:
                break          # dry run previews one representative beacon
        return n


def _set_channel(iface: str, channel: int) -> bool:
    from .backends.sniffer import set_channel
    return set_channel(iface, channel)


# ------------------------------------------------------------- verifications

KICK_KINDS = ("deauth", "disassoc")


def pmf_verdict(events: List[AirEvent], bssid: str, client: str,
                burst_ts: float) -> dict:
    """Backwards-compatible alias for :func:`kick_verdict`."""
    return kick_verdict(events, bssid, client, burst_ts)


def kick_verdict(events: List[AirEvent], bssid: str, client: str,
                 burst_ts: float) -> dict:
    """Decide whether a bounded deauth/disassoc burst actually kicked a client.

    * client keeps exchanging data and never re-associates -> the forged
      deauth/disassoc frames were IGNORED: PMF/802.11w is protecting the
      management plane (PASS).
    * an (re)association or EAPOL from the client follows the burst -> the
      client was disconnected and had to rejoin: management frames are NOT
      protected between this client and BSS (FAIL - fix PMF on both ends).
    * no client frames at all -> inconclusive (idle/asleep/off-channel).
    """
    bssid, client = normalize(bssid), normalize(client)
    before = [e for e in events
              if e.ts < burst_ts and _involves(e, bssid, client)]
    after = [e for e in events
             if e.ts >= burst_ts and _involves(e, bssid, client)]
    data_before = sum(1 for e in before if e.kind == "data")
    data_after = sum(1 for e in after if e.kind == "data")
    reauth_after = [e for e in after if e.kind in ("assoc", "eapol")]
    kicks_observed = sum(1 for e in events if e.kind in KICK_KINDS
                         and _involves(e, bssid, client))
    deauths_observed = sum(1 for e in events if e.kind == "deauth"
                           and _involves(e, bssid, client))
    disassocs_observed = sum(1 for e in events if e.kind == "disassoc"
                             and _involves(e, bssid, client))
    if data_before == 0:
        verdict = "inconclusive"
        detail = ("no traffic from the client before the burst - it may be "
                  "idle, asleep or on another channel; repeat while it is "
                  "actively using the network")
        protected = None
    elif reauth_after:
        verdict = "fail"
        protected = False
        detail = (f"client re-associated ({len(reauth_after)} assoc/EAPOL "
                  "frame(s) after the burst): the forged deauth/disassoc "
                  "frame was ACCEPTED. Management-frame protection (802.11w "
                  "PMF) is not protecting this client - set it to REQUIRED "
                  "on the AP and the client supplicant, then re-test")
    elif data_after > 0:
        verdict = "pass"
        protected = True
        detail = (f"client kept exchanging data ({data_after} frame(s)) and "
                  "never re-associated: the forged deauthentication/"
                  "disassociation frames were ignored - PMF is working on "
                  "this BSS")
    else:
        verdict = "inconclusive"
        protected = None
        detail = ("client was active before but silent after without a "
                  "visible re-association; extend --verify-s and re-test")
    return {"verdict": verdict, "pmf_protected": protected,
            "data_before": data_before, "data_after": data_after,
            "reauth_after": len(reauth_after),
            "kicks_observed": kicks_observed,
            "deauths_observed": deauths_observed,
            "disassocs_observed": disassocs_observed, "detail": detail}


def _involves(e: AirEvent, bssid: str, client: str) -> bool:
    return client in (e.src, e.dst) or bssid in (e.bssid, e.src, e.dst)


def canary_results(events: List[AirEvent], src_mac: str, token: str) -> dict:
    """Count canary markers heard back over the air (self-hear / co-radio)."""
    src = normalize(src_mac)
    heard = [e for e in events
             if e.kind == "probe" and (normalize(e.src) == src
                                       or e.ssid == token)]
    rssis = [e.rssi for e in heard if e.rssi is not None]
    return {"token": token, "heard": len(heard),
            "rssi_dbm": (max(rssis) if rssis else None),
            "note": ("markers heard on this radio; remote sensors must each "
                     "be checked with `ids`/`capture`/`traffic` and grepped "
                     f"for token {token}")}


def twin_drill_report(ssid: str, bssid: str, channel: int,
                      security: str, beacons: int, duration_s: float) -> dict:
    """How to confirm your IDS/warden caught the beacon-only clone."""
    return {"mode": "evil-twin", "ssid": ssid, "bssid": bssid,
            "channel": channel, "security": security,
            "beacons_transmitted": beacons, "duration_s": round(duration_s, 1),
            "association_path": "none (beacon-only drill: cannot serve clients)",
            "verify": (
                f"1) baseline first:  wifiscanner ids --db warden.sqlite "
                f"--learn   (on a normal scan); "
                f"2) run this drill; "
                f"3) wifiscanner ids --db warden.sqlite -i wlan0mon  must "
                f"raise unknown-bss for {bssid}; "
                f"4) wifiscanner scan  must list {ssid!r} twice (real + clone) "
                f"and *_rogue_alerts.csv must flag the same-SSID clone")}


# --------------------------------------------------------- IDS self-test

def ids_selftest_scenarios():
    """(name, [frames], expected_alert_kinds) synthesised entirely offline."""
    from scapy.all import Dot11, RadioTap
    from scapy.layers.dot11 import (Dot11AssoReq, Dot11Beacon, Dot11Deauth,
                                    Dot11Disas, Dot11Elt)
    ap, sta = "F0:9F:C2:11:22:34", "AC:BC:32:01:02:99"

    def deauth():
        return (RadioTap() / Dot11(type=0, subtype=12, addr1=sta,
                                   addr2=ap, addr3=ap)
                / Dot11Deauth(reason=7))

    def disassoc():
        # subtype 10: disassociation - the "polite" kick, also PMF-protected
        return (RadioTap() / Dot11(type=0, subtype=10, addr1=sta,
                                   addr2=ap, addr3=ap)
                / Dot11Disas(reason=8))

    def assoc():
        return (RadioTap() / Dot11(type=0, subtype=0, addr1=ap, addr2=sta,
                                   addr3=ap) / Dot11AssoReq()
                / Dot11Elt(ID=0, info=b"OwnNet"))

    def eapol():
        key = b"\x02\x03\x00\x5d\x02\x01\x8a\x00\x10" + b"\x00" * 80
        return (RadioTap() / Dot11(type=2, subtype=8, FCfield=["to_DS"],
                                   addr1=ap, addr2=sta, addr3=ap)
                / (b"\xaa\xaa\x03\x00\x00\x00\x88\x8e" + key))

    def beacon(channel=6, rsn=True):
        p = (RadioTap() / Dot11(type=0, subtype=8,
                                addr1="ff:ff:ff:ff:ff:ff", addr2=ap,
                                addr3=ap)
             / Dot11Beacon(cap=0x1111 if rsn else 0x0001))
        p /= Dot11Elt(ID=0, info=b"OwnNet")
        p /= Dot11Elt(ID=3, info=bytes([channel]))
        if rsn:
            p /= Dot11Elt(ID=48,
                          info=bytes.fromhex("0100000fac040100000fac040100000"
                                             "fac020c00"))
        return p

    rogue_ap = "12:34:56:78:9A:BC"
    rogue = (RadioTap() / Dot11(type=0, subtype=8,
                                addr1="ff:ff:ff:ff:ff:ff", addr2=rogue_ap,
                                addr3=rogue_ap)
             / Dot11Beacon(cap=0x0001) / Dot11Elt(ID=0, info=b"OwnNet"))

    return [
        ("deauth-flood detection",
         [deauth() for _ in range(6)],
         {"deauth-flood"}),
        ("disassociation-flood detection",
         [disassoc() for _ in range(6)],
         {"deauth-flood"}),
        ("forced-reauth / handshake-harvest chain",
         [assoc(), eapol()],
         {"forced-reauth", "handshake-harvest-signature"}),
        ("beacon-mutation persistence",
         [beacon(6, rsn=True)] + [beacon(11, rsn=False) for _ in range(3)],
         {"beacon-mutation"}),
        ("unknown-bss warden",
         [rogue],
         {"unknown-bss"}),
    ], ap


def run_ids_selftest(write_pcap: str = "") -> dict:
    """Feed every synthetic attack signature to the Watchdog; report fires.

    No root, no radio, no hardware - safe in CI and on locked-down hosts.
    """
    from .defense import Watchdog
    scenarios, own_ap = ids_selftest_scenarios()
    wd = Watchdog(window_s=60, cooldown_s=0, flood_frames=5,
                  sensitivity="medium", known_bssids={own_ap})
    all_frames = []
    rows = []
    for name, frames, expected in scenarios:
        for pkt in frames:
            wd.feed(pkt)
        all_frames.extend(frames)
        fired = {a.kind for a in wd.alerts}
        missing = expected - fired
        ok = not missing
        rows.append({"scenario": name,
                     "expected": "|".join(sorted(expected)),
                     "fired": "|".join(sorted(expected & fired)),
                     "missing": "|".join(sorted(missing)),
                     "status": "PASS" if ok else "FAIL"})
    if write_pcap:
        from scapy.all import wrpcap
        d = os.path.dirname(os.path.abspath(write_pcap))
        os.makedirs(d, exist_ok=True)
        wrpcap(write_pcap, all_frames)
        secure_file(write_pcap)
    return {"rows": rows,
            "passed": sum(1 for r in rows if r["status"] == "PASS"),
            "total": len(rows),
            "frames": len(all_frames),
            "alerts": len(wd.alerts),
            "own_bssid": own_ap}
