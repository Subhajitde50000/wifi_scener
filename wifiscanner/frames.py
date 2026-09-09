"""802.11 frame anatomy: an interactive textbook layer over any capture.

Explains, frame by frame, WHY every passive technique in this tool works:
which address field binds a client to an AP, what the RSN IE's bytes mean,
how EAPOL 4-way message flags are laid out, what "protected" costs an
eavesdropper. Key material (nonces, MICs) is deliberately NOT rendered -
the annotation stops at structure, because structure is what you need to
learn, and harvesting is not.
"""
from __future__ import annotations

from typing import Iterator, List, Optional

SUBTYPES_MGMT = {0: "Association Request", 1: "Association Response",
                 4: "Probe Request", 5: "Probe Response", 8: "Beacon",
                 11: "Disassociation", 12: "Deauthentication", 13: "Action"}
ELT_NAMES = {0: "SSID", 1: "Supported Rates", 3: "DS Param (channel)",
             5: "TIM", 42: "Ext SSID", 45: "HT Capabilities",
             46: "Supported Channels", 47: "HT Ext", 48: "RSN",
             50: "Ext Supported Rates", 53: "VHT Capabilities",
             60: "VHT Op", 191: "BSS Load", 192: "Extended Channel Switch",
             197: "Device Class?", 207: "HE Capabilities", 221: "Vendor (WPS/etc)"}
# IEEE 802.11 Table of AKM suite selectors (4th byte of OUI-00-0F-AC-xx)
AKM = {0x01: "802.1X", 0x02: "PSK", 0x03: "FT-802.1X", 0x04: "FT-PSK",
       0x05: "802.1X-SHA256", 0x06: "PSK-SHA256", 0x07: "TPK",
       0x08: "SAE", 0x09: "FT-SAE", 0x0b: "SUITE-B", 0x0c: "SUITE-B-192",
       0x12: "OWE"}
CIPHERS = {0x00: "group-specific", 0x01: "WEP-40", 0x02: "TKIP (broken)",
           0x04: "CCMP-128", 0x05: "WEP-104 (broken)", 0x06: "BIP-CMAC-128",
           0x08: "GCMP-256", 0x09: "BIP-GMAC-128", 0x0a: "BIP-GMAC-256",
           0xc0: "NOIGTK-128", 0xf0: "GROUP-DEFAULT"}
EAPOL_FLAGS = [(0x01, "EAP key"), (0x02, "key data"), (0x04, "request"),
               (0x08, "error"), (0x10, "secure (msg3+)"), (0x20, "mic"),
               (0x40, "pairwise (PTK)"), (0x80, "install (msg3)"),
               (0x100, "ack (msg1/3)"), (0x200, "mp key data"),
               (0x400, "new stasmac")]


def _dot11(pkt):
    from scapy.all import Dot11
    return pkt.getlayer(Dot11)


def _llc_snap(raw: bytes) -> Optional[str]:
    if raw[:3] == b"\xaa\xaa\x03" and len(raw) >= 8:
        et = int.from_bytes(raw[6:8], "big")
        return {0x0800: "IPv4", 0x0806: "ARP", 0x86dd: "IPv6",
                0x888e: "EAPOL"}.get(et, f"ethertype 0x{et:04x}")
    return None


def annotate(pkt, index: int = 0) -> str:
    """One frame -> a human-readable anatomy block."""
    from scapy.all import RadioTap, Dot11Elt, IP, TCP, UDP
    L = [f"── frame {index} ───────────────────────────────────────────"]
    rt = pkt.getlayer(RadioTap)
    if rt is not None:
        bits = []
        for name in ("dBm_AntSignal", "AntNoise", "ChannelFrequency", "TSFT"):
            v = getattr(rt, name, None)
            if v not in (None, 0):
                bits.append(f"{name}={v}")
        if bits:
            L.append("  radiotap: " + "  ".join(bits) +
                     "   <- why sniffing works: the card reports signal per frame")
    d = _dot11(pkt)
    if d is None:
        if pkt.load:
            L.append(f"  (not 802.11) payload {len(bytes(pkt.load))}B")
        return "\n".join(L)
    t, st = int(d.type), int(d.subtype)
    kind = {0: "Management", 1: "Control", 2: "Data"}.get(t, str(t))
    name = SUBTYPES_MGMT.get(st, f"subtype {st}") if t == 0 else \
        ("QoS Data" if st >= 8 else "Data") if t == 2 else f"subtype {st}"
    L.append(f"  {kind}: {name}")
    fcf = str(d.FCfield)
    L.append(f"  FC: type={t} subtype={st} flags={fcf.replace(' ', '+') or '-'}")
    addrs = [("addr1/RA", d.addr1), ("addr2/TA", d.addr2),
             ("addr3/BSSID", d.addr3)]
    if getattr(d, "addr4", None) and d.addr4 not in (None, "00:00:00:00:00:00"):
        addrs.append(("addr4", d.addr4))
    L.append("  addresses: " + "  ".join(f"{k}={v}" for k, v in addrs if v))
    if t == 2:
        to_ds = "to_DS" in fcf
        from_ds = "from_DS" in fcf
        if to_ds or from_ds:
            who = ("client->AP (uplink): addr2 is the CLIENT, addr3 the AP"
                   if to_ds and not from_ds else
                   "AP->client (downlink): addr1 is the CLIENT, addr3 the AP"
                   if from_ds and not to_ds else
                   "wireless distribution (4-address, e.g. WDS mesh)")
            L.append(f"  {who}")
            L.append("  -> THIS is how device counts work without joining: the "
                     "encrypted payload proves nothing to us, the ADDRESS "
                     "BINDING does.")
        raw = bytes(d.payload)
        l3 = _llc_snap(raw)
        if l3:
            L.append(f"  LLC/SNAP -> {l3} ({len(raw)}B)")
        if "protected" in fcf:
            L.append("  PROTECTED bit set: payload is encrypted. We read the "
                     "header (that's all passive analysis needs) and nothing "
                     "more.")
        if "wep" in fcf.lower():
            L.append("  WEP bit set: legacy broken cipher.")
    elif t == 0 and st in (12, 11):
        L.append("  -> an 'unplug over the air' frame: forged by anyone without "
                 "PMF; this tool DETECTS floods of them, and never sends one.")
    elif t == 0 and st in (8, 5):
        layer = pkt.getlayer(Dot11Elt)
        i = 0
        while isinstance(layer, Dot11Elt):
            info = bytes(layer.info)
            nm = ELT_NAMES.get(int(layer.ID), f"element {layer.ID}")
            extra = _decode_element(int(layer.ID), info)
            L.append(f"  IE[{int(layer.ID):>3}] {nm} ({len(info)}B)"
                     + (f": {extra}" if extra else ""))
            i += 1
            layer = layer.payload
        if i == 0 and bytes(d.payload)[:4] not in (b"",):
            L.append("  (beacon body not dissectable here)")
    elif t == 0 and st == 4:
        layer = pkt.getlayer(Dot11Elt)
        while isinstance(layer, Dot11Elt):
            if int(layer.ID) == 0:
                L.append(f"  probing for SSID {bytes(layer.info).decode(errors='replace')!r}"
                         "  <- how nearby-device presence is known for free")
            layer = layer.payload
    elif t == 0 and st == 0:
        L.append("  join request: binds addr2(client) to addr3(AP) with SSID"
                 "  <- the definitive association record")
    # inner IP if cleartext
    ip = pkt.getlayer(IP)
    if ip is not None:
        L.append(f"  inner: {ip.src} -> {ip.dst}")
        for p in (TCP, UDP):
            l4 = ip.getlayer(p)
            if l4 is not None:
                L.append(f"        {p.__name__} {int(l4.sport)} -> {int(l4.dport)}")
                break
    return "\n".join(L)


def _decode_element(elt_id: int, info: bytes) -> str:
    if elt_id == 0:
        return repr(info.decode(errors="replace"))
    if elt_id == 3 and info:
        return f"channel {info[0]}"
    if elt_id == 1:
        rates = [f"{b & 0x7f}.0" for b in info[:8]]
        return "base rates " + " ".join(rates) + (
            "  <- 802.11b rates present: legacy, weaker PHY")
    if elt_id == 191 and len(info) >= 3:
        st = int.from_bytes(info[0:2], "little")
        return f"station_count={st & 0x3fff} (AP's own load report, high 2 bits = CH utilization)"
    if elt_id == 48 and len(info) >= 8:                 # RSN
        def suite_at(off: int) -> int:
            if info[off:off + 3] == b"\x00\x0f\xac":
                return info[off + 3]
            return -1
        o = 2
        gc = suite_at(o); o += 4
        np_ = int.from_bytes(info[o:o + 2], "little"); o += 2
        pcs = []
        for _ in range(np_):
            v = suite_at(o); pcs.append(CIPHERS.get(v, f"0x{v:02x}")); o += 4
        na_ = int.from_bytes(info[o:o + 2], "little"); o += 2
        akm = []
        pmf = "unknown"
        for _ in range(na_):
            v = suite_at(o); akm.append(AKM.get(v, f"0x{v:02x}")); o += 4
        if o + 2 <= len(info):
            cap = int.from_bytes(info[o:o + 2], "little")
            pmf = ("required" if cap & 0x80 else
                   "optional" if cap & 0x40 else "not advertised")
            akm.append(f"PMF:{pmf}")
        return (f"group={CIPHERS.get(gc, gc)} pairwise={pcs} akm={akm} "
                f"mfp={pmf}")
    if elt_id == 221 and info[:4] == b"\x00\x50\xf2\x04":
        return "WPS present - the PIN enrolment hole; disable it"
    return ""


def eapol_flags(pkt) -> str:
    """Decode only the *structure* (message role + flags) of an EAPOL-Key
    frame. Nonces/keys/MICs are not extracted or displayed, by design."""
    from scapy.all import Dot11
    d = _dot11(pkt)
    raw = bytes(d.payload) if d is not None else b""
    if raw[:3] == b"\xaa\xaa\x03":
        raw = raw[8:]
    # EAPOL header: ver(1) type(1) len(2) | desc: type(1) key-info(2) ...
    if len(raw) < 7 or raw[0] not in (1, 2) or raw[1] != 3:
        return ""
    ki = int.from_bytes(raw[5:7], "big")
    names = [n for b, n in EAPOL_FLAGS if ki & b]
    msg = {(): "?", ("EAP key", "ack"): "M1 (AP->STA, announces ANonce)",
           ("EAP key", "mic", "key data"): "M2 (STA->AP: this is THE frame harvesting tools chase; its MIC is what offline attacks grind)",
           ("EAP key", "install", "key data"): "M3 (AP->STA, installs PTK)",
           ("EAP key", "ack", "mic"): "M4 (STA->AP, done)"}
    return (f"EAPOL-Key {msg.get(tuple(names), 'role unknown')}"
            f" [flags 0x{ki:04x}: {','.join(names)}]")


def annotate_pcap(path: str, limit: int = 20, filt: str = "",
                  max_frames: int = 200000) -> List[str]:
    from scapy.all import PcapReader, Dot11
    out: List[str] = []
    n = 0
    for pkt in PcapReader(path):
        n += 1
        if n > max_frames:
            break
        d = _dot11(pkt)
        if d is None:
            if not filt:
                continue
            continue
        t, st = int(d.type), int(d.subtype)
        tag = {12: "deauth", 11: "disassoc", 8: "beacon", 4: "probe-req",
               5: "probe-resp", 0: "assoc-req", 1: "assoc-resp"}.get(st, "") \
            if t == 0 else ("data" if t == 2 else "control")
        e = ""
        if tag == "data":
            e = eapol_flags(pkt)
            if e:
                tag += " handshake"
        if filt and filt.lower() not in (tag + str(t) + str(st)).lower():
            continue
        blk = annotate(pkt, n)
        if e:
            blk += f"\n  eapol: {e}"
        out.append(blk)
        if len(out) >= limit:
            break
    return out


def find_handshakes(path: str) -> dict:
    """Summarise EAPOL activity in a capture: WHICH bss, HOW MANY msgs, and
    whether PMF would have prevented the surrounding deauth dance. Counts
    only - no frames are extracted, stored, or exported."""
    from scapy.all import PcapReader
    stats: dict = {}
    for pkt in PcapReader(path):
        dd = _dot11(pkt)
        if dd is None:
            continue
        if int(dd.type) == 0 and int(dd.subtype) in (11, 12):
            stats.setdefault("deauth_disassoc", 0)
            stats["deauth_disassoc"] += 1
        ap = (dd.addr3 or "?").upper()
        if int(dd.type) == 2:
            from scapy.all import EAPOL
            if pkt.haslayer(EAPOL) or _llc_snap(bytes(dd.payload)) == "EAPOL":
                k = stats.setdefault("eapol_by_bss", {})
                k[ap] = k.get(ap, 0) + 1
                stats.setdefault("eapol_total", 0)
                stats["eapol_total"] += 1
    return stats
