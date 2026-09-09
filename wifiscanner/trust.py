"""Central trust model: every observation carries its SOURCE + CONFIDENCE.

Weakness #9 (\"no strong trust model\") is fixed here, and weaknesses #1
(client-count accuracy), #7 (IDS false positives) and #8 (rogue ambiguity)
are all grounded in this module:

* ``Source`` — where a fact came from. Router association tables outrank
  over-the-air inference; over-the-air inference outranks guesses.
* ``Observation`` — one dated piece of evidence with a 0-100 confidence.
* ``combine_confidence`` — noisy-OR fusion of independent evidence, so
  corroborated facts score higher and single-indicator hunches stay low.
* ``binding_confidence`` — how strongly a client<->AP binding is proven,
  from the *kind* of frames that established it.
* ``label`` — human wording (high/medium/low + one-line note) used by every
  display/export path so results never pretend to be more certain than they
  are.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Iterable, List, Optional


# ------------------------------------------------------------------ sources

class Source:
    """Canonical observation sources, most-trusted first."""
    ASSOC_TABLE = "assoc-table"     # router/AP kernel association table (ground truth)
    SURVEY_OS = "survey-os"         # iw / nmcli / airport / netsh scan of beacons
    MONITOR_RF = "monitor-rf"       # passive over-the-air 802.11 capture
    PCAP_FILE = "pcap-file"         # offline capture (same as RF, but replayed)
    LAN_ARP = "lan-arp"             # ARP/neighbour table + ping sweep (IP layer)
    LAN_NMAP = "lan-nmap"           # nmap host discovery
    SENSOR_HISTORY = "sensor-history"  # fused multi-sensor DB rows
    HEURISTIC = "heuristic"         # derived inference, no direct observation


# Base reliability of each source: (label, base confidence 0-100, note).
SOURCE_RELIABILITY = {
    Source.ASSOC_TABLE: ("router association table", 98,
                         "authoritative: the AP's own kernel station list"),
    Source.SURVEY_OS: ("OS wireless survey", 90,
                       "driver-reported beacon scan"),
    Source.MONITOR_RF: ("passive RF capture", 75,
                        "inferred from plaintext 802.11 headers; channel-hopping "
                        "means some frames are always missed"),
    Source.PCAP_FILE: ("capture file", 75,
                       "offline replay of an RF capture; same limits as live RF"),
    Source.LAN_ARP: ("LAN ARP sweep", 70,
                     "IP-layer presence; misses silent/firewalled hosts"),
    Source.LAN_NMAP: ("nmap discovery", 80,
                      "active host discovery on your own subnet"),
    Source.SENSOR_HISTORY: ("sensor history fusion", 65,
                            "fused across sensors/time; each hop adds uncertainty"),
    Source.HEURISTIC: ("heuristic inference", 40,
                       "derived guess, not a direct observation"),
}

# Short tokens used in CSV `sources` columns.
SOURCE_TOKENS = {
    "iw": Source.SURVEY_OS, "nmcli": Source.SURVEY_OS,
    "iwlist": Source.SURVEY_OS, "airport": Source.SURVEY_OS,
    "system_profiler": Source.SURVEY_OS, "netsh": Source.SURVEY_OS,
    "monitor": Source.MONITOR_RF, "lan": Source.LAN_ARP,
}


def normalize_source(token: str) -> str:
    """Map a legacy free-text source token to a canonical Source."""
    t = (token or "").strip().lower()
    if t in SOURCE_RELIABILITY:
        return t
    return SOURCE_TOKENS.get(t, Source.HEURISTIC if t else Source.HEURISTIC)


def source_label(source: str) -> str:
    return SOURCE_RELIABILITY.get(source, ("unknown", 0, ""))[0]


def source_confidence(source: str) -> int:
    return SOURCE_RELIABILITY.get(source, ("unknown", 0, ""))[1]


def source_note(source: str) -> str:
    return SOURCE_RELIABILITY.get(source, ("unknown", 0, ""))[2]


# --------------------------------------------------------------- observation

@dataclass
class Observation:
    """One dated piece of evidence behind a reported fact."""
    source: str                       # canonical Source value
    kind: str                         # e.g. "assoc-request", "data-bidi"
    confidence: int                   # 0-100 for THIS observation
    detail: str = ""                  # human-readable, shown in verbose output
    ts: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {"source": self.source, "kind": self.kind,
                "confidence": self.confidence, "detail": self.detail,
                "ts": self.ts}


# --------------------------------------------- client<->AP binding evidence

# How strongly each frame-level evidence kind proves a client is attached to
# an AP. Ordered weakest -> strongest; the binding confidence is the max of
# the observed kinds, boosted when independent kinds corroborate.
BINDING_EVIDENCE = {
    # kind                  (confidence, human note)
    "single-frame": (35, "one frame only — could be spoofed, transient or "
                         "mis-attributed during channel hops"),
    "data-unidir": (65, "data frames seen in one direction only"),
    "probe-only": (30, "probing nearby, NOT associated"),
    "arp-only": (50, "present on LAN, over-the-air binding unconfirmed"),
    "data-bidi": (85, "data frames seen in both directions (uplink+downlink)"),
    "assoc-request": (92, "explicit (re)association request captured"),
    "eapol": (90, "EAPOL handshake on this BSS — freshly (re)authenticated"),
    "assoc-table": (98, "listed in the router's own association table"),
}

BINDING_RANK = ["probe-only", "single-frame", "arp-only", "data-unidir",
                "data-bidi", "eapol", "assoc-request", "assoc-table"]


def binding_confidence(kinds: Iterable[str]) -> tuple[int, str, str]:
    """Return (confidence 0-100, best_kind, note) for a set of evidence kinds.

    Corroboration rule: each *additional independent* kind beyond the best
    adds +4 (capped at 99), so a client seen via assoc + EAPOL + bidirectional
    data scores higher than one seen via a single data frame.
    """
    kinds = [k for k in kinds if k in BINDING_EVIDENCE]
    if not kinds:
        return (0, "none", "no evidence recorded")
    best = max(kinds, key=lambda k: BINDING_RANK.index(k))
    conf, note = BINDING_EVIDENCE[best]
    extra = len(set(kinds)) - 1
    if extra > 0:
        conf = min(99, conf + 4 * extra)
        note = f"{note}; corroborated by {extra} further independent signal(s)"
    return (conf, best, note)


def combine_confidence(values: Iterable[int]) -> int:
    """Fuse independent 0-100 confidences with noisy-OR (cap 99).

    Two weak signals beat one weak signal, but fusion can never manufacture
    certainty: the result asymptotically approaches — but never reaches — 100.
    """
    vals = [max(0, min(100, int(v))) for v in values]
    if not vals:
        return 0
    doubt = 1.0
    for v in vals:
        doubt *= (1.0 - v / 100.0)
    return min(99, int(round((1.0 - doubt) * 100)))


def confidence_label(conf: int) -> str:
    """Bucket a 0-100 score for display."""
    if conf >= 85:
        return "high"
    if conf >= 60:
        return "medium"
    if conf >= 35:
        return "low"
    return "very-low"


def describe(conf: int, note: str = "") -> str:
    """One-line 'source + confidence' rendering used across the UI."""
    text = f"{confidence_label(conf)} confidence ({conf}/100)"
    return f"{text} — {note}" if note else text


# ------------------------------------------------------- AP-level confidence

def ap_confidence(source: str, beacons: int = 0, has_security: bool = False,
                  has_channel: bool = False) -> tuple[int, str]:
    """Confidence that an AP record is real and correctly described.

    Beacons are self-advertised claims: one sighting proves little, repeated
    sightings with a full IE set prove much more. Router-confirmed APs (your
    own connection) score highest.
    """
    if not source:
        return (0, "no source recorded")
    parts = [p for p in source.split("+") if p]
    canon = [normalize_source(p) for p in parts]
    base = max([source_confidence(c) for c in canon] or [0])
    notes: List[str] = []
    if len(set(canon)) > 1:
        base = min(99, base + 5)
        notes.append("seen by multiple independent sources")
    if beacons >= 5:
        base = min(99, base + 3)
    elif beacons == 0 and Source.MONITOR_RF in canon:
        base -= 10
        notes.append("no beacons captured (RF record only)")
    if not has_channel:
        base -= 5
        notes.append("channel unknown")
    if not has_security:
        notes.append("security stack not fully decoded")
    base = max(5, min(99, base))
    if not notes:
        notes.append(source_note(canon[0]) if canon else "")
    return (base, "; ".join(n for n in notes if n))


def correlated_note(sources: List[str]) -> str:
    """Explain how multiple sources were combined for one fact."""
    uniq = list(dict.fromkeys(sources))
    if len(uniq) <= 1:
        return source_note(uniq[0]) if uniq else "no source"
    best = max(uniq, key=source_confidence)
    return (f"{len(uniq)} sources fused ({', '.join(source_label(s) for s in uniq)}); "
            f"strongest is {source_label(best)}")
