"""Core data models for the Wi-Fi survey system."""
from __future__ import annotations

import math
import time
from dataclasses import dataclass, field, asdict
from typing import Optional


# ---------------------------------------------------------------- RF helpers

def channel_to_freq(ch: int, band_hint: str = "") -> Optional[int]:
    """Convert a channel number to a centre frequency in MHz."""
    if ch is None:
        return None
    if band_hint == "6GHz" or (ch >= 1 and band_hint == "6GHz"):
        return 5950 + ch * 5
    if 1 <= ch <= 13:
        return 2407 + ch * 5
    if ch == 14:
        return 2484
    if 32 <= ch <= 196:
        return 5000 + ch * 5
    return None


def freq_to_channel(freq: Optional[int]) -> Optional[int]:
    if not freq:
        return None
    f = int(freq)
    if f == 2484:
        return 14
    if 2412 <= f <= 2472:
        return (f - 2407) // 5
    if 5160 <= f <= 5885:
        return (f - 5000) // 5
    if 5955 <= f <= 7115:
        return (f - 5950) // 5
    return None


def band_of(freq: Optional[int]) -> str:
    if not freq:
        return "unknown"
    f = int(freq)
    if f < 2500:
        return "2.4GHz"
    if f < 5925:
        return "5GHz"
    if f < 7200:
        return "6GHz"
    return "unknown"


DEFAULT_TX_POWER_DBM = 20.0     # typical consumer AP EIRP (100 mW)


def estimate_distance_m(rssi: Optional[int], freq_mhz: Optional[int],
                        path_loss_exponent: float = 2.7,
                        tx_power_dbm: float = DEFAULT_TX_POWER_DBM) -> Optional[float]:
    """Log-distance path-loss estimate of the distance to a transmitter.

    RSSI = Tx - FSPL(1m) - 10 * n * log10(d)   =>
    d = 10 ** ((Tx - FSPL_1m - RSSI) / (10 * n))

    n = 2.0 free space, ~2.7 typical indoor, 3.5+ through many walls.
    This is an *estimate*: walls, antenna gain and the AP's real TX power
    all shift it, so treat it as an order-of-magnitude proximity hint.
    """
    if rssi is None or not freq_mhz:
        return None
    fspl_1m = 20 * math.log10(freq_mhz) - 27.55      # FSPL at d = 1 m, MHz form
    d = 10 ** ((tx_power_dbm - fspl_1m - rssi) / (10 * path_loss_exponent))
    return round(max(0.1, min(d, 2000.0)), 2)


def rssi_quality(rssi: Optional[int]) -> Optional[int]:
    """Map RSSI (dBm) to a 0-100 quality percentage (Microsoft-style)."""
    if rssi is None:
        return None
    if rssi <= -100:
        return 0
    if rssi >= -50:
        return 100
    return int(2 * (rssi + 100))


def rssi_bars(rssi: Optional[int]) -> str:
    q = rssi_quality(rssi)
    if q is None:
        return "----"
    n = min(4, max(0, (q + 24) // 25))
    return "\u2588" * n + "\u2591" * (4 - n)


# ---------------------------------------------------------------- dataclasses

@dataclass
class Station:
    """A client device (STA) seen associated with, or probing for, an AP.

    Trust model (see wifiscanner.trust): a station is *RF-observed* when
    passive capture saw frames binding it to a BSSID, and *confirmed* only
    when the router's own association table lists it. ``evidence_kinds``
    records which frame-level proofs were seen; ``binding_confidence`` turns
    them into a 0-100 score so callers can distinguish \"one stray frame\"
    from \"assoc + EAPOL + bidirectional data\".
    """
    mac: str
    bssid: Optional[str] = None          # AP it is associated with
    ssid: Optional[str] = None
    vendor: str = ""
    is_randomized: bool = False          # locally-administered / privacy MAC
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    packets: int = 0
    data_packets: int = 0
    bytes_seen: int = 0
    rssi: Optional[int] = None
    rssi_min: Optional[int] = None
    rssi_max: Optional[int] = None
    channel: Optional[int] = None
    probed_ssids: set = field(default_factory=set)
    ip_address: str = ""                 # only when actively scanning own LAN
    hostname: str = ""
    open_ports: list = field(default_factory=list)
    # --- trust / evidence (weaknesses #1, #2, #9) ---
    sources: set = field(default_factory=set)        # canonical trust.Source
    evidence_kinds: set = field(default_factory=set)  # trust.BINDING_EVIDENCE
    confirmed: bool = False              # in the router's assoc table?
    _dirs: set = field(default_factory=set, repr=False)  # uplink/downlink seen

    def observe(self, rssi: Optional[int] = None, data: bool = False,
                length: int = 0, source: str = "",
                evidence: str = "", direction: str = "") -> None:
        self.last_seen = time.time()
        self.packets += 1
        self.bytes_seen += length
        if data:
            self.data_packets += 1
        if rssi is not None:
            self.rssi = rssi
            self.rssi_min = rssi if self.rssi_min is None else min(self.rssi_min, rssi)
            self.rssi_max = rssi if self.rssi_max is None else max(self.rssi_max, rssi)
        if source:
            from .trust import normalize_source
            self.sources.add(normalize_source(source))
        if direction in ("up", "down"):
            self._dirs.add(direction)
            # A second direction upgrades unidir evidence to bidirectional.
            if len(self._dirs) == 2:
                self.evidence_kinds.discard("data-unidir")
                self.evidence_kinds.discard("single-frame")
                self.evidence_kinds.add("data-bidi")
            elif not self.evidence_kinds:
                self.evidence_kinds.add("data-unidir")
        if evidence:
            self.evidence_kinds.add(evidence)
            if evidence in ("assoc-request", "eapol", "assoc-table",
                            "data-bidi"):
                self.evidence_kinds.discard("single-frame")
        if not self.evidence_kinds and self.packets == 1:
            self.evidence_kinds.add("single-frame")

    @property
    def binding_confidence(self) -> int:
        """0-100: how strongly the AP binding is proven (trust model)."""
        from .trust import binding_confidence
        kinds = set(self.evidence_kinds)
        if self.confirmed:
            kinds.add("assoc-table")
        if self.data_packets >= 2 and "up" in self._dirs and "down" in self._dirs:
            kinds.add("data-bidi")
        conf, _, _ = binding_confidence(kinds)
        return conf

    @property
    def binding_kind(self) -> str:
        from .trust import binding_confidence
        kinds = set(self.evidence_kinds) | ({"assoc-table"} if self.confirmed else set())
        _, best, _ = binding_confidence(kinds)
        return best

    @property
    def binding_note(self) -> str:
        from .trust import binding_confidence
        kinds = set(self.evidence_kinds) | ({"assoc-table"} if self.confirmed else set())
        _, _, note = binding_confidence(kinds)
        return note

    @property
    def confidence_label(self) -> str:
        from .trust import confidence_label
        return confidence_label(self.binding_confidence)

    @property
    def source_label(self) -> str:
        """Human 'source + confidence' one-liner for display/export."""
        from .trust import confidence_label, source_label
        if not self.sources:
            return f"unrecorded ({self.binding_confidence}/100)"
        best = sorted(self.sources)[0]
        lbl = ", ".join(sorted(source_label(s) for s in self.sources))
        return f"{lbl} — {confidence_label(self.binding_confidence)} ({self.binding_confidence}/100)"

    @property
    def identity_class(self) -> str:
        """stable (globally-unique burned-in MAC) vs rotating (privacy MAC)."""
        return "rotating-privacy-mac" if self.is_randomized else "stable-mac"

    @property
    def identity_note(self) -> str:
        """Honesty guard for randomized MACs (weakness #2).

        Distinct rotating addresses must NEVER be claimed to be distinct
        devices — nor the same device. Both directions are unknowable from
        passive observation alone.
        """
        if self.is_randomized:
            return ("privacy MAC rotates: this address is one observation, not "
                    "one device — distinct rotating addresses may be the same "
                    "physical device, and one address may be reused by others")
        return "burned-in MAC: stable identifier for this radio"

    @property
    def dwell_s(self) -> float:
        return round(self.last_seen - self.first_seen, 1)

    def to_row(self) -> dict:
        d = asdict(self)
        d["probed_ssids"] = "|".join(sorted(self.probed_ssids))
        d["open_ports"] = "|".join(str(p) for p in self.open_ports)
        d["dwell_s"] = self.dwell_s
        d["signal_quality_pct"] = rssi_quality(self.rssi)
        d["first_seen"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.first_seen))
        d["last_seen"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.last_seen))
        # Trust columns (weaknesses #1/#2/#9): source + confidence on every row.
        d["sources"] = "|".join(sorted(self.sources)) if self.sources else ""
        d["evidence"] = "|".join(sorted(self.evidence_kinds)) if self.evidence_kinds else ""
        d["binding_confidence"] = self.binding_confidence
        d["confidence"] = self.confidence_label
        d["confirmed"] = int(self.confirmed)
        d["identity_class"] = self.identity_class
        d["identity_note"] = self.identity_note
        d.pop("_dirs", None)
        d.pop("evidence_kinds", None)
        return d


@dataclass
class AccessPoint:
    """A Wi-Fi access point / BSS with every detail we can extract."""
    bssid: str
    ssid: str = ""
    vendor: str = ""
    channel: Optional[int] = None
    frequency: Optional[int] = None
    width_mhz: Optional[int] = None
    rssi: Optional[int] = None
    rssi_min: Optional[int] = None
    rssi_max: Optional[int] = None
    noise: Optional[int] = None
    beacon_interval: Optional[int] = None
    dtim: Optional[int] = None
    country: str = ""
    max_rate_mbps: Optional[float] = None
    phy_modes: list = field(default_factory=list)   # a/b/g/n/ac/ax/be
    security: list = field(default_factory=list)    # WPA3, WPA2, WEP, OPEN...
    ciphers: list = field(default_factory=list)
    auth_suites: list = field(default_factory=list)
    pmf: str = ""                                    # disabled/optional/required
    wps: bool = False
    hidden: bool = False
    is_mesh: bool = False
    beacons: int = 0
    data_packets: int = 0
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    stations: dict = field(default_factory=dict)     # mac -> Station
    source: str = ""                                 # which backend saw it
    raw: dict = field(default_factory=dict)

    # ---------------- derived

    @property
    def band(self) -> str:
        return band_of(self.frequency or channel_to_freq(self.channel or 0))

    @property
    def client_count(self) -> int:
        return len(self.stations)

    @property
    def active_client_count(self) -> int:
        """Clients that actually pushed data frames (real traffic)."""
        return sum(1 for s in self.stations.values() if s.data_packets > 0)

    @property
    def confirmed_client_count(self) -> int:
        """Clients verified in the router's association table (ground truth).

        Weakness #1: this is the ONLY count that may be stated as fact.
        """
        return sum(1 for s in self.stations.values() if s.confirmed)

    @property
    def rf_only_client_count(self) -> int:
        """RF-observed clients NOT confirmed by the router (estimates)."""
        return sum(1 for s in self.stations.values() if not s.confirmed)

    @property
    def census(self) -> dict:
        """RF-observed vs router-confirmed client breakdown (weakness #1)."""
        confirmed = [s for s in self.stations.values() if s.confirmed]
        rf_only = [s for s in self.stations.values() if not s.confirmed]
        high = sum(1 for s in rf_only if s.binding_confidence >= 85)
        return {
            "total_observed": len(self.stations),
            "router_confirmed": len(confirmed),
            "rf_only": len(rf_only),
            "rf_high_confidence": high,
            "active": self.active_client_count,
        }

    @property
    def census_confidence(self) -> int:
        """0-100 confidence in the client count for this AP.

        Router confirmation dominates; otherwise the count is only as good
        as its weakest binding, discounted for channel-hopping misses.
        """
        if not self.stations:
            return 0
        if self.confirmed_client_count == len(self.stations):
            return 98
        from .trust import combine_confidence
        per_client = [s.binding_confidence for s in self.stations.values()]
        # The *count* confidence: every observed binding must be right, and
        # hopping means we may have missed clients entirely (-10, floor 5).
        worst = min(per_client) if per_client else 0
        fused = combine_confidence([worst, 70 if self.data_packets else 45])
        return max(5, fused - (0 if self.confirmed_client_count else 10))

    @property
    def census_note(self) -> str:
        from .trust import confidence_label
        c = self.census
        if c["router_confirmed"]:
            return (f"{c['router_confirmed']} router-confirmed + "
                    f"{c['rf_only']} RF-observed "
                    f"({confidence_label(self.census_confidence)} "
                    f"confidence {self.census_confidence}/100)")
        if not self.stations:
            return "no clients observed"
        return (f"{c['total_observed']} RF-observed, 0 router-confirmed "
                f"({confidence_label(self.census_confidence)} confidence "
                f"{self.census_confidence}/100 — estimate, not a fact)")

    @property
    def ap_confidence(self) -> int:
        from .trust import ap_confidence
        conf, _ = ap_confidence(self.source, beacons=self.beacons,
                                has_security=bool(self.security),
                                has_channel=self.channel is not None)
        return conf

    @property
    def ap_confidence_note(self) -> str:
        from .trust import ap_confidence
        _, note = ap_confidence(self.source, beacons=self.beacons,
                                has_security=bool(self.security),
                                has_channel=self.channel is not None)
        return note

    @property
    def snr(self) -> Optional[int]:
        if self.rssi is None or self.noise is None:
            return None
        return self.rssi - self.noise

    @property
    def distance_m(self) -> Optional[float]:
        return estimate_distance_m(self.rssi, self.frequency or channel_to_freq(self.channel or 0))

    @property
    def encryption(self) -> str:
        return "/".join(self.security) if self.security else "OPEN"

    @property
    def security_score(self) -> int:
        """0-100 security rating (higher == safer)."""
        s = set(self.security)
        if not s or s == {"OPEN"}:
            score = 5
        elif "WEP" in s:
            score = 15
        elif "WPA3" in s and "WPA2" in s:
            score = 80          # transition mode: downgrade-attackable
        elif "WPA3" in s:
            score = 100
        elif "WPA2" in s:
            score = 70
        elif "WPA" in s:
            score = 35
        else:
            score = 50
        if self.wps:
            score -= 25                      # WPS PIN / Pixie-Dust exposure
        if "TKIP" in self.ciphers:
            score -= 15
        if self.pmf == "required":
            score += 5
        elif self.pmf in ("", "disabled"):
            score -= 5                       # deauth / KRACK exposure
        return max(0, min(100, score))

    @property
    def security_grade(self) -> str:
        sc = self.security_score
        for bound, g in ((90, "A+"), (80, "A"), (70, "B"), (55, "C"), (35, "D"), (0, "F")):
            if sc >= bound:
                return g
        return "F"

    @property
    def risks(self) -> list:
        r = []
        if not self.security or self.security == ["OPEN"]:
            r.append("open-network:traffic-in-cleartext")
        if "WEP" in self.security:
            r.append("wep:trivially-crackable")
        if "WPA" in self.security and "WPA2" not in self.security:
            r.append("wpa1-legacy")
        if "TKIP" in self.ciphers:
            r.append("tkip-cipher-deprecated")
        if self.wps:
            r.append("wps-enabled:pixie-dust")
        if self.pmf in ("", "disabled") and self.security != ["OPEN"]:
            r.append("no-pmf:deauth-possible")
        if self.hidden:
            r.append("hidden-ssid:security-by-obscurity")
        if self.rssi is not None and self.rssi > -35:
            r.append("very-close-transmitter")
        return r

    def observe_beacon(self, rssi: Optional[int] = None) -> None:
        self.last_seen = time.time()
        self.beacons += 1
        if rssi is not None:
            self.rssi = rssi
            self.rssi_min = rssi if self.rssi_min is None else min(self.rssi_min, rssi)
            self.rssi_max = rssi if self.rssi_max is None else max(self.rssi_max, rssi)

    def add_station(self, sta: Station) -> Station:
        cur = self.stations.get(sta.mac)
        if cur is None:
            sta.bssid = self.bssid
            sta.ssid = sta.ssid or self.ssid
            self.stations[sta.mac] = sta
            return sta
        cur.last_seen = max(cur.last_seen, sta.last_seen)
        cur.first_seen = min(cur.first_seen, sta.first_seen)
        cur.packets += sta.packets
        cur.data_packets += sta.data_packets
        cur.bytes_seen += sta.bytes_seen
        if sta.rssi is not None:
            cur.rssi = sta.rssi
        cur.probed_ssids |= sta.probed_ssids
        # Trust fusion: union evidence/sources; router confirmation sticks.
        cur.sources |= set(getattr(sta, "sources", set()))
        cur.evidence_kinds |= set(getattr(sta, "evidence_kinds", set()))
        cur._dirs |= set(getattr(sta, "_dirs", set()))
        if sta.confirmed:
            cur.confirmed = True
            cur.evidence_kinds.add("assoc-table")
            cur.evidence_kinds.discard("single-frame")
        if len(cur._dirs) == 2:
            cur.evidence_kinds.discard("data-unidir")
            cur.evidence_kinds.discard("single-frame")
            cur.evidence_kinds.add("data-bidi")
        cur.ip_address = cur.ip_address or sta.ip_address
        cur.hostname = cur.hostname or sta.hostname
        cur.open_ports = cur.open_ports or sta.open_ports
        cur.vendor = cur.vendor or sta.vendor
        return cur

    def to_row(self) -> dict:
        return {
            "bssid": self.bssid,
            "ssid": self.ssid or ("<hidden>" if self.hidden else ""),
            "hidden": self.hidden,
            "vendor": self.vendor,
            "band": self.band,
            "channel": self.channel,
            "frequency_mhz": self.frequency,
            "channel_width_mhz": self.width_mhz,
            "rssi_dbm": self.rssi,
            "rssi_min_dbm": self.rssi_min,
            "rssi_max_dbm": self.rssi_max,
            "noise_dbm": self.noise,
            "snr_db": self.snr,
            "signal_quality_pct": rssi_quality(self.rssi),
            "signal_bars": rssi_bars(self.rssi),
            "estimated_distance_m": self.distance_m,
            "encryption": self.encryption,
            "ciphers": "|".join(self.ciphers),
            "auth_suites": "|".join(self.auth_suites),
            "pmf": self.pmf,
            "wps": self.wps,
            "security_score": self.security_score,
            "security_grade": self.security_grade,
            "risks": "|".join(self.risks),
            "phy_modes": "|".join(self.phy_modes),
            "max_rate_mbps": self.max_rate_mbps,
            "beacon_interval_tu": self.beacon_interval,
            "dtim_period": self.dtim,
            "country": self.country,
            "mesh": self.is_mesh,
            "beacons_seen": self.beacons,
            "data_packets": self.data_packets,
            "connected_devices": self.client_count,
            "active_devices": self.active_client_count,
            "confirmed_devices": self.confirmed_client_count,
            "rf_only_devices": self.rf_only_client_count,
            "census_confidence": self.census_confidence,
            "census_note": self.census_note,
            "ap_confidence": self.ap_confidence,
            "ap_confidence_note": self.ap_confidence_note,
            "client_macs": "|".join(sorted(self.stations)),
            "first_seen": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.first_seen)),
            "last_seen": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.last_seen)),
            "source": self.source,
        }
