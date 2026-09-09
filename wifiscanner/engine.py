"""Correlation engine: merges every data source into one coherent picture."""
from __future__ import annotations

import time
from collections import Counter, defaultdict
from typing import Dict, List, Optional

from .models import AccessPoint, Station, channel_to_freq
from .oui import lookup as oui_lookup, normalize
from .trust import (Source, combine_confidence, confidence_label,
                    normalize_source, source_confidence)
from .util import log


def merge_ap(dst: AccessPoint, src: AccessPoint) -> AccessPoint:
    """Merge `src` into `dst`, preferring the richer / stronger value."""
    if src.ssid and not dst.ssid:
        dst.ssid = src.ssid
        dst.hidden = False
    for attr in ("channel", "frequency", "width_mhz", "noise", "country",
                 "beacon_interval", "dtim", "max_rate_mbps"):
        if getattr(dst, attr) in (None, "", 0) and getattr(src, attr) not in (None, "", 0):
            setattr(dst, attr, getattr(src, attr))
    if src.rssi is not None:
        dst.rssi = src.rssi if dst.rssi is None else max(dst.rssi, src.rssi)
        dst.rssi_max = max(x for x in (dst.rssi_max, src.rssi_max, src.rssi) if x is not None)
        mins = [x for x in (dst.rssi_min, src.rssi_min, src.rssi) if x is not None]
        dst.rssi_min = min(mins) if mins else None
    if src.security and src.security != ["OPEN"]:
        merged = set(dst.security) | set(src.security)
        merged.discard("OPEN")
        dst.security = sorted(merged, reverse=True)
    elif not dst.security:
        dst.security = list(src.security)
    dst.ciphers = sorted(set(dst.ciphers) | set(src.ciphers))
    dst.auth_suites = sorted(set(dst.auth_suites) | set(src.auth_suites))
    dst.phy_modes = sorted(set(dst.phy_modes) | set(src.phy_modes))
    dst.pmf = dst.pmf or src.pmf
    dst.wps = dst.wps or src.wps
    dst.is_mesh = dst.is_mesh or src.is_mesh
    dst.beacons += src.beacons
    dst.data_packets += src.data_packets
    dst.first_seen = min(dst.first_seen, src.first_seen)
    dst.last_seen = max(dst.last_seen, src.last_seen)
    dst.vendor = dst.vendor or src.vendor
    for mac, sta in src.stations.items():
        dst.add_station(sta)
    dst.raw.update({k: v for k, v in src.raw.items() if k not in dst.raw})
    if src.source and src.source not in dst.source:
        dst.source = f"{dst.source}+{src.source}" if dst.source else src.source
    return dst


class Engine:
    """Holds the merged model of the RF environment and derives analytics."""

    def __init__(self):
        self.aps: Dict[str, AccessPoint] = {}
        self.unassociated: Dict[str, Station] = {}
        self.sniffer_stats: dict = {}
        self.connection: dict = {}
        self.started = time.time()

    # ------------------------------------------------------------- ingest

    def ingest(self, aps: List[AccessPoint]) -> None:
        for ap in aps:
            bssid = normalize(ap.bssid)
            ap.bssid = bssid
            if not ap.vendor:
                ap.vendor = oui_lookup(bssid)
            if not ap.frequency and ap.channel:
                ap.frequency = channel_to_freq(ap.channel)
            cur = self.aps.get(bssid)
            self.aps[bssid] = merge_ap(cur, ap) if cur else ap

    def ingest_unassociated(self, stations: Dict[str, Station]) -> None:
        for mac, sta in stations.items():
            sta.sources.add(Source.MONITOR_RF)
            sta.evidence_kinds.add("probe-only")
            cur = self.unassociated.get(mac)
            if cur is None:
                self.unassociated[mac] = sta
            else:
                cur.packets += sta.packets
                cur.probed_ssids |= sta.probed_ssids
                cur.last_seen = max(cur.last_seen, sta.last_seen)
                cur.sources |= set(sta.sources)
                cur.evidence_kinds |= set(sta.evidence_kinds)

    def ingest_lan(self, stations: List[Station], bssid_hint: str = "",
                   authoritative: bool = False,
                   source: str = "") -> None:
        """Attach IP-layer facts to over-the-air stations (or add new ones).

        Weakness #1 (source correlation): ``authoritative=True`` marks the
        stations as router-confirmed ground truth (from ``iw station dump``
        on your own AP); plain LAN sweeps only add ``arp-only`` evidence and
        can never confirm an over-the-air binding by themselves.
        """
        src = normalize_source(source) if source else (
            Source.ASSOC_TABLE if authoritative else Source.LAN_ARP)
        by_mac = {}
        for ap in self.aps.values():
            for mac, sta in ap.stations.items():
                by_mac[mac] = sta
        target = self.aps.get(normalize(bssid_hint)) if bssid_hint else None
        for sta in stations:
            sta.sources.add(src)
            if authoritative:
                sta.confirmed = True
                sta.evidence_kinds.add("assoc-table")
                sta.evidence_kinds.discard("single-frame")
            else:
                sta.evidence_kinds.add("arp-only")
            existing = by_mac.get(sta.mac)
            if existing:
                # Correlate: the LAN record corroborates the RF record.
                # Router confirmation upgrades the RF binding to confirmed.
                existing.ip_address = sta.ip_address or existing.ip_address
                existing.hostname = sta.hostname or existing.hostname
                existing.open_ports = sta.open_ports or existing.open_ports
                existing.vendor = existing.vendor or sta.vendor
                existing.sources.add(src)
                existing.evidence_kinds |= set(sta.evidence_kinds)
                if authoritative:
                    existing.confirmed = True
                    existing.evidence_kinds.discard("single-frame")
            elif target is not None:
                target.add_station(sta)
            else:
                self.unassociated[sta.mac] = sta

    # ---------------------------------------------------------- accessors

    def sorted_aps(self, key: str = "rssi") -> List[AccessPoint]:
        aps = list(self.aps.values())
        if key == "rssi":
            return sorted(aps, key=lambda a: (a.rssi is None, -(a.rssi or -999)))
        if key == "clients":
            return sorted(aps, key=lambda a: -a.client_count)
        if key == "ssid":
            return sorted(aps, key=lambda a: (a.ssid or "\uffff").lower())
        if key == "channel":
            return sorted(aps, key=lambda a: (a.channel or 999))
        if key == "security":
            return sorted(aps, key=lambda a: a.security_score)
        return aps

    def all_stations(self) -> List[Station]:
        out = []
        for ap in self.aps.values():
            out.extend(ap.stations.values())
        out.extend(self.unassociated.values())
        return out

    def find(self, needle: str) -> List[AccessPoint]:
        n = (needle or "").lower()
        return [a for a in self.aps.values()
                if n in (a.ssid or "").lower() or n in a.bssid.lower()]

    # ---------------------------------------------------------- analytics

    def channel_congestion(self) -> Dict[str, List[dict]]:
        """Per-band channel occupancy, overlap and a recommendation."""
        bands: Dict[str, Dict[int, List[AccessPoint]]] = defaultdict(lambda: defaultdict(list))
        for ap in self.aps.values():
            if ap.channel:
                bands[ap.band][ap.channel].append(ap)
        report: Dict[str, List[dict]] = {}
        for band, chans in bands.items():
            rows = []
            for ch, aps in sorted(chans.items()):
                # 2.4 GHz channels overlap +/- 4; 5/6 GHz are non-overlapping
                overlap = 0
                if band == "2.4GHz":
                    for other, o_aps in chans.items():
                        if other != ch and abs(other - ch) <= 4:
                            overlap += len(o_aps)
                strongest = max((a.rssi for a in aps if a.rssi is not None),
                                default=None)
                rows.append({
                    "band": band, "channel": ch, "ap_count": len(aps),
                    "overlapping_aps": overlap,
                    "total_interferers": len(aps) + overlap,
                    "clients": sum(a.client_count for a in aps),
                    "strongest_rssi_dbm": strongest,
                    "ssids": "|".join(sorted({a.ssid for a in aps if a.ssid})),
                })
            report[band] = sorted(rows, key=lambda r: r["channel"])
        return report

    def best_channels(self) -> Dict[str, List[int]]:
        out = {}
        cong = self.channel_congestion()
        for band, rows in cong.items():
            candidates = [1, 6, 11] if band == "2.4GHz" else [r["channel"] for r in rows]
            score = {c: 0 for c in candidates}
            for r in rows:
                for c in candidates:
                    dist = abs(r["channel"] - c)
                    if band == "2.4GHz" and dist <= 4:
                        score[c] += r["ap_count"] * (5 - dist)
                    elif band != "2.4GHz" and dist == 0:
                        score[c] += r["ap_count"] * 5
            out[band] = [c for c, _ in sorted(score.items(), key=lambda kv: kv[1])][:3]
        return out

    # Rogue scoring weights: independent indicators, each 0-100 evidence.
    # A verdict of likely-rogue REQUIRES >= 2 independent indicators
    # (weakness #8); single-indicator groups are reported as unconfirmed.
    ROGUE_WEIGHTS = {
        "open-clone": 45,        # OPEN BSS mirrors a protected SSID
        "security-mismatch": 25,  # same SSID, different crypto
        "vendor-mismatch": 20,   # same SSID, different makers
        "pmf-mismatch": 15,      # PMF required on one, absent on the other
        "signal-anomaly": 10,    # same-SSID BSSIDs >30 dB apart (weak hint)
        "warden-unknown": 20,    # a BSSID outside your known-good baseline
        "channel-anomaly": 10,   # same-SSID BSSIDs on far-apart channels
    }
    ROGUE_CONFIRM_SCORE = 40     # >= this + >=2 indicators => likely-rogue

    def rogue_candidates(self, known_bssids: Optional[set] = None,
                         include_unconfirmed: bool = True) -> List[dict]:
        """Score same-SSID BSS groups for evil-twin likelihood (weakness #8).

        Every group gets independent ``indicators`` with a fused ``score``
        (0-100) and a ``verdict``:

        * ``likely-rogue`` — >= 2 independent indicators AND score >= 40.
          This is the only verdict that counts as a rogue alert.
        * ``unconfirmed`` — a single indicator. Listed for review with
          severity ``low``; explicitly NOT declared rogue, because mesh
          systems, extenders and multi-vendor enterprise deployments all
          produce single-indicator lookalikes.

        ``known_bssids`` (your warden baseline) adds the ``warden-unknown``
        indicator for BSSIDs you have never baselined.
        """
        by_ssid: Dict[str, List[AccessPoint]] = defaultdict(list)
        for ap in self.aps.values():
            if ap.ssid:
                by_ssid[ap.ssid].append(ap)
        known = {b.upper() for b in (known_bssids or set())}
        alerts = []
        for ssid, aps in by_ssid.items():
            if len(aps) < 2:
                continue
            vendors = {a.vendor for a in aps if a.vendor}
            secs = {a.encryption for a in aps}
            pmfs = {a.pmf for a in aps if a.pmf}
            rssis = [a.rssi for a in aps if a.rssi is not None]
            chans = {a.channel for a in aps if a.channel}
            reasons, indicators = [], []
            if len(vendors) > 1:
                reasons.append(f"multiple vendors: {', '.join(sorted(vendors))}")
                indicators.append("vendor-mismatch")
            if len(secs) > 1:
                reasons.append(f"inconsistent security: {', '.join(sorted(secs))}")
                indicators.append("security-mismatch")
            if any(a.encryption == "OPEN" for a in aps) and len(secs) > 1:
                reasons.append("open clone of a protected SSID")
                indicators.append("open-clone")
            if len(pmfs) > 1 and "required" in pmfs:
                reasons.append(f"PMF mismatch across BSSIDs: {', '.join(sorted(pmfs))}")
                indicators.append("pmf-mismatch")
            if rssis and max(rssis) - min(rssis) > 30:
                reasons.append(f"same SSID {max(rssis) - min(rssis)} dB apart — "
                               f"one may be much closer than your AP")
                indicators.append("signal-anomaly")
            if chans and max(chans) - min(chans) > 30:
                reasons.append("same SSID on far-apart channels — possible clone "
                               "on a quiet channel")
                indicators.append("channel-anomaly")
            if known:
                unknown = [a.bssid for a in aps if a.bssid not in known]
                if unknown and len(unknown) < len(aps):
                    reasons.append(f"{len(unknown)} BSSID(s) outside your warden "
                                   f"baseline: {', '.join(unknown)}")
                    indicators.append("warden-unknown")
            if not indicators:
                continue  # same SSID, same vendor/crypto: mesh/extender — quiet
            score = combine_confidence([self.ROGUE_WEIGHTS[i] for i in indicators])
            confirmed = len(indicators) >= 2 and score >= self.ROGUE_CONFIRM_SCORE
            if confirmed:
                verdict = "likely-rogue"
                severity = ("high" if "open-clone" in indicators else "medium")
            else:
                verdict = ("unconfirmed — single indicator only; do not treat "
                           "as rogue")
                severity = "low"
            row = {
                "ssid": ssid, "bssid_count": len(aps),
                "bssids": "|".join(a.bssid for a in aps),
                "severity": severity,
                "reasons": "; ".join(reasons),
                "indicators": "|".join(indicators),
                "indicator_count": len(indicators),
                "score": score,
                "confidence": confidence_label(score),
                "verdict": verdict,
            }
            if confirmed or include_unconfirmed:
                alerts.append(row)
        # Confirmed first, then by score.
        alerts.sort(key=lambda r: (r["verdict"] != "likely-rogue", -r["score"]))
        return alerts

    def rogue_confirmed(self, known_bssids: Optional[set] = None) -> List[dict]:
        """Only the multi-indicator likely-rogue verdicts (weakness #8)."""
        return [r for r in self.rogue_candidates(known_bssids) if
                r["verdict"] == "likely-rogue"]

    def client_census(self) -> Dict[str, dict]:
        """Per-AP RF-observed vs router-confirmed census (weakness #1)."""
        out = {}
        for bssid, ap in self.aps.items():
            c = ap.census
            c.update({"ssid": ap.ssid, "confidence": ap.census_confidence,
                      "confidence_label": confidence_label(ap.census_confidence),
                      "note": ap.census_note})
            out[bssid] = c
        return out

    def identity_report(self) -> dict:
        """Observed-MAC vs physical-device honesty report (weakness #2).

        We count OBSERVED MAC ADDRESSES. Because privacy MACs rotate, the
        number of observed addresses is an UPPER bound on devices, and the
        number of stable addresses is a LOWER bound — the truth is somewhere
        in between and passive observation alone cannot pin it down. This
        tool therefore reports the range and never claims two rotating
        addresses are (or are not) the same device.
        """
        stable, rotating = set(), set()
        for ap in self.aps.values():
            for s in ap.stations.values():
                (rotating if s.is_randomized else stable).add(s.mac)
        return {
            "observed_macs": len(stable) + len(rotating),
            "stable_macs": len(stable),
            "rotating_macs": len(rotating),
            "estimated_devices_min": len(stable) + (1 if rotating else 0),
            "estimated_devices_max": len(stable) + len(rotating),
            "note": ("counts are observed MAC addresses, not verified devices: "
                     f"{len(rotating)} rotating privacy address(es) observed; "
                     "each may alias the same physical radio across scans"),
        }

    def summary(self) -> dict:
        aps = list(self.aps.values())
        clients = [s for a in aps for s in a.stations.values()]
        confirmed = [s for s in clients if s.confirmed]
        rf_only = [s for s in clients if not s.confirmed]
        rogues = self.rogue_candidates()
        identities = self.identity_report()
        sec = Counter()
        for a in aps:
            sec[a.encryption] += 1
        bands = Counter(a.band for a in aps)
        grades = Counter(a.security_grade for a in aps)
        vendors = Counter(a.vendor or "unknown" for a in aps)
        rssis = [a.rssi for a in aps if a.rssi is not None]
        return {
            "scan_started": time.strftime("%Y-%m-%d %H:%M:%S",
                                          time.localtime(self.started)),
            "duration_s": round(time.time() - self.started, 1),
            "access_points": len(aps),
            "unique_ssids": len({a.ssid for a in aps if a.ssid}),
            "hidden_ssids": sum(1 for a in aps if a.hidden),
            "connected_devices": len(clients),
            "connected_devices_confirmed": len(confirmed),
            "connected_devices_rf_only": len(rf_only),
            "active_devices": sum(1 for c in clients if c.data_packets > 0),
            "unassociated_devices": len(self.unassociated),
            "randomized_macs": sum(1 for c in clients if c.is_randomized),
            "observed_macs": identities["observed_macs"],
            "estimated_devices_range":
                f"{identities['estimated_devices_min']}-"
                f"{identities['estimated_devices_max']} "
                f"(observed MACs, not verified devices)",
            "open_networks": sum(1 for a in aps if a.encryption == "OPEN"),
            "wep_networks": sum(1 for a in aps if "WEP" in a.security),
            "wpa3_networks": sum(1 for a in aps if "WPA3" in a.security),
            "wps_enabled": sum(1 for a in aps if a.wps),
            "mesh_networks": sum(1 for a in aps if a.is_mesh),
            "strongest_rssi_dbm": max(rssis) if rssis else None,
            "weakest_rssi_dbm": min(rssis) if rssis else None,
            "median_rssi_dbm": sorted(rssis)[len(rssis) // 2] if rssis else None,
            "bands": dict(bands),
            "security_distribution": dict(sec),
            "security_grades": dict(grades),
            "top_vendors": dict(vendors.most_common(10)),
            "rogue_alerts": sum(1 for r in rogues
                                if r["verdict"] == "likely-rogue"),
            "rogue_unconfirmed": sum(1 for r in rogues
                                     if r["verdict"] != "likely-rogue"),
            "recommended_channels": self.best_channels(),
            "sniffer": self.sniffer_stats,
        }
