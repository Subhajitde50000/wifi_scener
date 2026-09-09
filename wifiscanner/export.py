"""Structured exporters: CSV (primary), JSON, HTML report, Markdown."""
from __future__ import annotations

import csv
import html
import json
import os
import time
from typing import List

from .engine import Engine
from .models import AccessPoint, rssi_quality
from .util import log

AP_COLUMNS = [
    "scan_id", "bssid", "ssid", "hidden", "vendor", "band", "channel",
    "frequency_mhz", "channel_width_mhz", "rssi_dbm", "rssi_min_dbm",
    "rssi_max_dbm", "noise_dbm", "snr_db", "signal_quality_pct", "signal_bars",
    "estimated_distance_m", "encryption", "ciphers", "auth_suites", "pmf",
    "wps", "security_score", "security_grade", "risks", "phy_modes",
    "max_rate_mbps", "beacon_interval_tu", "dtim_period", "country", "mesh",
    "beacons_seen", "data_packets", "connected_devices", "active_devices",
    "confirmed_devices", "rf_only_devices", "census_confidence", "census_note",
    "ap_confidence", "ap_confidence_note",
    "bss_load_sta_count", "channel_utilization_pct", "eapol_frames",
    "deauth_frames", "client_macs", "first_seen", "last_seen", "source",
]

STA_COLUMNS = [
    "scan_id", "mac", "vendor", "is_randomized", "identity_class",
    "associated_bssid",
    "associated_ssid", "ip_address", "hostname", "open_ports", "rssi_dbm",
    "rssi_min_dbm", "rssi_max_dbm", "signal_quality_pct",
    "estimated_distance_m", "channel", "packets", "data_packets",
    "bytes_seen", "dwell_s", "probed_ssids", "state",
    "sources", "evidence", "binding_confidence", "confidence", "confirmed",
    "identity_note", "first_seen", "last_seen",
]

ROGUE_COLUMNS = [
    "ssid", "bssid_count", "bssids", "severity", "reasons",
    "indicators", "indicator_count", "score", "confidence", "verdict",
]


def _ts() -> str:
    return time.strftime("%Y%m%d-%H%M%S")


def _ap_rows(engine: Engine, scan_id: str) -> List[dict]:
    rows = []
    for ap in engine.sorted_aps("rssi"):
        r = ap.to_row()
        r["scan_id"] = scan_id
        r["bss_load_sta_count"] = ap.raw.get("bss_load_sta_count", "")
        r["channel_utilization_pct"] = ap.raw.get("channel_utilization_pct", "")
        r["eapol_frames"] = ap.raw.get("eapol_frames", "")
        r["deauth_frames"] = ap.raw.get("deauths", "")
        rows.append({c: r.get(c, "") for c in AP_COLUMNS})
    return rows


def _sta_rows(engine: Engine, scan_id: str) -> List[dict]:
    from .models import estimate_distance_m, channel_to_freq
    rows = []
    for ap in engine.sorted_aps("rssi"):
        for sta in sorted(ap.stations.values(), key=lambda s: -(s.rssi or -999)):
            d = sta.to_row()
            d.update({
                "scan_id": scan_id,
                "associated_bssid": ap.bssid,
                "associated_ssid": ap.ssid,
                "rssi_dbm": sta.rssi,
                "rssi_min_dbm": sta.rssi_min,
                "rssi_max_dbm": sta.rssi_max,
                "estimated_distance_m": estimate_distance_m(
                    sta.rssi, channel_to_freq(sta.channel or ap.channel or 0)),
                "state": "associated",
            })
            rows.append({c: d.get(c, "") for c in STA_COLUMNS})
    for sta in engine.unassociated.values():
        d = sta.to_row()
        d.update({
            "scan_id": scan_id, "associated_bssid": "", "associated_ssid": "",
            "rssi_dbm": sta.rssi, "rssi_min_dbm": sta.rssi_min,
            "rssi_max_dbm": sta.rssi_max,
            "estimated_distance_m": estimate_distance_m(
                sta.rssi, channel_to_freq(sta.channel or 0)),
            "state": "unassociated/probing",
        })
        rows.append({c: d.get(c, "") for c in STA_COLUMNS})
    return rows


def _write_csv(path: str, columns: List[str], rows: List[dict]) -> str:
    from .privacy import secure_file
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.DictWriter(fh, fieldnames=columns, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)
    secure_file(path)  # exports contain device identities: owner-only
    log.info("wrote %-42s (%d rows)", path, len(rows))
    return path


def export_all(engine: Engine, outdir: str = "output", prefix: str = "",
               formats=("csv", "json"), scan_id: str = "",
               anonymize: bool = False, salt: str = "") -> List[str]:
    """Write every artefact and return the list of files created.

    ``anonymize=True`` pseudonymises client MACs (salted HMAC tokens) and
    drops hostnames/IPs/probe lists from the exported files (weakness #3),
    so reports can be shared without leaking device identities. A fresh
    random salt is used per export unless one is passed, and the salt is
    NEVER written to the export.
    """
    from .privacy import anonymize_hostname, hash_mac, new_salt, secure_file
    scan_id = scan_id or _ts()
    prefix = prefix or f"wifi-{scan_id}"
    os.makedirs(outdir, exist_ok=True)
    base = os.path.join(outdir, prefix)
    written: List[str] = []

    ap_rows = _ap_rows(engine, scan_id)
    sta_rows = _sta_rows(engine, scan_id)
    summary = engine.summary()
    congestion = engine.channel_congestion()
    rogues = engine.rogue_candidates()
    if anonymize:
        salt = salt or new_salt()
        for r in sta_rows:
            r["mac"] = hash_mac(r.get("mac", ""), salt)
            r["ip_address"] = ""
            r["hostname"] = anonymize_hostname(r.get("hostname", ""))
            r["probed_ssids"] = ""
        for r in ap_rows:
            r["client_macs"] = "|".join(
                hash_mac(m, salt) for m in str(r.get("client_macs", "") or "")
                .split("|") if m)
        summary["anonymized_export"] = True
        summary["anonymization_note"] = ("client MACs are salted one-export "
                                         "pseudonyms; unlinkable across exports")

    if "csv" in formats:
        written.append(_write_csv(f"{base}_networks.csv", AP_COLUMNS, ap_rows))
        written.append(_write_csv(f"{base}_devices.csv", STA_COLUMNS, sta_rows))
        crows = [r for rows in congestion.values() for r in rows]
        if crows:
            written.append(_write_csv(
                f"{base}_channels.csv",
                ["band", "channel", "ap_count", "overlapping_aps",
                 "total_interferers", "clients", "strongest_rssi_dbm", "ssids"],
                crows))
        if rogues:
            written.append(_write_csv(
                f"{base}_rogue_alerts.csv", ROGUE_COLUMNS, rogues))
        flat = [{"metric": k, "value": json.dumps(v) if isinstance(v, (dict, list)) else v}
                for k, v in summary.items()]
        written.append(_write_csv(f"{base}_summary.csv", ["metric", "value"], flat))

    if "json" in formats:
        payload = {
            "scan_id": scan_id,
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "summary": summary,
            "connection": engine.connection,
            "networks": ap_rows,
            "devices": sta_rows,
            "channel_congestion": congestion,
            "rogue_alerts": rogues,
        }
        p = f"{base}.json"
        with open(p, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, default=str)
        secure_file(p)
        log.info("wrote %-42s", p)
        written.append(p)

    if "html" in formats:
        written.append(_write_html(f"{base}.html", scan_id, summary, ap_rows,
                                   sta_rows, congestion, rogues))
    if "md" in formats:
        written.append(_write_md(f"{base}.md", scan_id, summary, ap_rows, rogues))
    return written


# ------------------------------------------------------------------- HTML

_CSS = """
:root{--bg:#0b0f17;--card:#141a26;--fg:#e6edf3;--mut:#8b98ab;--acc:#4ea1ff;
--good:#3fb950;--warn:#d29922;--bad:#f85149;--line:#232b3a}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.5 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;padding:28px}
h1{font-size:24px;margin:0 0 4px}h2{font-size:17px;margin:28px 0 10px;color:var(--acc)}
.sub{color:var(--mut);margin-bottom:20px}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px}
.card .v{font-size:26px;font-weight:600}.card .k{color:var(--mut);font-size:11px;
text-transform:uppercase;letter-spacing:.5px}
table{width:100%;border-collapse:collapse;background:var(--card);border-radius:10px;
overflow:hidden;font-size:12.5px;margin-top:8px}
th{background:#1b2434;text-align:left;padding:9px 10px;color:var(--mut);
font-weight:600;position:sticky;top:0;white-space:nowrap}
td{padding:8px 10px;border-top:1px solid var(--line);white-space:nowrap}
tr:hover td{background:#1a2233}
.g{font-weight:700;padding:2px 7px;border-radius:5px;font-size:11px}
.gA{background:rgba(63,185,80,.18);color:var(--good)}
.gB{background:rgba(78,161,255,.18);color:var(--acc)}
.gC{background:rgba(210,153,34,.18);color:var(--warn)}
.gF{background:rgba(248,81,73,.18);color:var(--bad)}
.bar{display:inline-block;height:7px;border-radius:4px;background:var(--acc);vertical-align:middle}
.wrap{overflow:auto;max-height:640px;border-radius:10px}
.alert{background:rgba(248,81,73,.1);border:1px solid var(--bad);border-radius:8px;
padding:10px 14px;margin:6px 0}
"""


def _grade_cls(g: str) -> str:
    return {"A+": "gA", "A": "gA", "B": "gB", "C": "gC", "D": "gF", "F": "gF"}.get(g, "gB")


def _write_html(path, scan_id, summary, ap_rows, sta_rows, congestion, rogues) -> str:
    def esc(v):
        return html.escape(str(v if v not in (None, "") else "-"))

    cards = [("Networks", summary["access_points"]),
             ("Devices Found", summary["connected_devices"]),
             ("Active Devices", summary["active_devices"]),
             ("Probing Devices", summary["unassociated_devices"]),
             ("Open Networks", summary["open_networks"]),
             ("WPA3", summary["wpa3_networks"]),
             ("WPS Exposed", summary["wps_enabled"]),
             ("Rogue Alerts", summary["rogue_alerts"])]
    parts = [f"<!doctype html><meta charset=utf-8><title>Wi-Fi Survey {scan_id}</title>",
             f"<style>{_CSS}</style>",
             "<h1>Wi-Fi Intelligence Report</h1>",
             f"<div class=sub>Scan <b>{esc(scan_id)}</b> &middot; {esc(summary['scan_started'])} "
             f"&middot; {esc(summary['duration_s'])}s</div>", "<div class=cards>"]
    for k, v in cards:
        parts.append(f"<div class=card><div class=k>{k}</div><div class=v>{esc(v)}</div></div>")
    parts.append("</div>")

    if rogues:
        parts.append("<h2>Rogue / Evil-Twin Alerts</h2>")
        for r in rogues:
            parts.append(f"<div class=alert><b>{esc(r['ssid'])}</b> "
                         f"[{esc(r['severity'])}] &mdash; {esc(r['reasons'])}</div>")

    show = ["ssid", "bssid", "vendor", "band", "channel", "rssi_dbm",
            "signal_quality_pct", "encryption", "security_grade",
            "connected_devices", "estimated_distance_m", "risks"]
    parts.append("<h2>Access Points</h2><div class=wrap><table><tr>"
                 + "".join(f"<th>{h.replace('_',' ').title()}</th>" for h in show) + "</tr>")
    for r in ap_rows:
        tds = []
        for h in show:
            v = r.get(h, "")
            if h == "security_grade":
                tds.append(f"<td><span class='g {_grade_cls(str(v))}'>{esc(v)}</span></td>")
            elif h == "signal_quality_pct" and v != "":
                tds.append(f"<td><span class=bar style='width:{int(v or 0)*.6}px'></span> {esc(v)}%</td>")
            else:
                tds.append(f"<td>{esc(v)}</td>")
        parts.append("<tr>" + "".join(tds) + "</tr>")
    parts.append("</table></div>")

    dshow = ["mac", "vendor", "is_randomized", "associated_ssid",
             "associated_bssid", "ip_address", "hostname", "rssi_dbm",
             "packets", "data_packets", "state", "probed_ssids"]
    parts.append("<h2>Devices</h2><div class=wrap><table><tr>"
                 + "".join(f"<th>{h.replace('_',' ').title()}</th>" for h in dshow) + "</tr>")
    for r in sta_rows:
        parts.append("<tr>" + "".join(f"<td>{esc(r.get(h,''))}</td>" for h in dshow) + "</tr>")
    parts.append("</table></div>")

    parts.append("<h2>Channel Congestion</h2><div class=wrap><table>"
                 "<tr><th>Band</th><th>Channel</th><th>APs</th>"
                 "<th>Overlapping</th><th>Clients</th><th>Strongest</th></tr>")
    for band, rows in congestion.items():
        for r in rows:
            parts.append(f"<tr><td>{esc(band)}</td><td>{esc(r['channel'])}</td>"
                         f"<td>{esc(r['ap_count'])}</td><td>{esc(r['overlapping_aps'])}</td>"
                         f"<td>{esc(r['clients'])}</td>"
                         f"<td>{esc(r['strongest_rssi_dbm'])} dBm</td></tr>")
    parts.append("</table></div>")
    rec = summary.get("recommended_channels", {})
    if rec:
        parts.append("<h2>Recommended Channels</h2><div class=cards>")
        for band, chans in rec.items():
            parts.append(f"<div class=card><div class=k>{esc(band)}</div>"
                         f"<div class=v>{esc(', '.join(map(str, chans)))}</div></div>")
        parts.append("</div>")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(parts))
    log.info("wrote %-42s", path)
    return path


def _write_md(path, scan_id, summary, ap_rows, rogues) -> str:
    L = [f"# Wi-Fi Survey `{scan_id}`", "",
         f"- Started: {summary['scan_started']} ({summary['duration_s']}s)",
         f"- Access points: **{summary['access_points']}**",
         f"- Devices detected: **{summary['connected_devices']}** "
         f"({summary['active_devices']} actively transmitting)",
         f"- Unassociated/probing devices: {summary['unassociated_devices']}",
         f"- Open: {summary['open_networks']} | WEP: {summary['wep_networks']} | "
         f"WPA3: {summary['wpa3_networks']} | WPS: {summary['wps_enabled']}", ""]
    if rogues:
        L += ["## Rogue alerts", ""]
        L += [f"- **{r['ssid']}** ({r['severity']}): {r['reasons']}" for r in rogues] + [""]
    L += ["## Networks", "",
          "| SSID | BSSID | Vendor | Band | Ch | RSSI | Security | Grade | Devices |",
          "|---|---|---|---|---|---|---|---|---|"]
    for r in ap_rows:
        L.append(f"| {r['ssid'] or '<hidden>'} | {r['bssid']} | {r['vendor'] or '-'} "
                 f"| {r['band']} | {r['channel']} | {r['rssi_dbm']} dBm "
                 f"| {r['encryption']} | {r['security_grade']} | {r['connected_devices']} |")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(L) + "\n")
    log.info("wrote %-42s", path)
    return path
