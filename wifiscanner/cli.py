"""wifiscanner command-line interface."""
from __future__ import annotations

import argparse
import os
import sys
import time

from . import __version__, inject as ij
from .backends import lan, sniffer, survey
from .display import (print_banner, print_congestion, print_detail,
                      print_devices, print_networks, print_rogues,
                      print_summary, print_rows, console, _RICH)
from .engine import Engine
from .export import export_all
from .locate import Tracker, ascii_map, load_sensors, load_zones
from .defense import Watchdog, audit_ap, audit_engine
from .oui import db_size, is_randomized, normalize
from .store import Store, parse_when
from .util import is_root, log, os_name, setup_logging

LEGAL = (
    "SCOPE: passive, defensive, own-network-first. Every survey, IDS, audit "
    "and history feature only listens to what is broadcast in public "
    "airspace and reads YOUR OWN router's association table. The single "
    "exception is `inject`, which can transmit - but only as an explicit, "
    "opt-in, AUTHORIZED self-test of your own defences (IDS sensor canaries, "
    "active probe scanning, a bounded own-AP PMF/deauth-resistance check). "
    "It defaults to a DRY RUN (nothing emitted), needs root plus --authorized "
    "(--yes for deauth frames), is hard rate-capped below attack thresholds, "
    "refuses broadcast/third-party targets, and logs every frame. It contains "
    "no flood, AP-clone, jam, key-crack or decrypt capability. Continuous "
    "history recording is restricted to your own network. Use transmission "
    "only on infrastructure you own or are authorised in writing to test. "
    "`lab` is a LOCAL phishing-awareness simulation that uses synthetic "
    "credentials and never contacts a real authentication service. `wpa-lab` "
    "is an OFFLINE decryption laboratory: it only opens laboratory-generated "
    "captures using laboratory-controlled key material the instructor owns "
    "and hands out."
)


def cmd_research_ui(args) -> int:
    from wifiscanner.research.ui import start_ui_server
    db_path = f"sqlite:///{args.db}" if getattr(args, "db", None) else "sqlite:///research_labs.sqlite"
    try:
        start_ui_server(db_path, args.bind, args.port)
    except KeyboardInterrupt:
        print("\nResearch UI stopped.")
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"Failed to start UI: {e}")
        return 1
    return 0

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="wifiscanner",
        description="Advanced passive Wi-Fi survey, client-attribution and CSV export engine.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  wifiscanner scan                          quick survey of nearby networks
  wifiscanner scan -o out --format csv json html
  wifiscanner monitor -i wlan0 -d 120       count devices per AP (root, passive)
  wifiscanner own                           full client census of YOUR network
  wifiscanner record --db home.sqlite       keep presence history of your AP
  wifiscanner presence --db home.sqlite --since -24h
  wifiscanner locate --db home.sqlite --sensors sensors.csv
  wifiscanner trail --db home.sqlite --sensors sensors.csv --zones zones.csv \
      --mac AC:BC:32:01:02:03
  wifiscanner capture -i wlan0 -d 3600 --ring-segments 8 --rotate-mb 64
  wifiscanner traffic capture.pcap -o out   dissect unencrypted frames
  wifiscanner offline capture.pcap          analyse an existing capture
  wifiscanner ids -i wlan0 --pcap hour.pcap  passive IDS: deauth floods,
                                              handshake-harvest signatures,
                                              beacon mutations, rogue BSSIDs
  wifiscanner audit                           hardening report for YOUR network
  wifiscanner frames capture.pcap             802.11 frame-by-frame anatomy
                                              (how all of this works)
  wifiscanner inject --mode ids-selftest      offline test: does MY IDS detect
                                              deauth/beacon/warden signatures?
  wifiscanner inject --mode canary -i wlan0   dry run by default: preview the
      --channels 1,6,11                          probe markers, add --transmit
                                              --authorized to actually emit
  wifiscanner inject --mode pmf-test -i wlan0 -c 6 --bssid MY-AP \\
      --client MY-test-laptop --transmit --authorized --yes
  wifiscanner inject --mode deauth -i wlan0 -c 6 --frame-type both \\
      --bssid MY-AP --client MY-test-laptop --count 10 --transmit \\
      --authorized --yes        # bounded, unicast, audited kick TEST
  wifiscanner lab                           LOCAL phishing-awareness lab:
                                              fake captive portal + instructor
                                              dashboard (synthetic credentials
                                              only; never contacts a real
                                              service)
  wifiscanner lab --self-test               prove the lab end-to-end offline
  wifiscanner lab --reset --yes                    wipe submissions between classes
  wifiscanner wpa-lab inventory lesson.pcap        WPA lab: list BSS security,
                                                     handshakes, frame states
  wifiscanner wpa-lab make-fixture lesson.pcap     build a cryptographically
      --ssid ClassNet --password 'lab-secret'        real WPA2 lab capture
  wifiscanner wpa-lab try lesson.pcap --ssid ClassNet --password guess1
                                                   verify a candidate key via
                                                     the handshake MIC
  wifiscanner wpa-lab decrypt lesson.pcap --password 'lab-secret' -o out
                                                   authorised decryption:
                                                     frames CSV + report +
                                                     decrypted.pcap
  wifiscanner wpa-lab web lesson.pcap --password 'lab-secret'
                                                   student/instructor web lab
  wifiscanner mac-lab make-dataset macds --seed 8 --fresh
                                                   instructor: build the MAC
                                                     randomization dataset
  wifiscanner mac-lab correlate macds            evidence matrix + engine
                                                   clusters (twin trap inside)
  wifiscanner mac-lab explain macds M1 M2        full reasoning for one pair
  printf '[["AA:BB:CC:DD:EE:01","AA:BB:CC:DD:EE:02"]]' | wifiscanner mac-lab score macds --submit -
                                                   grade a clustering answer
  wifiscanner mac-lab web macds                  student portal + instructor
                                                     dashboard (token-gated)
  wifiscanner track-lab make-dataset tds --seed 9 --fresh
                                                   instructor: 2 weeks of
                                                     synthetic sightings
  wifiscanner track-lab history tds --mac 3C:5A:B4:71:00:42
                                                   one device's visit timeline
  wifiscanner track-lab compare tds --since 2d   short window vs full
                                                     retention, side by side
  wifiscanner track-lab web tds                  student portal + instructor
                                                     dashboard (token-gated)
  wifiscanner stealth-lab make-scenario scn --seed 10 --fresh
                                                   instructor: 4 days of
                                                     synthetic host telemetry
                                                     with an implant inside
  wifiscanner stealth-lab hunt scn             league of suspects +
                                                   explainable signals
  wifiscanner stealth-lab web scn --port 8823  defender console + instructor
                                                     dashboard
  wifiscanner response-lab simulate --mode dry-run
                                                   IDS-rule pipeline: what
                                                     WOULD get blocked
  wifiscanner response-lab simulate --mode auto --enable-rule R6 \\
      --clear-allowlist                          the friendly-fire exercise
  wifiscanner scan-lab web --port 8825          scope-control scan console
                                                     (virtual estate 10.77.*)
  wifiscanner cred-lab web /tmp/lesson.pcap     credential-security console
                                                     on :8826 (lab identities)
  wifiscanner priv-lab web --db /tmp/priv       privacy/randomization lab
                                                     on :8827 (synthetic)
  wifiscanner rf-lab web                          interference console :8828
                                                     (simulated metrics)
  wifiscanner handshake-lab web --db /tmp/hs    handshake/password
                                                     auditing lab :8829
  wifiscanner response-lab web --port 8824     response console + instructor
                                                     approvals/reset/rollback
  wifiscanner interfaces                    list wireless adapters
""")
    p.add_argument("--version", action="version", version=f"wifiscanner {__version__}")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("-q", "--quiet", action="store_true")
    p.add_argument("--no-banner", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("-i", "--interface", default="", help="wireless interface")
        sp.add_argument("-o", "--output", default="", metavar="DIR",
                        help="export directory (enables CSV export)")
        sp.add_argument("--prefix", default="", help="output filename prefix")
        sp.add_argument("--format", nargs="+", default=["csv", "json"],
                        choices=["csv", "json", "html", "md"])
        sp.add_argument("--sort", default="rssi",
                        choices=["rssi", "clients", "ssid", "channel", "security"])
        sp.add_argument("--limit", type=int, default=0)
        sp.add_argument("--db", default="", metavar="SQLITE",
                        help="also persist this scan into a history database")
        sp.add_argument("--sensor", default="", metavar="NAME",
                        help="tag stored rows with this sensor id (multi-AP setups)")
        sp.add_argument("--retain-days", type=float, default=90.0,
                        help="history retention for --db (0 = keep forever, "
                             "not recommended)")
        sp.add_argument("--privacy-mode", default="standard",
                        choices=["standard", "minimal", "ephemeral"],
                        help="minimal = pseudonymised MACs, no hostnames/probes; "
                             "ephemeral = refuse all persistence")
        sp.add_argument("--anonymize", action="store_true",
                        help="pseudonymise client MACs in exports (salted, "
                             "per-export, unlinkable)")
        return sp

    s = common(sub.add_parser("scan", help="survey nearby access points"))
    s.add_argument("--backend", default="auto",
                   choices=["auto", "nmcli", "iw", "iwlist", "airport", "netsh"])
    s.add_argument("--no-rescan", action="store_true")

    m = common(sub.add_parser("monitor", help="passively count devices per AP (root)"))
    m.add_argument("-d", "--duration", type=float, default=60.0)
    m.add_argument("-c", "--channels", default="",
                   help="comma list, e.g. 1,6,11 (default: hop all)")
    m.add_argument("--bands", nargs="+", default=["2.4GHz", "5GHz"],
                   choices=["2.4GHz", "5GHz", "6GHz"])
    m.add_argument("--bssid", default="", help="lock onto one AP")
    m.add_argument("--hop-interval", type=float, default=0.35)
    m.add_argument("--airmon", action="store_true", help="use airmon-ng")
    m.add_argument("--no-monitor-setup", action="store_true",
                   help="interface is already in monitor mode")
    m.add_argument("--write-pcap", default="", metavar="FILE")

    f = common(sub.add_parser("full", help="scan + monitor + LAN inventory + export"))
    f.add_argument("-d", "--duration", type=float, default=60.0)
    f.add_argument("--bands", nargs="+", default=["2.4GHz", "5GHz"])
    f.add_argument("--airmon", action="store_true")
    f.add_argument("--no-monitor-setup", action="store_true")
    f.add_argument("--lan", action="store_true", help="also inventory current LAN")
    f.add_argument("--ports", action="store_true")

    d = common(sub.add_parser("detail", help="A-to-Z detail for a network"))
    d.add_argument("target", help="SSID or BSSID (substring ok)")
    d.add_argument("-d", "--duration", type=float, default=45.0,
                   help="monitor seconds to enumerate its clients (root)")
    d.add_argument("--no-monitor", action="store_true")
    d.add_argument("--airmon", action="store_true")
    d.add_argument("--no-monitor-setup", action="store_true")

    dv = common(sub.add_parser("devices", help="list detected client devices"))
    dv.add_argument("-d", "--duration", type=float, default=60.0)
    dv.add_argument("--lan", action="store_true", help="scan the LAN you are joined to")
    dv.add_argument("--subnet", default="", help="e.g. 192.168.1.0/24")
    dv.add_argument("--ports", action="store_true", help="port-scan LAN devices")
    dv.add_argument("--no-monitor", action="store_true")
    dv.add_argument("--airmon", action="store_true")
    dv.add_argument("--no-monitor-setup", action="store_true")

    w = common(sub.add_parser("watch", help="live refreshing dashboard"))
    w.add_argument("-n", "--interval", type=float, default=8.0)
    w.add_argument("--monitor", action="store_true", help="add monitor-mode capture")
    w.add_argument("--airmon", action="store_true")
    w.add_argument("--no-monitor-setup", action="store_true")

    off = common(sub.add_parser("offline", help="analyse an existing pcap"))
    off.add_argument("pcap")

    ow = common(sub.add_parser(
        "own", help="authoritative client census of YOUR OWN network/AP"))
    ow.add_argument("-d", "--duration", type=float, default=25.0)
    ow.add_argument("--no-lan", action="store_true",
                    help="skip the active LAN sweep (ARP/DNS/ports)")
    ow.add_argument("--ports", action="store_true", help="port-scan your LAN hosts")
    ow.add_argument("--no-monitor", action="store_true")
    ow.add_argument("--airmon", action="store_true")
    ow.add_argument("--no-monitor-setup", action="store_true")

    rec = sub.add_parser("record", help="continuously record YOUR network's "
                                        "presence history to SQLite")
    rec.add_argument("--db", default="presence.sqlite", metavar="SQLITE")
    rec.add_argument("-i", "--interface", default="")
    rec.add_argument("--bssid", default="",
                     help="AP to record (comma-separated list). Default: your own "
                          "current connection. Refuses open-ended bystander logging.")
    rec.add_argument("--sensor", default="", help="sensor id for multi-AP lateration")
    rec.add_argument("-n", "--interval", type=float, default=30.0,
                     help="seconds between snapshots")
    rec.add_argument("-d", "--duration", type=float, default=0.0,
                     help="total seconds (0 = run until Ctrl-C)")
    rec.add_argument("--lan", action="store_true",
                     help="enrich with ARP/DNS/ports (hostnames, IPs)")
    rec.add_argument("--backend", default="auto",
                     choices=["auto", "nmcli", "iw", "iwlist", "airport", "netsh"])
    rec.add_argument("--pcap", default="",
                     help="one-shot: import an existing capture into the DB and exit")
    rec.add_argument("--retain-days", type=float, default=90.0,
                     help="history retention in days (0 = keep forever, "
                          "not recommended)")
    rec.add_argument("--privacy-mode", default="standard",
                     choices=["standard", "minimal", "ephemeral"],
                     help="minimal = pseudonymised MACs, no hostnames; "
                          "ephemeral = refuse to persist")
    rec.add_argument("--anonymize", action="store_true",
                     help="store salted MAC pseudonyms instead of real MACs")

    pr = sub.add_parser("presence", help="query presence history: who was on, when")
    pr.add_argument("--db", default="presence.sqlite")
    pr.add_argument("--mac", default="")
    pr.add_argument("--ssid", default="")
    pr.add_argument("--since", default="", help="'-24h', '2026-09-07', '18:00'")
    pr.add_argument("--until", default="")
    pr.add_argument("--gap", type=float, default=300.0,
                    help="seconds of absence that ends a session")
    pr.add_argument("--known", action="store_true", help="show device roster instead")
    pr.add_argument("-o", "--output", default="", help="also export session CSV here")
    pr.add_argument("--limit", type=int, default=100)

    loc = sub.add_parser("locate", help="estimate device positions from multiple "
                                        "sensors (trilateration + zone dwell)")
    loc.add_argument("--db", default="presence.sqlite")
    loc.add_argument("--sensors", required=True,
                     help="CSV: name,x,y[,floor,rssi_offset_db,tx_power_dbm] (metres)")
    loc.add_argument("--zones", default="", help="CSV: zone,x,y polygon vertices")
    loc.add_argument("--mac", default="")
    loc.add_argument("--window", type=float, default=3.0,
                     help="seconds to fuse readings across sensors")
    loc.add_argument("--n-exp", type=float, default=2.7,
                     help="path-loss exponent (2 free-space, 2.7 indoor, 3.5 dense)")
    loc.add_argument("--since", default="")
    loc.add_argument("--until", default="")
    loc.add_argument("--recompute", action="store_true",
                     help="re-derive fixes and store them back into the DB")
    loc.add_argument("--live", action="store_true",
                     help="also do a short live capture first")
    loc.add_argument("-d", "--duration", type=float, default=20.0)
    loc.add_argument("-i", "--interface", default="")
    loc.add_argument("--airmon", action="store_true")
    loc.add_argument("--no-monitor-setup", action="store_true")

    tr = sub.add_parser("trail", help="reconstruct a device's movement path "
                                      "across YOUR sensor grid")
    tr.add_argument("--mac", required=True)
    tr.add_argument("--db", default="presence.sqlite")
    tr.add_argument("--sensors", default="")
    tr.add_argument("--zones", default="")
    tr.add_argument("--window", type=float, default=3.0)
    tr.add_argument("--since", default="")
    tr.add_argument("--until", default="")
    tr.add_argument("--map", action="store_true", help="ASCII movement map")
    tr.add_argument("-o", "--output", default="")

    cap = sub.add_parser("capture", help="raw 802.11 frame capture to pcap "
                                        "(ring buffer, rotation; passive)")
    cap.add_argument("-i", "--interface", default="")
    cap.add_argument("-d", "--duration", type=float, default=300.0)
    cap.add_argument("-c", "--channels", default="")
    cap.add_argument("--bands", nargs="+", default=["2.4GHz", "5GHz"],
                     choices=["2.4GHz", "5GHz", "6GHz"])
    cap.add_argument("--bssid", default="")
    cap.add_argument("--hop-interval", type=float, default=0.35)
    cap.add_argument("-o", "--pcap", default="capture.pcap", metavar="FILE")
    cap.add_argument("--rotate-mb", type=float, default=0.0,
                     help="start a new file after N MB")
    cap.add_argument("--ring-segments", type=int, default=0,
                     help="keep only N segment files (bounded ring buffer)")
    cap.add_argument("--analyze", action="store_true",
                     help="also parse the capture into AP/client tables at exit")
    cap.add_argument("--ack-sensitive", action="store_true",
                     help="acknowledge that raw captures contain sensitive "
                          "third-party data (silences the warning)")
    cap.add_argument("--strip-payloads", action="store_true",
                     help="privacy-preserving capture: truncate frames to 128 "
                          "bytes (headers for counting/IDS, no payloads)")
    cap.add_argument("--max-age-days", type=float, default=0.0,
                     help="delete capture segments older than N days on exit "
                          "(0 = keep)")
    cap.add_argument("--airmon", action="store_true")
    cap.add_argument("--no-monitor-setup", action="store_true")

    trf = sub.add_parser("traffic", help="dissect UNENCRYPTED frames from a "
                                        "capture or live monitor interface")
    trf.add_argument("pcap", nargs="?", default="",
                     help="capture file to dissect (omit with --live)")
    trf.add_argument("--live", action="store_true",
                     help="live dissection (root; monitor interface)")
    trf.add_argument("-i", "--interface", default="")
    trf.add_argument("-d", "--duration", type=float, default=30.0)
    trf.add_argument("--max-frames", type=int, default=200000)
    trf.add_argument("--limit", type=int, default=40)
    trf.add_argument("-o", "--output", default="", help="export events/flows CSV here")
    trf.add_argument("--prefix", default="traffic")
    trf.add_argument("--no-redact", action="store_true",
                     help="disable URL/User-Agent redaction (NOT recommended; "
                          "logs sensitive cleartext verbatim)")
    trf.add_argument("--anonymize-ips", action="store_true",
                     help="mask IPs to /24 in events/flows (for shared reports)")
    trf.add_argument("--airmon", action="store_true")
    trf.add_argument("--no-monitor-setup", action="store_true")

    ids = sub.add_parser("ids", help="passive wireless IDS: detect deauth "
                       "floods, handshake-harvest attempts, beacon mutation, "
                       "and unapproved BSSIDs. Detection only - it never "
                       "attacks back, because that is not what defence needs.")
    ids.add_argument("-i", "--interface", default="")
    ids.add_argument("-d", "--duration", type=float, default=60.0)
    ids.add_argument("--pcap", default="", help="analyse an existing capture instead")
    ids.add_argument("--window", type=float, default=10.0, help="anomaly window (s)")
    ids.add_argument("--flood", type=int, default=5, help="mgmt frames in window that count as flood")
    ids.add_argument("--sensitivity", default="medium",
                     choices=["low", "medium", "high"],
                     help="low = fewer, surer alerts (2x threshold); "
                          "high = more, noisier alerts")
    ids.add_argument("--db", default="", help="warden baseline sqlite (learn/unknown BSSIDs)")
    ids.add_argument("--learn", action="store_true", help="save current APs as known-good baseline")
    ids.add_argument("--airmon", action="store_true")
    ids.add_argument("--no-monitor-setup", action="store_true")
    ids.add_argument("-o", "--output", default="", help="export alerts CSV here")
    ids.add_argument("--follow", action="store_true", help="print alerts live as they fire")

    aud = sub.add_parser("audit", help="defensive hardening audit of your own "
                         "network: every weakness -> the attack it exposes -> "
                         "the setting that defeats it")
    aud.add_argument("--ssid", default="", help="audit only networks matching this")
    aud.add_argument("--pcap", default="", help="audit from a capture file")
    aud.add_argument("-i", "--interface", default="")
    aud.add_argument("-o", "--output", default="", help="write markdown report here")

    fr = sub.add_parser("frames", help="802.11 frame anatomy: annotated, "
                        "educational dissection of every frame in a capture")
    fr.add_argument("pcap")
    fr.add_argument("--limit", type=int, default=20)
    fr.add_argument("--filter", default="",
                    help="beacon|probe-req|assoc-req|deauth|disassoc|data|handshake")
    fr.add_argument("--handshakes", action="store_true",
                    help="just summarise EAPOL/deauth activity (counts only)")

    inj = sub.add_parser("inject", help="AUTHORIZED transmission for defensive "
                         "self-test only: IDS canaries, active probe scan, a "
                         "bounded own-AP PMF/deauth-resistance test, and an "
                         "explicit unicast deauth/disassoc TEST. Dry run by "
                         "default; needs root + --authorized (+--yes for kick "
                         "modes). Broadcast/wildcard/third-party targets refused.")
    inj.add_argument("-i", "--interface", default="", help="wireless interface")
    inj.add_argument("--mode", default="probe",
                     choices=["probe", "canary", "pmf-test", "deauth",
                              "evil-twin", "ids-selftest"],
                     help="probe = active survey; canary = IDS/sensor coverage "
                          "marker; pmf-test = small burst to verify YOUR AP "
                          "enforces PMF; deauth = explicit bounded unicast "
                          "deauth/disassoc TEST of YOUR own client (pen-test); "
                          "evil-twin = bounded BEACON-ONLY drill that "
                          "advertises your own SSID from a spoofed BSSID to "
                          "test rogue-AP detection (no client/data path); "
                          "ids-selftest = offline, zero-RF IDS signature check")
    inj.add_argument("-c", "--channels", default="",
                     help="comma list, e.g. 1,6,11 (kick/twin modes: channel)")
    inj.add_argument("--ssid", default="",
                     help="probe mode: directed probe for this SSID (default: "
                          "wildcard broadcast probe, like normal client scans); "
                          "evil-twin: the network name YOU own that the beacon "
                          "drill advertises (required for that mode)")
    inj.add_argument("--security", default="open", choices=["open", "wpa2"],
                     help="evil-twin drill: security the cloned beacon "
                          "advertises (open = the classic open-clone; wpa2 = "
                          "WPA2-PSK/CCMP advertisement)")
    inj.add_argument("--bssid", default="",
                     help="kick modes: YOUR AP's BSSID (unicast, required); "
                          "evil-twin: override the advertised clone BSSID "
                          "(default: a random locally-administered address, "
                          "which is the anomaly your warden should catch)")
    inj.add_argument("--client", default="",
                     help="kick modes: YOUR own test device's MAC (unicast, "
                          "required; broadcast/multicast targets are refused)")
    inj.add_argument("--frame-type", default="deauth", dest="frame_type",
                     choices=["deauth", "disassoc", "both"],
                     help="deauth mode: which disconnect frame to send "
                          "(both alternates deauth+disassoc)")
    inj.add_argument("--direction", default="ap-to-sta",
                     choices=["ap-to-sta", "sta-to-ap"],
                     help="deauth mode: spoofed direction (ap-to-sta is the "
                          "classic client kick; sta-to-ap drops it AP-side)")
    inj.add_argument("--count", type=int, default=2,
                     help="frames per channel (probe/canary) or kick burst size "
                          "(pmf-test/deauth); hard-capped per mode for safety")
    inj.add_argument("--dwell", type=float, default=0.0,
                     help="seconds to listen on each channel after a burst "
                          "(0 = sensible default per mode)")
    inj.add_argument("--baseline-s", type=float, default=5.0,
                     help="pmf-test: observe client activity before the burst")
    inj.add_argument("--verify-s", type=float, default=8.0,
                     help="pmf-test: observe for re-association after the burst")
    inj.add_argument("--duration", type=float, default=20.0,
                     help="evil-twin drill: how many seconds to beacon "
                          "(hard-capped; self-terminates)")
    inj.add_argument("--token", default="", help="canary: marker SSID (auto if "
                                                 "blank; grep this in sensor logs)")
    inj.add_argument("--src-mac", default="",
                     help="source MAC (default: random locally-administered)")
    inj.add_argument("--transmit", action="store_true",
                     help="actually emit frames over the air (WITHOUT this flag "
                          "the command is a dry run that only builds/displays)")
    inj.add_argument("--authorized", action="store_true",
                     help="assert you own the target network / hold written "
                          "authorization to test it (required with --transmit)")
    inj.add_argument("--yes", action="store_true",
                     help="required for the impact modes (pmf-test, deauth, "
                          "evil-twin): acknowledge the test may disconnect the "
                          "named client or beacons an impersonated SSID you "
                          "own; the action is bounded and audited")
    inj.add_argument("--airmon", action="store_true")
    inj.add_argument("--no-monitor-setup", action="store_true")
    inj.add_argument("--audit-log", default="",
                     help="CSV audit trail of every frame (default: "
                          "<output>/injection_audit.csv); always written 0600")
    inj.add_argument("--write-pcap", default="",
                     help="also record the verification window to a pcap")
    inj.add_argument("-o", "--output", default="output", metavar="DIR",
                     help="directory for the audit log / pcap (default: ./output)")

    dbp = sub.add_parser("db", help="history-database maintenance: retention, "
                         "anonymization, deletion (privacy controls)")
    dbp.add_argument("--db", default="presence.sqlite", metavar="SQLITE")
    dbp.add_argument("--report", action="store_true",
                     help="show permissions/size/retention/tables report")
    dbp.add_argument("--prune-days", type=float, default=0.0,
                     help="delete rows older than N days, then vacuum")
    dbp.add_argument("--delete-mac", default="",
                     help="erase every row for one device MAC (or pseudonym)")
    dbp.add_argument("--anonymize-db", action="store_true",
                     help="IRREVERSIBLY pseudonymise stored MACs + drop IPs/ "
                          "hostnames (no undo)")
    dbp.add_argument("--purge", action="store_true",
                     help="delete ALL history rows (keeps warden baseline)")
    dbp.add_argument("--vacuum", action="store_true",
                     help="reclaim space after deletions")
    dbp.add_argument("--yes", action="store_true",
                     help="confirm destructive actions (required)")

    lab = sub.add_parser(
        "lab", help="LOCAL captive-portal phishing AWARENESS lab: serves a "
                    "fake Wi-Fi login page + instructor dashboard on your own "
                    "machine, records training submissions against synthetic "
                    "accounts, and provides debrief pages (indicators, "
                    "comparison, attacker's view). Never contacts a real "
                    "authentication service.")
    lab.add_argument("--bind", default="127.0.0.1",
                     help="listen address (default: localhost only; use "
                          "0.0.0.0 to present to a classroom LAN you control)")
    lab.add_argument("--port", type=int, default=8808)
    lab.add_argument("--db", default="", metavar="SQLITE",
                     help="training database (default: lab.sqlite; the "
                          "self-test runs in-memory unless you give one here)")
    lab.add_argument("--accounts", type=int, default=10,
                     help="size of the synthetic trainee roster (1-200)")
    lab.add_argument("--ssid", default="CampusNet-Guest",
                     help="network name the fake portal pretends to be")
    lab.add_argument("--instructor-token", default="",
                     help="fix the dashboard URL token (default: random per "
                          "run, printed to the instructor console)")
    lab.add_argument("--duration", type=float, default=0.0,
                     help="auto-stop the server after N seconds "
                          "(0 = until Ctrl-C)")
    lab.add_argument("--reset", action="store_true",
                     help="wipe all submissions and events (roster kept; "
                          "requires --yes) and exit")
    lab.add_argument("--rotate-roster", action="store_true",
                     help="with --reset: also regenerate fresh synthetic "
                          "credentials for the next class")
    lab.add_argument("--yes", action="store_true",
                     help="confirm destructive --reset (required)")
    lab.add_argument("--self-test", action="store_true",
                     help="run the whole lab loop offline (portal, submission, "
                          "detection, dashboard API, reset) and exit")
    lab.add_argument("-o", "--output", default="", metavar="DIR",
                     help="on exit (or with --reset): export roster, attempts "
                          "and events as CSV + JSON here")

    wpa = sub.add_parser(
        "wpa-lab", help="WPA/WPA2/WPA3 decryption laboratory: inventory real "
                        "lab captures, verify candidate keys against the 4-way "
                        "handshake MIC, perform authorised decryption with "
                        "laboratory key material, and study before/after "
                        "visibility. Stdlib crypto, verified against published "
                        "vectors; offline only; no RF.")
    wpa.add_argument("action",
                     choices=["inventory", "try", "decrypt", "make-fixture",
                              "exercises", "web"],
                     help="inventory = frame/handshake map (no key needed); "
                          "try = verify ONE candidate key; decrypt = full "
                          "authorised decryption with the lab keyring; "
                          "make-fixture = build a real lab capture "
                          "(instructor); exercises = guided worksheet; "
                          "web = student portal + instructor dashboard")
    wpa.add_argument("pcap", nargs="?", default="", metavar="CAPTURE",
                     help="capture file to analyse (or output path for "
                          "make-fixture)")
    wpa.add_argument("--ssid", default="",
                     help="network name (needed with --password; default for "
                          "make-fixture: LabNet-PSK)")
    wpa.add_argument("--password", default="",
                     help="candidate/lab passphrase (PSK derivation)")
    wpa.add_argument("--psk", default="", help="raw 64-hex PSK (= PMK)")
    wpa.add_argument("--pmk", default="",
                     help="raw 64-hex PMK (for WPA3-SAE captures the "
                          "instructor supplies this)")
    wpa.add_argument("--key-file", default="", metavar="FILE",
                     help="instructor keyring: one passphrase or 64-hex PMK "
                          "per line (or 'ssid=NAME,pass=phrase')")
    wpa.add_argument("--cipher", default="ccmp",
                     choices=["ccmp", "ccmp-256", "gcmp", "tkip"],
                     help="make-fixture: pairwise cipher the lab AP runs")
    wpa.add_argument("--channel", type=int, default=6)
    wpa.add_argument("--no-handshake", action="store_true",
                     help="make-fixture: omit the 4-way handshake (exercise "
                          "4: even the right key then fails)")
    wpa.add_argument("--no-plaintext", action="store_true",
                     help="make-fixture: omit the open-network contrast tail")
    wpa.add_argument("--exercise", type=int, default=0,
                     help="exercises: print only exercise N")
    wpa.add_argument("-o", "--output", default="", metavar="DIR",
                     help="decrypt: export frames CSV, report.md, JSON and "
                          "decrypted.pcap here")
    wpa.add_argument("--limit", type=int, default=30,
                     help="try/decrypt: max decrypted frames to print")
    wpa.add_argument("--reset", action="store_true",
                     help="web: wipe the training DB at startup")
    wpa.add_argument("--bind", default="127.0.0.1",
                     help="web: listen address (default localhost; 0.0.0.0 "
                          "for a classroom LAN you control)")
    wpa.add_argument("--port", type=int, default=8811)
    wpa.add_argument("--db", default="", metavar="SQLITE",
                     help="web: attempts/event log DB (default "
                          "wpa_lab.sqlite; use ':memory:' to keep nothing)")
    wpa.add_argument("--instructor-token", default="",
                     help="web: fix the dashboard URL token (default random)")
    wpa.add_argument("--duration", type=float, default=0.0,
                     help="web: auto-stop after N seconds (0 = until Ctrl-C)")

    macl = sub.add_parser(
        "mac-lab", help="MAC randomization & deanonymization laboratory: "
                        "instructor makes a synthetic multi-sensor probe "
                        "dataset (radiotap pcaps); students correlate "
                        "rotated MACs using metadata evidence, face the "
                        "twin false-positive trap, and get scored. "
                        "Offline only; synthetic devices only.")
    macl.add_argument("action",
                      choices=["make-dataset", "inventory", "correlate",
                               "explain", "score", "exercises", "web"],
                      help="make-dataset = instructor builds the lab data "
                           "set; inventory = MAC map of the dataset; "
                           "correlate = pairwise evidence matrix + engine "
                           "clusters; explain = full reasoning for ONE "
                           "pair; score = grade a clustering answer against "
                           "instructor ground truth; exercises = worksheet; "
                           "web = student portal + instructor dashboard")
    macl.add_argument("dataset", nargs="?", default="", metavar="DIR",
                      help="dataset directory (sensor-*.pcap + manifest)")
    macl.add_argument("macs", nargs="*", metavar="MAC",
                      help="explain: the two MACs to reason about")
    macl.add_argument("--seed", type=int, default=8,
                      help="make-dataset: RNG seed (change per class)")
    macl.add_argument("--fresh", action="store_true",
                      help="make-dataset: overwrite an existing DIR")
    macl.add_argument("--min", dest="min_verdict", default="likely",
                      choices=["possible", "likely", "high"],
                      help="correlate: cluster threshold (default likely)")
    macl.add_argument("--submit", default="", metavar="JSON",
                      help="score: file with the answer clustering "
                           "[[mac,mac,...], ...] — or '-' for stdin")
    macl.add_argument("--limit", type=int, default=25,
                      help="correlate: max evidence rows to print")
    macl.add_argument("--exercise", type=int, default=0,
                      help="exercises: (all; individual selection planned — "
                           "print the whole sheet)")
    macl.add_argument("--bind", default="127.0.0.1",
                      help="web: listen address (default localhost; 0.0.0.0 "
                           "for a classroom LAN you control)")
    macl.add_argument("--port", type=int, default=8821)
    macl.add_argument("--db", default="", metavar="SQLITE",
                      help="web: attempts/event log DB (default "
                           "mac_lab.sqlite; use ':memory:' to keep nothing)")
    macl.add_argument("--instructor-token", default="",
                      help="web: fix the dashboard URL token (default random)")
    macl.add_argument("--duration", type=float, default=0.0,
                      help="web: auto-stop after N seconds (0 = until Ctrl-C)")

    trl = sub.add_parser(
        "track-lab", help="Long-term device tracking & privacy laboratory: "
                          "2 weeks of synthetic multi-sensor sightings of "
                          "persistent, decoy, and MAC-rotating lab devices; "
                          "students build histories, recover routines and "
                          "movement edges, contrast short vs long retention, "
                          "and are scored on attribution traps. Instructor "
                          "regenerates fresh datasets per class. Offline "
                          "only; synthetic devices only.")
    trl.add_argument("action",
                     choices=["make-dataset", "inventory", "history",
                              "patterns", "compare", "score", "exercises",
                              "web"],
                     help="make-dataset = instructor builds the tracking "
                          "dataset; inventory = MAC presence table; history "
                          "= appearance timeline (optionally one MAC); "
                          "patterns = weekday/hour heatmaps + movement "
                          "edges; compare = short-window vs full history "
                          "side by side; score = grade quiz answers; "
                          "exercises = worksheet; web = student portal + "
                          "instructor dashboard")
    trl.add_argument("dataset", nargs="?", default="", metavar="DIR")
    trl.add_argument("--seed", type=int, default=9,
                     help="make-dataset: RNG seed (change per class)")
    trl.add_argument("--days", type=int, default=14,
                     help="make-dataset: day span of the synthetic history")
    trl.add_argument("--fresh", action="store_true",
                     help="make-dataset: overwrite an existing DIR")
    trl.add_argument("--mac", default="",
                     help="history/patterns: focus on one MAC")
    trl.add_argument("--since", default="",
                     help="history/compare: only the tail window, e.g. 2d, "
                          "36h, 90m")
    trl.add_argument("--answers", default="", metavar="JSON",
                     help="score: file with quiz answers "
                          '{"q_identity": "MAC", ...} — or "-" for stdin')
    trl.add_argument("--exercise", type=int, default=0,
                     help="exercises: (print the whole sheet)")
    trl.add_argument("--bind", default="127.0.0.1")
    trl.add_argument("--port", type=int, default=8822)
    trl.add_argument("--db", default="", metavar="SQLITE",
                     help="web: attempts/event log DB (default "
                          "track_lab.sqlite; use ':memory:' to keep nothing)")
    trl.add_argument("--instructor-token", default="",
                     help="web: fix the dashboard URL token (default random)")
    trl.add_argument("--duration", type=float, default=0.0,
                     help="web: auto-stop after N seconds (0 = until Ctrl-C)")

    stl = sub.add_parser(
        "stealth-lab", help="hidden-monitoring & stealth-detection "
                             "laboratory: a synthetic 4-day telemetry "
                             "scenario with a concealed implant; "
                             "defender-console tables (procs/conns/files/" 
                             "auth/services), behaviour-change alerts, an "
                             "explainable signal engine, scored hunt quiz, "
                             "token-gated instructor dashboard. Offline "
                             "only; no real host touched.")
    stl.add_argument("action",
                     choices=["make-scenario", "telemetry", "hunt",
                              "explain", "compare", "alerts", "score",
                              "exercises", "web"],
                     help="make-scenario = instructor builds the telemetry "
                          "scenario; telemetry = defender tables; hunt = "
                          "engine league of suspects; explain = signals for "
                          "one key; compare = benign monitor vs implant; "
                          "alerts = behaviour-change alert timeline; score "
                          "= grade quiz answers; web = student portal + "
                          "instructor dashboard")
    stl.add_argument("dataset", nargs="?", default="", metavar="DIR")
    stl.add_argument("key", nargs="?", default="", metavar="KEY",
                     help="explain: entity key (e.g. IMPLANT, snmpd-corp, "
                          "sshd)")
    stl.add_argument("--kind", default="procs",
                     choices=["procs", "listeners", "files", "auth"]),
    stl.add_argument("--day", type=int, default=0,
                     help="telemetry: only day N (1-4; 0 = everything)")
    stl.add_argument("--tick", type=int, default=0,
                     help="telemetry/hunt: view state at tick N (0 = end)")
    stl.add_argument("--seed", type=int, default=10,
                     help="make-scenario: RNG seed (change per class)")
    stl.add_argument("--fresh", action="store_true",
                     help="make-scenario: overwrite an existing DIR")
    stl.add_argument("--answers", default="", metavar="JSON",
                     help="score: quiz answers file — or '-' for stdin")
    stl.add_argument("--bind", default="127.0.0.1")
    stl.add_argument("--port", type=int, default=8823)
    stl.add_argument("--db", default="", metavar="SQLITE",
                     help="web: attempts/event log DB (default "
                          "stealth_lab.sqlite; ':memory:' keeps nothing)")
    stl.add_argument("--instructor-token", default="")
    stl.add_argument("--duration", type=float, default=0.0,
                     help="web: auto-stop after N seconds")

    rpl = sub.add_parser(
        "response-lab", help="automatic (offensive) response laboratory: "
                             "seeded IDS-event stream on designated lab "
                             "test devices; rule-based response policies "
                             "with dry-run / approval / auto / manual "
                             "modes; simulated firewall enforcement, "
                             "approval queue, rollback, and a full "
                             "detect->decide->respond->result audit trail. "
                             "Offline only; never blocks anything real.")
    rpl.add_argument("action",
                     choices=["cast", "rules", "simulate", "exercises",
                              "score", "web"],
                     help="cast = designated test devices; rules = "
                          "rulebook; simulate = run the pipeline offline "
                          "and print it; exercises = worksheet; score = "
                          "grade quiz answers; web = portal + instructor "
                          "console")
    rpl.add_argument("--seed", type=int, default=11)
    rpl.add_argument("--ticks", type=int, default=96)
    rpl.add_argument("--mode", default="dry-run",
                     choices=["dry-run", "approval", "auto", "manual"],
                     help="simulate: response policy mode (web starts in "
                          "dry-run too)")
    rpl.add_argument("--enable-rule", action="append", default=[],
                     metavar="RID",
                     help="simulate: force-enable rule R6 (the aggressive "
                          "one ships disabled — that's the exercise)")
    rpl.add_argument("--clear-allowlist", action="store_true",
                     help="simulate: start with an EMPTY allowlist (the FP "
                          "trap: your own IT scanner may get blocked)")
    rpl.add_argument("--answers", default="", metavar="JSON",
                     help="score: quiz answers file — or '-' for stdin")
    rpl.add_argument("--bind", default="127.0.0.1")
    rpl.add_argument("--port", type=int, default=8824)
    rpl.add_argument("--db", default="", metavar="SQLITE",
                     help="web: attempts/event log DB (default "
                          "response_lab.sqlite; ':memory:' keeps nothing)")
    rpl.add_argument("--instructor-token", default="")
    rpl.add_argument("--duration", type=float, default=0.0,
                     help="web: auto-stop after N seconds")

    scl = sub.add_parser(
        "scan-lab", help="large-scale scanning & scope-control laboratory: "
                         "instructor-built virtual lab estate (10.77.*), "
                         "simulated concurrent scans with live progress, "
                         "rate limiting, and a sentinel that refuses and "
                         "alarms on out-of-scope targets. Isolated & "
                         "synthetic — scans open no sockets, probe no "
                         "network.")
    scl.add_argument("action",
                     choices=["make-dataset", "inventory", "scan",
                              "compare", "score", "exercises", "web"],
                     help="make-dataset = instructor builds the estate; "
                          "inventory = browse the lab assets; scan = run a "
                          "simulated scan now (rate/concurrency-controlled);"
                          " compare = targeted vs uncontrolled; score = "
                          "grade quiz answers; web = console + instructor "
                          "dashboard")
    scl.add_argument("dataset", nargs="?", default="", metavar="DIR")
    scl.add_argument("--seed", type=int, default=12)
    scl.add_argument("--size", type=int, default=220,
                     help="make-dataset: estate size")
    scl.add_argument("--fresh", action="store_true")
    scl.add_argument("--targets", default="",
                     help="scan: comma-separated IPs, or '*' for the whole "
                          "registered estate")
    scl.add_argument("--rate", type=float, default=100,
                     help="scan: probes per second (0 = unlimited)")
    scl.add_argument("--concurrency", type=int, default=8,
                     help="scan: simulated workers")
    scl.add_argument("--services", default="",
                     help="scan: comma list of service probes "
                          f"({'ssh/22,http/80,…'})")
    scl.add_argument("--answers", default="", metavar="JSON",
                     help="score: quiz answers file — or '-' for stdin")
    scl.add_argument("--bind", default="127.0.0.1")
    scl.add_argument("--port", type=int, default=8825)
    scl.add_argument("--db", default="", metavar="SQLITE",
                     help="web: attempts/event log DB (default "
                          "scan_lab.sqlite; ':memory:' keeps nothing)")
    scl.add_argument("--instructor-token", default="")
    scl.add_argument("--duration", type=float, default=0.0,
                     help="web: auto-stop after N seconds")

    crl = sub.add_parser(
        "cred-lab", help="credential & session security laboratory: a lab-"
                         "generated capture twins plaintext and TLS legs of "
                         "the same synthetic identities — dissect it, list "
                         "exactly what a watcher steals (basic-auth, form "
                         "posts, FTP, Telnet, SNMPv1 community, replayable "
                         "cookies), then prove what TLS hides. Synthetic "
                         "credentials only; nothing real ever enters.")
    crl.add_argument("action",
                     choices=["make-fixture", "dissect", "exposures",
                              "tls", "alerts", "report", "compare",
                              "exercises", "score", "web"],
                     help="make-fixture = instructor generates the capture "
                          "+ synthetic accounts; dissect = packet analysis; "
                          "exposures/tls = each leg's tables; alerts = "
                          "insecure-auth detectors; report = export bundle; "
                          "compare = side-by-side table; score/web as usual")
    crl.add_argument("pcap", nargs="?", default="", metavar="CAPTURE")
    crl.add_argument("--seed", type=int, default=13)
    crl.add_argument("--students", type=int, default=6,
                     help="make-fixture: how many synthetic accounts")
    crl.add_argument("-o", "--output", default="", metavar="DIR",
                     help="report: export bundle here")
    crl.add_argument("--answers", default="", metavar="JSON",
                     help="score: quiz answers file — or '-' for stdin")
    crl.add_argument("--bind", default="127.0.0.1")
    crl.add_argument("--port", type=int, default=8826)
    crl.add_argument("--db", default="", metavar="SQLITE",
                     help="web: attempts/event log DB (default "
                          "cred_lab.sqlite; ':memory:' keeps nothing)")
    crl.add_argument("--instructor-token", default="")
    crl.add_argument("--duration", type=float, default=0.0,
                     help="web: auto-stop after N seconds")

    prl = sub.add_parser(
        "priv-lab", help="wireless privacy & MAC-randomization laboratory: "
                         "instructor-generated synthetic observation logs "
                         "(locally-administered 02:1a:b4 OUI only), cluster "
                         "rotated MACs by probe fingerprint / routine, "
                         "measure PNO-scrub impact, FT-scope sentinel for "
                         "out-of-scope correlation, web console.")
    prl.add_argument("action",
                     choices=["make-dataset", "inventory", "correlate",
                              "compare", "exercises", "score", "web"],
                     help="make-dataset = instructor generates synthetic "
                          "devices + observations; correlate = cluster "
                          "rotated MACs (refuses restricted targets); "
                          "compare = before/after privacy-config scrub; "
                          "score/web as usual")
    prl.add_argument("data", nargs="?", default="", metavar="DIR")
    prl.add_argument("--db", default="", metavar="DIR_OR_SQLITE",
                     help="dataset dir for analysis commands / sqlite log "
                          "for web")
    prl.add_argument("--seed", type=int, default=14)
    prl.add_argument("--devices", type=int, default=10)
    prl.add_argument("--days", type=int, default=6)
    prl.add_argument("--fresh", action="store_true",
                     help="destroy an existing dataset first")
    prl.add_argument("--target", default="*",
                     help="correlate: restrict to one device id")
    prl.add_argument("--answers", default="", metavar="JSON")
    prl.add_argument("--bind", default="127.0.0.1")
    prl.add_argument("--port", type=int, default=8827)
    prl.add_argument("--instructor-token", default="")
    prl.add_argument("--duration", type=float, default=0.0)
    rfl = sub.add_parser(
        "rf-lab", help="RF interference & Wi-Fi resilience laboratory: "
                       "simulated metrics (channel util, SNR, loss, "
                       "latency, throughput) for a lab estate of APs on "
                       "ch 1/6/11, instructor start/stop/reset/intensity "
                       "controls for microwave/Bluetooth/cordless/chaos "
                       "interference, detector + incident analysis, "
                       "rechannel-resilience exercise. No real RF "
                       "transmission.")
    rfl.add_argument("action",
                     choices=["baseline", "inject", "compare",
                              "investigate", "resilience", "exercises",
                              "score", "web"],
                     help="inject = simulated interference (prints what "
                          "the detector sees); investigate = signature "
                          "analysis; resilience = channel-change exercise; "
                          "score/web as usual")
    rfl.add_argument("--seed", type=int, default=15)
    rfl.add_argument("--interferer", default="microwave",
                     choices=["microwave", "bluetooth", "cordless",
                              "chaos"])
    rfl.add_argument("--intensity", type=int, default=60,
                     help="0..100 (hard cap)")
    rfl.add_argument("--ap", default="LAB-AP-3")
    rfl.add_argument("--channel", type=int, default=1)
    rfl.add_argument("--ticks", type=int, default=30)
    rfl.add_argument("--answers", default="", metavar="JSON")
    rfl.add_argument("--bind", default="127.0.0.1")
    rfl.add_argument("--port", type=int, default=8828)
    rfl.add_argument("--db", default="", metavar="SQLITE",
                     help="web: attempts/event log DB")
    rfl.add_argument("--instructor-token", default="")
    rfl.add_argument("--duration", type=float, default=0.0)

    hsh = sub.add_parser(
        "handshake-lab", help="WPA handshake capture & password-auditing "
                              "laboratory: instructor-generated 4-way "
                              "handshakes (cryptographically real, lab SSID "
                              "only), three difficulty tiers, offline "
                              "dictionary audit with real PBKDF2 timing, "
                              "captured/audited/authenticated state "
                              "distinction, instructor regenerate/reset/"
                              "destroy. Synthetic credentials only.")
    hsh.add_argument("action",
                     choices=["make-dataset", "inventory", "analyze",
                              "audit", "compare", "authenticate",
                              "exercises", "score", "web"],
                     help="make-dataset = instructor generates "
                          "captures+lists+creds; analyze = validate the "
                          "capture; audit = offline dictionary run; "
                          "compare = three tiers side-by-side; "
                          "authenticate = prove possession with the found "
                          "credential; score/web as usual")
    hsh.add_argument("data", nargs="?", default="", metavar="DIR")
    hsh.add_argument("--db", default="", metavar="DIR_OR_SQLITE",
                     help="dataset dir for analysis / sqlite log for web")
    hsh.add_argument("--seed", type=int, default=3)
    hsh.add_argument("--tier", default="easy",
                     choices=["easy", "medium", "expert"])
    hsh.add_argument("--password", default="",
                     help="authenticate: credential under test")
    hsh.add_argument("--answers", default="", metavar="JSON")
    hsh.add_argument("--fresh", action="store_true",
                     help="make-dataset: destroy existing dataset first")
    hsh.add_argument("--bind", default="127.0.0.1")
    hsh.add_argument("--port", type=int, default=8829)
    hsh.add_argument("--instructor-token", default="")
    hsh.add_argument("--duration", type=float, default=0.0)
    hsh.add_argument("--quiet", action="store_true")

    sub.add_parser("interfaces", help="list wireless interfaces and capabilities")
    
    p_rui = sub.add_parser("research-ui", help="Start the Research Platform Workstation UI")
    p_rui.add_argument("--port", type=int, default=8830)
    p_rui.add_argument("--bind", default="0.0.0.0")
    p_rui.add_argument("--db", help="Path to sqlite db (default: research_labs.sqlite)")
    
    return p


# ------------------------------------------------------------------ helpers

def _do_survey(args) -> Engine:
    eng = Engine()
    backend = getattr(args, "backend", "auto")
    rescan = not getattr(args, "no_rescan", False)
    log.info("scanning for access points (%s)...", backend)
    aps = survey.survey_networks(args.interface, backend, rescan)
    eng.ingest(aps)
    log.info("discovered %d access points", len(eng.aps))
    return eng


def _do_monitor(args, eng: Engine, duration: float, bssid: str = "") -> Engine:
    if not sniffer.scapy_available():
        log.error("scapy is not installed - monitor mode unavailable. "
                  "Install with:  pip install scapy")
        return eng
    iface = args.interface
    if not iface:
        ifaces = survey.list_interfaces()
        if not ifaces:
            log.error("no wireless interface found; specify one with -i")
            return eng
        iface = ifaces[0]["name"]
        log.info("using interface %s", iface)
    if not is_root() and not getattr(args, "no_monitor_setup", False):
        log.error("monitor mode requires root. Re-run with sudo, or pass "
                  "--no-monitor-setup if %s is already in monitor mode.", iface)
        return eng
    channels = None
    if getattr(args, "channels", ""):
        channels = [int(c) for c in args.channels.split(",") if c.strip()]
    # Lock to the target AP's channel when we already know it.
    if bssid and not channels:
        ap = eng.aps.get(normalize(bssid))
        if ap and ap.channel:
            channels = [ap.channel]
            log.info("locking to channel %d for %s", ap.channel, bssid)

    def _run(mon_iface: str) -> None:
        sn = sniffer.MonitorSniffer(
            mon_iface, channels=channels,
            hop_interval=getattr(args, "hop_interval", 0.35),
            bands=tuple(getattr(args, "bands", ("2.4GHz", "5GHz"))),
            lock_bssid=bssid)
        sn.run(duration, pcap_out=getattr(args, "write_pcap", ""))
        eng.ingest(sn.results())
        eng.ingest_unassociated(sn.unassociated)
        eng.sniffer_stats = sn.stats()
        log.info("capture stats: %s", eng.sniffer_stats)

    if getattr(args, "no_monitor_setup", False):
        _run(iface)
    else:
        with sniffer.MonitorMode(iface, use_airmon=getattr(args, "airmon", False)) as mon:
            _run(mon)
    return eng


def _export(args, eng: Engine) -> None:
    if not args.output:
        return
    files = export_all(eng, args.output, args.prefix, tuple(args.format),
                       anonymize=getattr(args, "anonymize", False))
    msg = "\n".join(f"  -> {f}" for f in files)
    anon = " (anonymized: salted pseudonyms, no hostnames/IPs/probes)" \
        if getattr(args, "anonymize", False) else " (owner-only permissions)"
    print(f"\nExported {len(files)} file(s){anon}:\n{msg}")


def _maybe_store(args, eng: Engine, mode: str = "scan") -> None:
    db = getattr(args, "db", "")
    if not db:
        return
    try:
        st = Store(db, retention_days=getattr(args, "retain_days", 90.0),
                   privacy_mode=getattr(args, "privacy_mode", "standard"),
                   anonymize=getattr(args, "anonymize", False))
    except PermissionError as exc:
        log.error("%s", exc)
        return
    try:
        sid = st.record_engine(eng, mode=mode, sensor=getattr(args, "sensor", ""))
        print(f"persisted scan {sid} -> {db}")
    finally:
        st.close()


def _fmt_ts(ts) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)) if ts else "-"


# ----------------------------------------------------------------- commands

def cmd_scan(args) -> int:
    eng = _do_survey(args)
    print_networks(eng, args.sort, args.limit)
    print_congestion(eng)
    print_rogues(eng)
    print_summary(eng)
    _maybe_store(args, eng, "scan")
    _export(args, eng)
    return 0


def cmd_monitor(args) -> int:
    eng = _do_survey(args)
    _do_monitor(args, eng, args.duration, args.bssid)
    print_networks(eng, "clients" if not args.sort else args.sort, args.limit)
    print_devices(eng, args.limit)
    print_rogues(eng)
    print_summary(eng)
    _maybe_store(args, eng, "monitor")
    _export(args, eng)
    return 0


def cmd_full(args) -> int:
    eng = _do_survey(args)
    _do_monitor(args, eng, args.duration)
    if args.lan:
        eng.connection = lan.current_connection()
        eng.ingest_lan(lan.lan_inventory(do_ports=args.ports),
                       bssid_hint=eng.connection.get("bssid", ""))
    print_networks(eng, args.sort, args.limit)
    print_devices(eng, args.limit)
    print_congestion(eng)
    print_rogues(eng)
    print_summary(eng)
    if not args.output:
        args.output = "output"
    if "html" not in args.format:
        args.format = list(args.format) + ["html"]
    _maybe_store(args, eng, "full")
    _export(args, eng)
    return 0


def cmd_detail(args) -> int:
    eng = _do_survey(args)
    matches = eng.find(args.target)
    if not matches:
        log.error("no network matching %r (found %d networks)", args.target, len(eng.aps))
        return 1
    if len(matches) > 1:
        log.info("%d BSSIDs match %r", len(matches), args.target)
    if not args.no_monitor and is_root() and sniffer.scapy_available():
        _do_monitor(args, eng, args.duration, matches[0].bssid)
        matches = eng.find(args.target)
    elif not args.no_monitor:
        log.warning("client enumeration skipped (needs root + scapy); "
                    "showing beacon-derived detail only")
    for ap in matches:
        print_detail(ap)
    _export(args, eng)
    return 0


def cmd_devices(args) -> int:
    eng = _do_survey(args)
    if not args.no_monitor and is_root() and sniffer.scapy_available():
        _do_monitor(args, eng, args.duration)
    if args.lan:
        eng.connection = lan.current_connection()
        stations = lan.lan_inventory(args.subnet, do_ports=args.ports)
        eng.ingest_lan(stations, bssid_hint=eng.connection.get("bssid", ""))
    print_devices(eng, args.limit)
    print_summary(eng)
    _maybe_store(args, eng, "devices")
    _export(args, eng)
    return 0


def cmd_watch(args) -> int:
    eng = Engine()
    try:
        while True:
            fresh = _do_survey(args)
            eng.ingest(list(fresh.aps.values()))
            if args.monitor and is_root() and sniffer.scapy_available():
                _do_monitor(args, eng, max(3.0, args.interval - 1))
            os.system("cls" if os_name() == "windows" else "clear")
            if not args.no_banner:
                print_banner()
            print_networks(eng, args.sort, args.limit)
            print_devices(eng, args.limit)
            print_summary(eng)
            print(f"\nrefreshing every {args.interval}s - Ctrl-C to stop and export")
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nstopped.")
    _export(args, eng)
    return 0


def cmd_offline(args) -> int:
    if not sniffer.scapy_available():
        log.error("scapy required for pcap analysis:  pip install scapy")
        return 2
    if not os.path.exists(args.pcap):
        log.error("no such file: %s", args.pcap)
        return 2
    eng = Engine()
    sn = sniffer.MonitorSniffer(iface="offline")
    sn.read_pcap(args.pcap)
    eng.ingest(sn.results())
    eng.ingest_unassociated(sn.unassociated)
    eng.sniffer_stats = sn.stats()
    print_networks(eng, args.sort, args.limit)
    print_devices(eng, args.limit)
    print_congestion(eng)
    print_rogues(eng)
    print_summary(eng)
    _maybe_store(args, eng, "offline")
    _export(args, eng)
    return 0


# ------------------------------------------------------- own-network suite

def cmd_own(args) -> int:
    """Client census of the network you own/are connected to."""
    conn = lan.current_connection()
    my_bssid = conn.get("bssid", "") or ""
    eng = Engine()
    print_rows("Your connection", [
        ("SSID", "ssid"), ("BSSID", "bssid"), ("Channel", "channel"),
        ("Rate", "rate"), ("Signal", "signal"), ("Security", "security"),
        ("Gateway", "gateway"), ("Subnet", "subnet")],
        [dict(conn)])

    ap_clients = lan.own_ap_clients(args.interface)
    if ap_clients:
        log.info("own AP association table supplied %d clients", len(ap_clients))

    eng.ingest(survey.survey_networks(args.interface, "auto", False))
    if not my_bssid:
        for b, a in eng.aps.items():
            if a.client_count:
                my_bssid = b
                break

    if not args.no_monitor and my_bssid and is_root() and sniffer.scapy_available():
        _do_monitor(args, eng, args.duration, my_bssid)
    elif not args.no_monitor:
        log.info("over-the-air census skipped (needs root+scapy) - using "
                 "association table + LAN sweep")

    if not args.no_lan:
        eng.ingest_lan(lan.lan_inventory(do_ports=args.ports),
                       bssid_hint=my_bssid)
    if ap_clients:
        # The AP's own kernel table is ground truth: router-CONFIRMED.
        eng.ingest_lan(ap_clients, bssid_hint=my_bssid, authoritative=True)
        print(f"router association table confirmed "
              f"{len(ap_clients)} client(s) — these counts are fact, "
              f"everything else RF-observed is an estimate")

    ap = eng.aps.get(normalize(my_bssid)) if my_bssid else None
    if ap:
        print_detail(ap)
    else:
        log.info("no AP record for your connection - showing devices instead")
        print_devices(eng)
    print_summary(eng)
    _maybe_store(args, eng, "own")
    _export(args, eng)
    return 0


def cmd_record(args) -> int:
    """Continuous presence recorder, scoped to your own network(s) only."""
    try:
        st0 = Store(args.db, retention_days=args.retain_days,
                    privacy_mode=args.privacy_mode,
                    anonymize=args.anonymize)
        st0.close()
    except PermissionError as exc:
        log.error("%s", exc)
        return 2
    if args.pcap:
        if not sniffer.scapy_available():
            log.error("scapy required for pcap import")
            return 2
        eng = Engine()
        sn = sniffer.MonitorSniffer(iface="offline")
        sn.read_pcap(args.pcap)
        eng.ingest(sn.results())
        st = Store(args.db, retention_days=args.retain_days,
                   privacy_mode=args.privacy_mode,
                   anonymize=args.anonymize)
        try:
            sid = st.record_engine(eng, mode="pcap-import", sensor=args.sensor)
            print(f"imported {args.pcap} into {args.db} as scan {sid}")
        finally:
            st.close()
        return 0

    wanted = {normalize(b) for b in args.bssid.split(",") if b.strip()}
    if not wanted:
        conn = lan.current_connection()
        if conn.get("bssid"):
            wanted = {normalize(conn["bssid"])}
            print(f"recording your current connection: SSID={conn.get('ssid', '?')} "
                  f"BSSID={conn['bssid']}")
    if not wanted:
        log.error("record needs an explicit own-network target: pass --bssid "
                  "AA:BB:... or be connected to your Wi-Fi. Indefinitely "
                  "logging every nearby device is not a feature of this tool; "
                  "use `scan`/`monitor` for ephemeral surveys.")
        return 2

    st = Store(args.db, retention_days=args.retain_days,
               privacy_mode=args.privacy_mode,
               anonymize=args.anonymize)
    if args.retain_days:
        print(f"retention: rows older than {args.retain_days:g} days are "
              f"pruned automatically")
    else:
        print("retention DISABLED (rows kept forever) — not recommended; "
              "see `db --prune-days`")
    if st.anonymize:
        print("privacy: storing salted MAC pseudonyms, no hostnames/IPs")
    t_end = time.time() + args.duration if args.duration else 0.0
    n = 0
    try:
        while True:
            t0 = time.time()
            eng = Engine()
            try:
                eng.ingest(survey.survey_networks(args.interface, args.backend,
                                                   rescan=(n % 10 == 0)))
            except Exception as exc:
                log.warning("survey pass failed: %s", exc)
            eng.aps = {b: a for b, a in eng.aps.items() if b in wanted}
            if args.lan:
                eng.ingest_lan(lan.lan_inventory())
            apc = lan.own_ap_clients(args.interface)
            if apc:
                eng.ingest_lan(apc, bssid_hint=next(iter(eng.aps), ""))
            sid = st.record_engine(eng, mode="record", sensor=args.sensor)
            n += 1
            clients = sum(a.client_count for a in eng.aps.values())
            print(f"[{_fmt_ts(time.time())}] {sid}: {len(eng.aps)} BSS, "
                  f"{clients} clients -> {args.db}")
            if t_end and time.time() + args.interval > t_end:
                break
            time.sleep(max(1.0, args.interval - (time.time() - t0)))
    except KeyboardInterrupt:
        print("\nstopped.")
    finally:
        s = st.stats()
        print(f"history: {s['devices']['rows']} device rows, "
              f"{s['observations']['rows']} observations in {args.db}")
        st.close()
    return 0


def cmd_presence(args) -> int:
    if not os.path.exists(args.db):
        log.error("no history database at %s - start with:  wifiscanner record",
                  args.db)
        return 2
    st = Store(args.db)
    try:
        if args.known:
            rows = st.known_devices()[:args.limit]
            for r in rows:
                r["first"] = _fmt_ts(r["first"])
                r["last"] = _fmt_ts(r["last"])
            print_rows(f"Device roster ({len(rows)} seen so far)",
                       [("MAC", "mac"), ("Seen", "n"), ("First", "first"),
                        ("Last", "last"), ("APs", "bssids"),
                        ("SSIDs", "ssids")], rows)
            return 0
        rows = st.sessions(mac=args.mac, ssid=args.ssid,
                           since=parse_when(args.since),
                           until=parse_when(args.until, end=True), gap=args.gap)
        for r in rows:
            r["first_h"] = _fmt_ts(r["first_seen"])
            r["last_h"] = _fmt_ts(r["last_seen"])
            r["dur_h"] = (f"{int(r['duration_s'] // 60)}m"
                          f"{int(r['duration_s'] % 60):02d}s")
        rows = rows[:args.limit]
        print_rows(f"Presence sessions ({len(rows)} latest, gap>{args.gap:.0f}s "
                   f"splits sessions)",
                   [("MAC", "mac"), ("SSID", "ssid"), ("BSSID", "bssid"),
                    ("Since", "first_h"), ("Until", "last_h"),
                    ("Duration", "dur_h"), ("Seen", "sightings"),
                    ("AvgRSSI", "avg_rssi")], rows)
        live = [r for r in rows if r["last_seen"] > time.time() - max(args.gap * 2, 60)]
        print(f"\n{len(live)} devices present NOW (seen within "
              f"{max(args.gap * 2, 60):.0f}s)")
        if args.output:
            import csv as _csv
            from .privacy import secure_file
            os.makedirs(args.output, exist_ok=True)
            path = os.path.join(args.output, "presence_sessions.csv")
            with open(path, "w", newline="", encoding="utf-8-sig") as fh:
                w = _csv.DictWriter(fh, fieldnames=[
                    "mac", "bssid", "ssid", "first_seen", "last_seen",
                    "duration_s", "sightings", "avg_rssi", "min_rssi", "max_rssi"],
                    extrasaction="ignore")
                w.writeheader()
                w.writerows(rows)
            secure_file(path)
            print(f"exported -> {path}")
        return 0
    finally:
        st.close()


def _tracker(args):
    sensors = load_sensors(args.sensors) if args.sensors else []
    zones = load_zones(args.zones) if getattr(args, "zones", "") else []
    if not sensors:
        log.error("locate/trail need a sensor grid: --sensors sensors.csv "
                  "(rows: name,x,y[,floor,rssi_offset,tx_power] in metres)")
        return None, None, None
    return (Tracker(sensors, zones, window_s=getattr(args, "window", 3.0),
                    path_loss_exponent=getattr(args, "n_exp", 2.7)),
            sensors, zones)


def cmd_locate(args) -> int:
    tracker, sensors, zones = _tracker(args)
    if not tracker:
        return 2
    if args.live:
        eng = _do_survey(args)
        _do_monitor(args, eng, args.duration)
        st0 = Store(args.db)
        st0.record_engine(eng, mode="locate-live",
                          sensor=getattr(args, "sensor", "") or sensors[0].name)
        st0.close()
    st = Store(args.db)
    try:
        obs = st.get_observations(args.mac, parse_when(args.since),
                                   parse_when(args.until, end=True))
        if not obs:
            log.error("no sensor observations in %s yet - run `record` on each "
                      "sensor, tagging it with --sensor NAME matching sensors.csv",
                      args.db)
            return 2
        fixes = tracker.fixes(obs)
        if args.recompute and fixes:
            st.record_fixes([(f.ts, f.mac, f.x, f.y, f.uncertainty_m,
                              f.method, f.sensors) for f in fixes])
        rows = [dict(ts=_fmt_ts(f.ts), mac=f.mac, x=f.x, y=f.y,
                     unc=f.uncertainty_m, zone=f.zone, method=f.method,
                     conf=f.confidence, zone_conf=f.zone_confidence,
                     sensors=f.sensors, answer=f.display)
                for f in fixes[-80:]]
        print_rows(f"Position fixes ({len(fixes)} computed, showing latest {len(rows)}) — "
                   f"ZONE is the primary answer; coordinates are shown only "
                   f"when confidence is medium/high",
                   [("Time", "ts"), ("MAC", "mac"), ("x", "x"), ("y", "y"),
                    ("Err±m", "unc"), ("Zone", "zone"), ("ZoneConf", "zone_conf"),
                    ("Method", "method"), ("Conf", "conf"),
                    ("Sources", "sensors")], rows)
        for f in fixes[-5:]:
            print(f"  -> {f.mac} @ {_fmt_ts(f.ts)[11:]}: {f.display}")
        if len(sensors) >= 2 and fixes:
            print()
            print(ascii_map(fixes[-400:], sensors, zones))
        return 0
    finally:
        st.close()


def cmd_trail(args) -> int:
    st = Store(args.db)
    try:
        since, until = parse_when(args.since), parse_when(args.until, end=True)
        tracker = sensors = zones = None
        if args.sensors:
            tracker, sensors, zones = _tracker(args)
            if not tracker:
                return 2
            obs = st.get_observations(args.mac, since, until)
            fixes = tracker.fixes(obs)
            if fixes:
                st.record_fixes([(f.ts, f.mac, f.x, f.y, f.uncertainty_m,
                                  f.method, f.sensors) for f in fixes])
        else:
            hist = st.device_history(args.mac, 10000)[::-1]
            fixes = [type("F", (), dict(ts=r["ts"], mac=args.mac, x=None, y=None,
                                       uncertainty_m=None, method="presence-only",
                                       sensors=r.get("sensor", ""), zone="",
                                       rssi=r.get("rssi"), ssid=r.get("ssid")))()
                     for r in hist]
        if not fixes:
            log.error("no movement data for %s in %s", args.mac, args.db)
            return 2
        rows = []
        for f in fixes:
            d = dict(ts=_fmt_ts(f.ts), x=f.x, y=f.y, unc=f.uncertainty_m,
                     zone=getattr(f, "zone", ""), method=f.method,
                     conf=getattr(f, "confidence", ""),
                     answer=getattr(f, "display", ""))
            rows.append(d)
        print_rows(f"Movement trail for {args.mac} ({len(fixes)} fixes) — "
                   f"zone-level answers; low-confidence coordinates withheld",
                   [("Time", "ts"), ("x", "x"), ("y", "y"), ("Err±m", "unc"),
                    ("Zone", "zone"), ("Method", "method"), ("Conf", "conf")],
                   rows[-100:])
        if tracker:
            dwell = tracker.zone_dwell(fixes)
            if dwell:
                print_rows("Zone dwell", [("Zone", "zone"), ("Seconds", "secs")],
                           [dict(zone=z, secs=s) for z, s in
                            sorted(dwell.items(), key=lambda kv: -kv[1])])
        if args.map and sensors and any(f.x is not None for f in fixes):
            print()
            print(ascii_map(fixes, sensors, zones))
        if args.output:
            os.makedirs(args.output, exist_ok=True)
            path = os.path.join(args.output,
                                f"trail-{args.mac.replace(':', '')}.csv")
            import csv as _csv
            from .privacy import secure_file
            with open(path, "w", newline="", encoding="utf-8-sig") as fh:
                w = _csv.DictWriter(fh, fieldnames=[
                    "ts", "time", "mac", "x", "y", "unc_m", "error_radius_m",
                    "zone", "zone_confidence", "method", "confidence",
                    "sensor_count", "display"])
                w.writeheader()
                for f in fixes:
                    w.writerow({"ts": round(f.ts, 1), "time": _fmt_ts(f.ts),
                                "mac": f.mac, "x": f.x, "y": f.y,
                                "unc_m": f.uncertainty_m,
                                "error_radius_m": getattr(
                                    f, "error_radius_m", f.uncertainty_m),
                                "zone": getattr(f, "zone", ""),
                                "zone_confidence": getattr(
                                    f, "zone_confidence", ""),
                                "method": f.method,
                                "confidence": getattr(f, "confidence", ""),
                                "sensor_count": getattr(f, "sensor_count", ""),
                                "display": getattr(f, "display", "")})
            secure_file(path)
            print(f"exported -> {path}")
        return 0
    finally:
        st.close()


def cmd_capture(args) -> int:
    """Raw frame capture with rotation / ring buffer. Passive only."""
    if not args.ack_sensitive:
        log.warning("raw captures contain sensitive third-party data "
                    "(payloads, identifiers) — collect only where authorized; "
                    "add --strip-payloads for a privacy-preserving header-only "
                    "capture, or --ack-sensitive to silence this warning")
    if not sniffer.scapy_available():
        log.error("scapy required:  pip install scapy")
        return 2
    iface = args.interface
    if not iface:
        ifaces = survey.list_interfaces()
        if not ifaces:
            log.error("no wireless interface found; specify -i")
            return 2
        iface = ifaces[0]["name"]
    if not args.no_monitor_setup and not is_root():
        log.error("monitor capture requires root (sudo)")
        return 13
    channels = [int(c) for c in args.channels.split(",") if c.strip()] \
        if args.channels else None
    sn = sniffer.MonitorSniffer(iface, channels=channels,
                                hop_interval=args.hop_interval,
                                bands=tuple(args.bands), lock_bssid=args.bssid)
    snaplen = 128 if args.strip_payloads else 0
    if args.strip_payloads:
        print("privacy-preserving capture: 128-byte snaplen keeps 802.11 "
              "headers (counting/IDS) and discards payloads")
    print(f"capture files are written owner-only (0600) to {args.pcap or '.'}; "
          f"they remain sensitive — store encrypted, delete when done")

    def _go(mon):
        sn.iface = mon
        sn.run(args.duration, pcap_out=args.pcap,
               ring_segments=args.ring_segments, rotate_mb=args.rotate_mb,
               snaplen=snaplen, secure_storage=True)

    try:
        if args.no_monitor_setup:
            _go(iface)
        else:
            with sniffer.MonitorMode(iface, use_airmon=args.airmon) as mon:
                _go(mon)
    except KeyboardInterrupt:
        sn.stop()
        print("\nstopped.")
    stt = sn.stats()
    print_rows("Capture stats", [(k, k) for k in stt], [stt])
    if args.max_age_days:
        import glob as _glob
        base, _ext = os.path.splitext(args.pcap)
        cutoff = time.time() - args.max_age_days * 86400
        for f in _glob.glob(base + "*.pcap*"):
            try:
                if os.path.getmtime(f) < cutoff:
                    os.remove(f)
                    print(f"  retention: deleted expired segment {f}")
            except OSError as exc:
                log.warning("retention delete failed for %s: %s", f, exc)
    if args.analyze:
        eng = Engine()
        eng.ingest(sn.results())
        eng.ingest_unassociated(sn.unassociated)
        print_networks(eng, "clients")
        print_devices(eng)
    return 0


def cmd_traffic(args) -> int:
    """Inspect UNENCRYPTED traffic. This tool never decrypts protected frames."""
    if not sniffer.scapy_available():
        log.error("scapy required:  pip install scapy")
        return 2
    from . import traffic as tf
    redact = not args.no_redact
    if args.no_redact:
        log.warning("--no-redact: URL query strings, full User-Agents and "
                    "hostnames will be logged VERBATIM. Only use on your own "
                    "network with consent.")
    else:
        print("redaction ON (default): URL queries stripped, User-Agents "
              "reduced to product tokens, credential values never logged")
    if args.live:
        if not is_root():
            log.error("live dissection needs root + a monitor interface")
            return 13

        def show(ev):
            print(f"{_fmt_ts(ev.ts)[11:]} [{ev.proto}] {ev.src} -> {ev.dst}  "
                  f"{ev.summary}" + (f"  !!{ev.alert}" if ev.alert else ""))
        if args.no_monitor_setup:
            d = tf.analyze_live(args.interface, args.duration, on_event=show,
                                redact=redact,
                                anonymize_ips=args.anonymize_ips)
        else:
            with sniffer.MonitorMode(args.interface,
                                     use_airmon=args.airmon) as mon:
                d = tf.analyze_live(mon, args.duration, on_event=show,
                                    redact=redact,
                                    anonymize_ips=args.anonymize_ips)
    else:
        if not args.pcap or not os.path.exists(args.pcap):
            log.error("usage: wifiscanner traffic <file.pcap>  (or --live -i wlan0mon)")
            return 2
        print("dissecting cleartext frames only; protected frames are skipped "
              "and counted...")
        d = tf.analyze_pcap(args.pcap, args.max_frames, redact=redact,
                            anonymize_ips=args.anonymize_ips)
    tf.print_dissector(d, args.limit)
    if d.protected_skipped:
        print(f"note: {d.protected_skipped} protected frames skipped - by "
              f"design this tool never attempts decryption.")
    if args.output:
        for f in tf.export(args.output, args.prefix, d):
            print(f"  -> {f}")
    return 0


# ------------------------------------------------- defense & education

def cmd_ids(args) -> int:
    from wifiscanner.defense import Watchdog
    from wifiscanner.store import Store
    from wifiscanner.research.integrations import IDSResearchAdapter
    from wifiscanner.research import DatabaseManager, EventBus, ResourceManager, ExperimentManager
    
    # Initialize the new Research Platform backend
    db = DatabaseManager("sqlite:///research_ids.sqlite")
    db.initialize_schema()
    event_bus = EventBus(db)
    resource_mgr = ResourceManager(db)
    exp_mgr = ExperimentManager(db, event_bus, resource_mgr)
    
    adapter = IDSResearchAdapter(db, event_bus, resource_mgr, exp_mgr)
    project_id = db.SessionLocal().execute(
        __import__("sqlalchemy").text("SELECT id FROM research_projects LIMIT 1")
    ).scalar()
    if not project_id:
        from wifiscanner.research import ProjectManager
        pm = ProjectManager(db)
        project_id = pm.create_project("Default IDS Project")
        
    exp_id = adapter.setup_ids_experiment(
        project_id=project_id,
        interface=args.interface or "pcap",
        window=args.window,
        flood=args.flood,
        sensitivity=args.sensitivity
    )
    
    event_bus.start()
    
    wd = Watchdog(window_s=args.window, flood_frames=args.flood,
                  sensitivity=args.sensitivity)
    print(f"IDS sensitivity: {args.sensitivity} "
          f"(effective flood threshold {wd.effective_flood_n} frames; "
          f"adaptive margin raises it automatically in noisy air)")
    print(f"Research Platform initialized. Experiment ID: {exp_id}")

    known: set = set()
    st = None
    if args.db:
        st = Store(args.db)
        known = {r["bssid"] for r in st.warden_list()}
    wd.known = known or wd.known
    fired = [0]
    
    def process_pkt(pkt):
        wd.feed(pkt)
        if pkt.haslayer("Dot11"):
            event_bus.publish(
                source="sniffer",
                event_type="frame.captured",
                payload={"len": len(pkt), "time": float(pkt.time)},
                experiment_id=exp_id,
                persist=False 
            )

    if args.pcap:
        if not sniffer.scapy_available():
            log.error("scapy required for pcap analysis")
            return 2
        from scapy.all import PcapReader
        adapter.start_live_ids(exp_id)
        for pkt in PcapReader(args.pcap):
            process_pkt(pkt)
        log.info("analysed %s", args.pcap)
    else:
        if not sniffer.scapy_available():
            log.error("scapy required for live IDS")
            return 2
        iface = args.interface
        if not iface:
            ifaces = survey.list_interfaces()
            if not ifaces:
                log.error("no wireless interface; use --pcap FILE instead")
                return 2
            iface = ifaces[0]["name"]
        sn = sniffer.MonitorSniffer(iface, hop_interval=0.35)

        try:
            adapter.start_live_ids(exp_id)
        except Exception as e:
            log.error(f"Resource allocation failed: {e}")
            return 1

        def cb(pkt):
            try:
                process_pkt(pkt)
            except Exception:
                pass
            if args.follow and len(wd.alerts) > fired[0]:
                for a in wd.alerts[fired[0]:]:
                    event_bus.publish(
                        source="WatchdogIDS",
                        event_type="ids.alert",
                        severity=a.severity,
                        payload=a.to_row(),
                        experiment_id=exp_id
                    )
                    print(f"[{a.severity.upper():8}] {a.kind}: {a.detail}")
                fired[0] = len(wd.alerts)
        if args.no_monitor_setup:
            sn.run(args.duration, on_packet=cb)
        else:
            if not is_root():
                log.error("live IDS needs root (monitor mode), or --pcap FILE")
                return 13
            with sniffer.MonitorMode(iface, use_airmon=args.airmon) as mon:
                sn.iface = mon
                sn.run(args.duration, on_packet=cb)

    adapter.stop_ids(exp_id)
    event_bus.stop()

    alerts = wd.results()
    if args.learn and st is not None:
        eng = Engine()
        if args.pcap and sniffer.scapy_available():
            sn2 = sniffer.MonitorSniffer(iface="offline")
            sn2.read_pcap(args.pcap)
            eng.ingest(sn2.results())
        else:
            eng.ingest(survey.survey_networks(args.interface, "auto", False))
        n = st.learn_warden(eng)
        print(f"warden baseline updated: {n} BSSIDs marked known-good in {args.db}")
    if alerts:
        from .display import print_rows
        print_rows(f"IDS alerts ({len(alerts)}) — every alert carries "
                   f"confidence + status; 'unconfirmed' means a single "
                   f"indicator, corroborate before acting",
                   [("Time", "time"), ("Severity", "severity"), ("Kind", "kind"),
                    ("BSSID", "bssid"), ("SSID", "ssid"), ("Conf", "confidence"),
                    ("Status", "status"), ("Evidence", "evidence"),
                    ("Detail", "detail")],
                   [a.to_row() for a in alerts])
    else:
        print("no anomalies detected in "
              f"{wd.stats()['frames']} frames ({wd.stats()['runtime_s'] or ''}s).")
    s = wd.stats()
    print(f"watchdog: {s['frames']} frames, {s['alerts']} alerts "
          f"{ {k: v for k, v in s['by_severity'].items()} }")
    if args.output and alerts:
        import csv as _csv
        from .privacy import secure_file
        os.makedirs(args.output, exist_ok=True)
        path = os.path.join(args.output, "ids_alerts.csv")
        with open(path, "w", newline="", encoding="utf-8-sig") as fh:
            w = _csv.DictWriter(fh, fieldnames=list(alerts[0].to_row()))
            w.writeheader()
            w.writerows(a.to_row() for a in alerts)
        secure_file(path)
        print(f"exported -> {path}")
    if st:
        st.close()
    return 0


def cmd_audit(args) -> int:
    eng = Engine()
    if args.pcap:
        if not sniffer.scapy_available():
            log.error("scapy required for pcap audit")
            return 2
        sn = sniffer.MonitorSniffer(iface="offline")
        sn.read_pcap(args.pcap)
        eng.ingest(sn.results())
    else:
        eng.ingest(survey.survey_networks(args.interface, "auto", True))
    if args.ssid:
        eng.aps = {b: a for b, a in eng.aps.items()
                   if args.ssid.lower() in (a.ssid or "").lower()
                   or args.ssid.upper() == b}
    if not eng.aps:
        log.error("no networks to audit (connected? or pass --pcap / --ssid)")
        return 2
    rows = audit_engine(eng)
    from .display import print_rows
    fails = [r for r in rows if r["status"] != "PASS"]
    print_rows(f"Hardening audit - {len(eng.aps)} BSS, "
               f"{len(fails)} findings",
               [("BSSID", "bssid"), ("SSID", "ssid"), ("Check", "check"),
                ("Status", "status"), ("Severity", "severity"),
                ("Fix", "finding")], rows)
    if args.output:
        os.makedirs(args.output, exist_ok=True)
        path = os.path.join(args.output, "audit_report.md")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("# Wi-Fi hardening audit\n\n")
            for a in eng.sorted_aps("rssi"):
                fh.write(f"\n## {a.ssid or '<hidden>'} ({a.bssid}, {a.vendor})\n\n")
                fh.write(f"- Current: {a.encryption}, PMF {a.pmf or '?'}, "
                         f"channel {a.channel}, WPS {'ENABLED' if a.wps else 'off'}\n")
                for r in [x for x in rows if x["bssid"] == a.bssid]:
                    mark = {"PASS": "[x]", "WARN": "[!]", "FAIL": "[ ]"}[r["status"]]
                    fh.write(f" - {mark} **{r['check']}** "
                             f"{'— ' + r['finding'] if r['finding'] else ''}\n")
        print(f"report -> {path}")
    return 0


def cmd_frames(args) -> int:
    if not sniffer.scapy_available():
        log.error("scapy required:  pip install scapy")
        return 2
    if not os.path.exists(args.pcap):
        log.error("no such file: %s", args.pcap)
        return 2
    from .frames import annotate_pcap, find_handshakes
    if args.handshakes:
        stats = find_handshakes(args.pcap)
        print_rows("EAPOL / deauth activity (counts only - no frames are "
                   "extracted, by design)",
                   [("metric", "k"), ("value", "v")],
                   [{"k": k, "v": v} for k, v in stats.items()
                    if k != "eapol_by_bss"])
        for b, c in (stats.get("eapol_by_bss") or {}).items():
            print(f"  eapol @ {b}: {c}")
        return 0
    blocks = annotate_pcap(args.pcap, limit=args.limit, filt=args.filter)
    if not blocks:
        print("no frames matched (check --filter).")
    for b in blocks:
        print(b)
    print(f"\n({len(blocks)} frames annotated"
          + (f", filter={args.filter!r}" if args.filter else "") + ")")
    return 0


# ------------------------------------------------- authorized injection

def cmd_inject(args) -> int:
    """Transmit frames ONLY as an authorized, logged, bounded self-test.

    Defaults to a dry run that builds/describes frames and writes the audit
    trail without touching the radio, so the operator can preview an action.
    Live emission requires root + --transmit + --authorized (and --yes for
    the bounded pmf-test); broadcast/third-party targets are refused.
    """
    # ------------------------------------------------ offline, zero-RF mode
    if args.mode == "ids-selftest":
        pcap = args.write_pcap or (os.path.join(args.output,
                                                "ids_selftest.pcap")
                                   if args.output else "")
        print("IDS self-test: synthesising attack signatures OFFLINE (no "
              "radio, no root) and confirming the watchdog fires on each.\n")
        rep = ij.run_ids_selftest(write_pcap=pcap)
        print_rows("IDS signature self-test",
                   [("Scenario", "scenario"), ("Expected", "expected"),
                    ("Fired", "fired"), ("Missing", "missing"),
                    ("Status", "status")], rep["rows"])
        all_pass = rep["passed"] == rep["total"]
        print(f"\nwatchdog saw {rep['frames']} synthetic frames -> "
              f"{rep['alerts']} alerts; {rep['passed']}/{rep['total']} "
              f"signatures detected.")
        if pcap and os.path.exists(pcap):
            print(f"synthetic-signature pcap (for `ids --pcap`): {pcap}")
        if not all_pass:
            log.error("IDS did NOT fire on every signature - investigate "
                      "sensor coverage before trusting live detection.")
            return 1
        print("all signatures detected: this sensor's detection path works.")
        return 0

    # ---------------------------------------------------- live modes
    if not sniffer.scapy_available():
        log.error("scapy required for injection:  pip install scapy")
        return 2

    mode = args.mode
    bssid = client = ""
    twin = {}
    try:
        if mode in ij.KICK_MODES:
            bssid, client = ij.validate_kick_targets(args.bssid, args.client,
                                                     mode)
        if mode == "evil-twin":
            channel = (ij.parse_channels(args.channels) or [6])[0]
            t_ssid, t_ch, t_sec, t_bssid = ij.validate_twin(
                args.ssid, channel, args.security, args.bssid)
            twin = {"ssid": t_ssid, "channel": t_ch, "security": t_sec,
                    "bssid": t_bssid,
                    "duration": ij.clamp_twin_duration(args.duration)}
        # Consent + privilege gates (raise InjectionError with a clear reason).
        ij.gate_transmission(mode, transmit=args.transmit,
                             authorized=args.authorized,
                             confirmed=args.yes)
    except ij.InjectionError as exc:
        log.error("%s", exc)
        return 2

    iface = args.interface
    if not iface:
        ifaces = survey.list_interfaces()
        if not ifaces:
            log.error("no wireless interface found; specify one with -i")
            return 2
        iface = ifaces[0]["name"]
        log.info("using interface %s", iface)

    transmit = args.transmit and args.authorized
    count = ij.clamp_count(mode, args.count)
    channels = ij.parse_channels(args.channels)
    if mode in ij.KICK_MODES and not args.channels:
        log.warning("no --channels given: targeting channel %s. Pass the AP's "
                    "channel (-c CH) or the frames may not reach it.",
                    channels[0])
    os.makedirs(args.output, exist_ok=True)
    audit_path = args.audit_log or os.path.join(args.output,
                                                "injection_audit.csv")
    # A verification pcap only makes sense when frames actually go out.
    pcap_path = args.write_pcap
    if transmit and not pcap_path:
        pcap_path = os.path.join(args.output, f"inject-{mode}.pcap")
    audit = ij.AuditLog(audit_path)
    src_mac = args.src_mac or ij.random_local_mac()

    try:
        if not transmit:
            print("DRY RUN: no frames will be transmitted. Add --transmit "
                  "--authorized" + (" --yes" if mode in ij.CONFIRM_MODES
                                    else "") +
                  " to actually emit. Preview:\n")
            inj = ij.Injector(iface, mode=mode, dry_run=True, audit=audit,
                              src_mac=src_mac)
            _build_preview(inj, mode, channels, args, twin)
            if mode == "evil-twin":
                n_beacons = int(twin["duration"] / ij.BEACON_INTERVAL_S)
                n_beacons = min(n_beacons, ij.MAX_TWIN_BEACONS)
                print(f"(would transmit ~{n_beacons} beacons over "
                      f"{twin['duration']:.0f}s on channel {twin['channel']}; "
                      "1 shown above; beacon-only, no client path)")
            print(f"\naudit trail: {audit_path}")
            print(f"frames built: {inj.built}; frames transmitted: 0")
            return 0

        return _inject_live(args, ij, mode, iface, channels, count, bssid,
                            client, src_mac, audit, audit_path, pcap_path)
    finally:
        audit.close()


def _build_preview(inj, mode, channels, args, twin=None) -> None:
    """Populate the audit log in dry-run mode and show the would-be frames."""
    if mode == "probe":
        ssids = [s.strip() for s in args.ssid.split(",") if s.strip()] or [""]
        inj.probe_sweep(channels, ssids, ij.clamp_count("probe", args.count))
    elif mode == "canary":
        token = args.token or ij.new_canary_token()
        print(f"canary token: {token}\n")
        inj.canary_sweep(channels, token, ij.clamp_count("canary", args.count))
    elif mode == "evil-twin":
        t = twin or {}
        print(f"evil-twin drill: beacons advertising SSID={t.get('ssid')!r} "
              f"from spoofed BSSID {t.get('bssid')} on channel "
              f"{t.get('channel')} ({t.get('security')}) - beacon ONLY, no "
              "probe/assoc/auth/data path.\n")
        pkt = ij.build_beacon(t.get("bssid"), t.get("ssid"),
                              t.get("channel", 6), t.get("security", "open"))
        inj._emit(pkt, frame="beacon", channel=str(t.get("channel", "")),
                  target=t.get("bssid", ""),
                  detail=f"ssid={t.get('ssid')} sec={t.get('security')}")
    elif mode in ij.KICK_MODES:
        bssid, client = ij.validate_kick_targets(args.bssid, args.client, mode)
        n = ij.clamp_count(mode, args.count)
        ftype = args.frame_type if mode == "deauth" else "deauth"
        direction = args.direction if mode == "deauth" else "ap-to-sta"
        print(f"target: {bssid} -> {client}   {n} {ftype} frame(s), "
              f"direction={direction}\n")
        inj.kick_burst(bssid, client, n, frame_type=ftype, direction=direction)


def _inject_live(args, ij, mode, iface, channels, count, bssid, client,
                 src_mac, audit, audit_path, pcap_path) -> int:
    """Actually transmit. Assumes consent gates have already passed + root."""
    from .display import print_rows
    inj = ij.Injector(iface, mode=mode, dry_run=False, audit=audit,
                      src_mac=src_mac)

    def _run(tx_iface: str) -> dict:
        inj.iface = tx_iface
        if mode == "evil-twin":
            # Beacon-only drill: channel-locked, self-terminating. We listen
            # on the same channel while beaconing purely so a local warden
            # run would observe it; no probe/assoc/auth/data frames are sent.
            t = twin
            dur = t["duration"]
            listener = ij.AirListener(tx_iface, dur + 2.0,
                                      pcap_path=pcap_path)
            listener.start()
            n = inj.twin_beacons(t["ssid"], t["bssid"], t["channel"],
                                 t["security"], dur)
            print(f"transmitted {n} beacon(s) advertising {t['ssid']!r} "
                  f"from {t['bssid']} (ch {t['channel']}, {t['security']}) "
                  "for the drill window; stopping.")
            listener.join()
            return ij.twin_drill_report(t["ssid"], t["bssid"], t["channel"],
                                        t["security"], n, dur)
        if mode in ij.KICK_MODES:
            ij._set_channel(tx_iface, channels[0])
            dur = args.baseline_s + args.verify_s + 2.0
            listener = ij.AirListener(tx_iface, dur, pcap_path=pcap_path)
            listener.start()
            print(f"baseline: listening {args.baseline_s:.0f}s for {client} "
                  "on your AP...")
            time.sleep(args.baseline_s)
            burst_ts = time.time()
            ftype = args.frame_type if mode == "deauth" else "deauth"
            direction = args.direction if mode == "deauth" else "ap-to-sta"
            inj.kick_burst(bssid, client, count, frame_type=ftype,
                           direction=direction)
            print(f"sent {count} bounded {ftype} frame(s); observing "
                  f"{args.verify_s:.0f}s for disconnect / re-association...")
            time.sleep(args.verify_s)
            listener.join()
            rep = ij.kick_verdict(listener.events, bssid, client, burst_ts)
            rep["mode"] = mode
            rep["frame_type"] = ftype
            rep["direction"] = direction
            rep["burst_sent"] = count
            rep["frames_seen"] = listener.frames
            rep["pcap"] = pcap_path or "-"
            return rep
        # probe / canary: a long-running listener; burst + dwell per channel
        dwell = args.dwell or ij.DEFAULT_DWELL_S
        n_ssid = len([s for s in args.ssid.split(",") if s.strip()] or [""])
        total_dur = len(channels) * (
            dwell + count * n_ssid * inj.interval + 2.0) + 2
        listener = ij.AirListener(tx_iface, total_dur, pcap_path=pcap_path)
        listener.start()
        if mode == "probe":
            ssids = [s.strip() for s in args.ssid.split(",") if s.strip()] or [""]
            for ch in channels:
                ij._set_channel(tx_iface, ch)
                for ssid in ssids:
                    for _ in range(count):
                        inj._emit(ij.build_probe_request(src_mac, ssid),
                                  frame="probe-request", channel=str(ch),
                                  target=ij.BROADCAST,
                                  detail=f"ssid={ssid or '<wildcard>'}")
                time.sleep(dwell)
            listener.join()
            responses = [e for e in listener.events if e.kind == "proberesp"]
            bssids = sorted({(normalize(e.bssid), e.ssid) for e in responses})
            return {"mode": "probe", "channels": ",".join(map(str, channels)),
                    "probe_responses": len(responses),
                    "distinct_bss": len(bssids),
                    "networks": "|".join(f"{s}@{b}" for b, s in bssids[:30]),
                    "sent": inj.sent, "pcap": pcap_path or "-"}
        token = args.token or ij.new_canary_token()
        print(f"canary token: {token}")
        print("every remote IDS/capture sensor must now report this token; "
              "grep it in their logs/pcaps.")
        for ch in channels:
            ij._set_channel(tx_iface, ch)
            for _ in range(count):
                inj._emit(ij.build_probe_request(src_mac, token),
                          frame="canary-probe", channel=str(ch),
                          target=ij.BROADCAST, detail=f"token={token}")
            time.sleep(dwell)
        listener.join()
        rep = ij.canary_results(listener.events, src_mac, token)
        rep.update({"mode": "canary", "sent": inj.sent, "pcap": pcap_path or "-"})
        return rep

    if args.no_monitor_setup:
        rep = _run(iface)
    else:
        with sniffer.MonitorMode(iface, use_airmon=args.airmon) as mon:
            rep = _run(mon)

    # ---------------------------------------------------------------- report
    if mode in ij.KICK_MODES:
        title = ("PMF / deauth-resistance self-test" if mode == "pmf-test"
                 else "Deauthentication / disassociation test (authorised)")
        print_rows(title,
                   [("Fact", "k"), ("Result", "v")],
                   [{"k": k, "v": v} for k, v in rep.items()])
        verdict = rep.get("verdict")
        if verdict == "pass":
            print("\nPASS: the forged deauth/disassoc frames were ignored - "
                  "management-frame protection (PMF/802.11w) is protecting "
                  "this client.")
        elif verdict == "fail":
            log.error("\nKICKED: the client disconnected and had to "
                      "re-associate. Management-frame protection (802.11w PMF) "
                      "is NOT enforced - set it to REQUIRED on your AP and "
                      "supplicant, then re-test. For a PMF verification this "
                      "is FAIL; for a pen-test it confirms the client/AP are "
                      "vulnerable to a kick attack.")
            return 1
        else:
            log.warning("\nINCONCLUSIVE: %s", rep.get("detail"))
            return 3
    else:
        print_rows(f"Injection result ({rep.get('mode')})",
                   [(k, k) for k in rep], [rep])
        if mode == "evil-twin":
            print("\nThis was a BEACON-ONLY drill - it cannot accept clients. "
                  "Verify detection:\n  " + str(rep.get("verify", "")))
    print(f"\ntransmitted {inj.sent} frame(s); audit trail: {audit_path}")
    if pcap_path and os.path.exists(pcap_path):
        print(f"verification capture: {pcap_path}")
    return 0


def cmd_db(args) -> int:
    """History-database maintenance: retention, anonymization, deletion."""
    if not os.path.exists(args.db) and not args.report:
        log.error("no database at %s", args.db)
        return 2
    st = Store(args.db) if os.path.exists(args.db) else None
    try:
        if args.report or not (args.prune_days or args.delete_mac or
                               args.anonymize_db or args.purge or args.vacuum):
            if st is None:
                log.error("no database at %s - nothing to report", args.db)
                return 2
            rep = st.storage_report()
            print_rows("Database storage report",
                       [("Fact", "k"), ("Value", "v")],
                       [{"k": "path", "v": rep.get("path")},
                        {"k": "size", "v": f"{rep.get('bytes', 0)} bytes"},
                        {"k": "mode", "v": rep.get("mode")},
                        {"k": "world-readable",
                         "v": rep.get("world_readable")},
                        {"k": "retention", "v": rep.get("retention")},
                        {"k": "privacy mode", "v": rep.get("privacy_mode")},
                        {"k": "anonymized writes",
                         "v": rep.get("anonymized_writes")},
                        {"k": "device rows",
                         "v": rep["tables"]["devices"]["rows"]},
                        {"k": "observation rows",
                         "v": rep["tables"]["observations"]["rows"]},
                        {"k": "fix rows",
                         "v": rep["tables"]["fixes"]["rows"]}])
            if rep.get("world_readable"):
                print("WARNING: database is readable by other users — "
                      "it maps devices to places and times. Restrict it: "
                      f"`chmod 600 {args.db}` (this tool creates 0600 by "
                      f"default; it was loosened afterwards)")
            return 0
        if args.prune_days:
            n = st.prune(args.prune_days)
            print(f"pruned {n} row(s) older than {args.prune_days:g} days")
        if args.delete_mac:
            n = st.delete_device(args.delete_mac)
            print(f"erased {n} row(s) for {args.delete_mac}")
        if args.anonymize_db or args.purge:
            if not args.yes:
                log.warning("proceeding without --yes: --anonymize-db is "
                            "IRREVERSIBLE and --purge deletes all history")
            if args.anonymize_db:
                n = st.anonymize_history()
                print(f"anonymized {n} row(s) — MACs are now salted "
                      f"pseudonyms, IPs/hostnames cleared (no undo)")
            if args.purge:
                n = st.purge_all()
                print(f"purged {n} history row(s)")
        if args.vacuum or args.prune_days or args.delete_mac or \
                args.anonymize_db or args.purge:
            st.vacuum()
            print("vacuumed.")
        return 0
    finally:
        if st is not None:
            st.close()


def cmd_lab(args) -> int:
    """Local captive-portal phishing AWARENESS lab (training simulation).

    Serves the fake portal + instructor dashboard on a local socket, keeps
    the roster + captured TEST values in an owner-only SQLite file, and
    offers reset/export paths. No RF, no third-party auth: synthetic
    credentials only.
    """
    from . import lab as labmod
    db = args.db or ("" if args.self_test else "lab.sqlite")

    # -- maintenance path: reset (+optional roster rotation) ---------------
    if args.reset or args.rotate_roster:
        if not args.yes:
            log.error("--reset deletes every captured training submission; "
                      "re-run with --yes to confirm.")
            return 2
        path = db or "lab.sqlite"
        if not os.path.exists(path):
            log.error("no lab database at %s - nothing to reset", path)
            return 2
        st = labmod.LabStore(path)
        try:
            if args.rotate_roster:
                n = st.rotate_roster(args.accounts)
                print(f"lab reset: wiped AND regenerated the synthetic roster "
                      f"({n} fresh accounts, old data gone)")
                print_rows("New synthetic roster (hand these to students)",
                           [("Account", "account"),
                            ("Training password", "secret")], st.accounts())
            else:
                removed = st.reset()
                print(f"lab reset: deleted {removed} training row(s) "
                      f"(synthetic roster kept)")
            if args.output:
                for f in labmod.export_lab(st, args.output):
                    print(f"  -> {f}")
        finally:
            st.close()
        return 0

    # -- offline proof path -------------------------------------------------
    if args.self_test:
        print("lab self-test: running the full student + instructor loop "
              "against a throwaway server (no port stays open)...\n")
        ok = labmod.self_test(db_path=db or ":memory:",
                              accounts=max(2, min(args.accounts, 20)))
        return 0 if ok else 1

    # -- live lab -----------------------------------------------------------
    st = labmod.LabStore(db)
    try:
        st.ensure_roster(args.accounts)
        token = args.instructor_token or labmod.new_token()
        app = labmod.LabApp(st, ssid=args.ssid, token=token)
        httpd = labmod.make_server(args.bind, args.port, app)
        host = ("localhost" if args.bind in ("127.0.0.1", "::1")
                else args.bind)
        st.record_event("server-start",
                        f"bind={args.bind} port={args.port} "
                        f"ssid={args.ssid!r}")
        portal_url = f"http://{host}:{args.port}/"
        instructor_url = f"http://{host}:{args.port}/i/{token}"
        print(f"lab portal (students)  : {portal_url}")
        print(f"instructor dashboard   : {instructor_url}   "
              f"(keep this link private - it is the attacker's view)")
        print("debrief pages (share AFTER the exercise): "
              "/indicators  /compare  /learn")
        if args.bind == "0.0.0.0":
            log.warning("lab is bound to all interfaces: anyone on this LAN "
                        "can reach the fake portal. Use only on a classroom "
                        "network you control.")
        rows = st.accounts()
        print_rows(f"Synthetic roster ({len(rows)} training accounts - "
                   f"no real service; hand out for the exercise)",
                   [("Account", "account"),
                    ("Training password", "secret")], rows)
        print("\nlive capture lines appear as 'lab capture #N ...' - "
              "Ctrl-C to stop.\n")
        if args.duration:
            import threading as _th
            _th.Timer(args.duration, httpd.shutdown).start()
        try:
            httpd.serve_forever(poll_interval=0.5)
        except KeyboardInterrupt:
            print("\nstopping the lab...")
        finally:
            httpd.server_close()
        if args.output:
            for f in labmod.export_lab(st, args.output):
                print(f"  -> {f}")
        f = st.funnel()
        print(f"exercise summary: {f['portal_views']} portal views, "
              f"{f['submissions']} submissions, "
              f"{f['roster_matches']} synthetic credential(s) captured")
        return 0
    except OSError as exc:
        log.error("cannot start the lab server on %s:%s - %s",
                  args.bind, args.port, exc)
        return 2
    finally:
        st.close()


def cmd_wpa_lab(args) -> int:
    """WPA/WPA2/WPA3 decryption laboratory (offline, lab captures only)."""
    from . import wpalab as wl
    from wifiscanner.research import DatabaseManager, EventBus, ResourceManager, ExperimentManager, DatasetManager, ProjectManager
    from wifiscanner.research.lab_integrations import WPALabResearchAdapter
    
    db = DatabaseManager("sqlite:///research_labs.sqlite")
    db.initialize_schema()
    event_bus = EventBus(db)
    exp_mgr = ExperimentManager(db, event_bus, ResourceManager(db))
    dataset_mgr = DatasetManager(db)
    pm = ProjectManager(db)
    adapter = WPALabResearchAdapter(db, exp_mgr, dataset_mgr)

    # ------------------------------------------------ instructor: fixtures
    if args.action == "make-fixture":
        if not args.pcap:
            log.error("usage: wifiscanner wpa-lab make-fixture OUT.pcap "
                      "[--ssid ...] [--password ...]")
            return 2
        password = args.password or "lab-passphrase-07"
        ssid = args.ssid or "LabNet-PSK"
        meta = wl.make_fixture(args.pcap, ssid=ssid, password=password,
                               cipher=args.cipher, channel=args.channel,
                               include_handshake=not args.no_handshake,
                               include_plaintext_tail=not args.no_plaintext)
                               
        project_id = db.SessionLocal().execute(__import__("sqlalchemy").text("SELECT id FROM research_projects LIMIT 1")).scalar()
        if not project_id:
            project_id = pm.create_project("WPA Cryptography Project")
            
        ds_id = adapter.import_fixture_as_dataset(args.pcap, meta)
        
        print(f"laboratory capture written: {meta['path']} "
              f"({meta['frames']} frames)")
        query = f"SELECT checksum FROM research_datasets WHERE id='{ds_id}'"
        chk = dataset_mgr.db.SessionLocal().execute(__import__("sqlalchemy").text(query)).scalar()
        print(f"[Research Platform] Registered as Dataset ID: {ds_id} (Checksum: {chk})")
        print(f"  SSID:       {meta['ssid']}")
        print(f"  AP:         {meta['ap']}   client: {meta['sta']}")
        print(f"  cipher:     {meta['cipher']}   channel: {args.channel}")
        print(f"  passphrase: {meta['password']!r}"
              + ("   (hand it to students for exercise 3)" 
                 if not args.no_handshake else "   (exercise 4: capture has "
                 "NO handshake — even this correct key cannot decrypt it)"))
        print(f"  PMK (instructor-only): {meta['pmk']}")
        log.warning("keep the printed PMK/passphrase in instructor notes; "
                    "the capture file itself is shareable")
        return 0

    if args.action == "exercises":
        print(wl.exercises_text(args.exercise))
        if not args.exercise:
            print("Each exercise works standalone. Suggested order: 1 → 6. "
                  "Captures: `wpa-lab make-fixture` (ex 1-3, 5-6) and "
                  "`wpa-lab make-fixture --no-handshake` (ex 4).")
        return 0

    # ------------------------------------------------ anything capture-side
    if not args.pcap:
        log.error("this action needs a capture file")
        return 2
    if not os.path.exists(args.pcap):
        log.error("no such capture: %s (build one: wifiscanner wpa-lab "
                  "make-fixture lab.pcap --ssid ClassNet)", args.pcap)
        return 2
    try:
        analysis = wl.analyze_capture(wl.parse_capture(args.pcap))
    except wl.PcapError as exc:
        log.error("%s", exc)
        return 2

    default_ssid = next((a["ssid"] for a in analysis["aps"].values()
                         if a.get("ssid")), "")

    def _print_inventory(analysis):
        aps = analysis["aps"]
        print_rows("Networks in the capture",
                   [("BSSID", "bssid"), ("SSID", "ssid"),
                    ("Generation", "security"), ("Cipher", "cipher"),
                    ("AKM", "akm_s"), ("PMF", "pmf"), ("Ch", "channel")],
                   [dict(a, akm_s=",".join(a["akm"])) for a in aps.values()])
        hs = analysis["handshakes"]
        rows = []
        for h in hs:
            rows.append({"ap": h["ap_s"], "sta": h["sta_s"],
                         "msgs": ",".join(map(str, sorted(set(h["msgs"])))),
                         "complete": "yes" if h["complete"] else "NO",
                         "anonce": h["anonce"][:8].hex() + "…"
                         if h["anonce"] else "-",
                         "snonce": h["snonce"][:8].hex() + "…"
                         if h["snonce"] else "-"})
        print_rows("4-way handshakes (the 'authorization to decrypt' "
                   "artifact)",
                   [("AP", "ap"), ("Client", "sta"), ("Msgs", "msgs"),
                    ("Complete", "complete"), ("ANonce", "anonce"),
                    ("SNonce", "snonce")], rows)
        rows0 = wl.frame_rows(analysis)
        states = {}
        for r in rows0:
            states[r["status"]] = states.get(r["status"], 0) + 1
        print_rows("Frame states (what an observer sees WITHOUT any key)",
                   [("Status", "k"), ("Frames", "v")],
                   [dict(k=k, v=v) for k, v in states.items()])
        eap = [f for f in analysis["frames"] if f.is_eapol]
        if not eap:
            print("\n⚠ no EAPOL handshake frames in this capture — keys "
                  "CANNOT be verified or derived from it (see exercise 4)")
        return rows0

    if args.action == "inventory":
        _print_inventory(analysis)
        return 0

    # gather lab key material (authorized by definition: the instructor owns
    # it and hands it out for the exercise)
    keys = []
    if args.action in ("try", "decrypt", "web"):
        if args.password:
            ssid = args.ssid or default_ssid
            if not ssid:
                log.error("passphrase derivation needs the network name: "
                          "--ssid (the capture has no SSID to fall back on)")
                return 2
            keys.append(wl.LabKey(args.password, ssid=ssid,
                                  label="--password"))
            if not args.ssid:
                print(f"(deriving the PSK from capture SSID {ssid!r})")
        for hexa, label in ((args.psk, "--psk"), (args.pmk, "--pmk")):
            if hexa:
                keys.append(wl.LabKey(hexa, label=label))
        if args.key_file:
            keys.extend(wl.load_key_file(args.key_file))

    def _no_handshake_teaching():
        print("\n🚫 NO HANDSHAKE IN THIS CAPTURE — not one key can even be "
              "tested.\nThe PSK/PMK alone is not enough: the per-session PTK "
              "is derived from the passphrase AND the fresh ANonce/SNonce "
              "exchanged when the client joined. No nonces → no PTK → "
              "no decryption, even with the CORRECT passphrase.\n"
              "That is why real captures must start before the target joins "
              "(and why attackers force re-joins — `wifiscanner ids` watches "
              "for exactly that). Exercise 4 in `wpa-lab exercises`.")

    if args.action == "try":
        if not keys:
            log.error("try needs a candidate: --password (with --ssid), "
                      "--psk or --pmk")
            return 2
        if not analysis["handshakes"]:
            print(f"capture {args.pcap}: no EAPOL 4-way handshake present")
            _no_handshake_teaching()
            return 3
        result = wl.decrypt_capture(analysis, keys)
        for v in result["verdicts"]:
            mark = {"accepted": "✅ ACCEPTED", "wrong-key": "❌ wrong key",
                    "no-handshake": "🚫"}[v["verdict"]]
            print(f"{mark}  {v['pair']}: {v['detail']}")
        accepted = any(v["verdict"] == "accepted" for v in result["verdicts"])
        if accepted:
            print(f"\n🔓 authorised decryption: {result['decrypted']} "
                  f"frame(s) opened with the verified key")
            dec = [r for r in result["rows"] if r["status"] == "decrypted"]
            print_rows("What just became visible (was pure noise before)",
                       [("#", "idx"), ("From", "sa"), ("To", "da"),
                        ("Proto", "plain_kind"), ("Content", "info")],
                       dec[:args.limit])
            print("\nbefore: only MAC addresses, sizes and timing of these "
                  "frames were visible; after: hosts, names, URLs. That "
                  "difference is the WPA privacy guarantee, observed "
                  "first-hand.")
            return 0
        if any(v["verdict"] == "no-handshake"
               for v in result["verdicts"]):
            print("\nnothing can be verified: the capture lacks the "
                  "handshake. Even the correct passphrase fails here — "
                  "the PTK needs the fresh nonces. (See exercise 4.)")
            return 3
        print("\nwrong key → MIC mismatch → zero frames decrypted. The "
              "handshake proves keys offline; try the worksheet's next "
              "candidate.")
        return 1

    if args.action == "decrypt":
        if not keys:
            log.error("decrypt needs laboratory key material: --password "
                      "(+--ssid), --psk, --pmk or --key-file")
            return 2
        if not analysis["handshakes"]:
            print(f"capture {args.pcap}: no EAPOL 4-way handshake present")
            _no_handshake_teaching()
            return 3
        result = wl.decrypt_capture(analysis, keys)
        _print_inventory_keep_short(analysis, result)
        if args.output:
            files = wl.export_lab(args.pcap, analysis, result, args.output)
            for f in files:
                print(f"  -> {f}")
        ok = result["decrypted"] > 0
        if not ok:
            print("nothing decrypted: no key verified. See the verdicts "
                  "above — wrong keys fail at the MIC, missing handshakes "
                  "fail before that.")
        return 0 if ok else 1

    # ------------------------------------------------------------------ web
    keys0 = keys
    token = args.instructor_token or wl_session_token()
    db = args.db or "wpa_lab.sqlite"
    store = wl.WpaLabStore(db)
    try:
        app = wl.WpaWebApp(args.pcap, store, keys0, token)
        httpd = wl.make_web_server(args.bind, args.port, app)
    except OSError as exc:
        log.error("cannot bind %s:%s - %s", args.bind, args.port, exc)
        store.close()
        return 2
    host = "localhost" if args.bind in ("127.0.0.1", "::1") else args.bind
    base = f"http://{host}:{args.port}"
    print(f"student portal      : {base}/")
    print(f"instructor dashboard: {base}/i/{token}   (keep private)")
    print(f"lab capture         : {args.pcap} "
          f"({len(app.analysis['frames'])} frames; "
          f"{'handshake present' if app.analysis['handshakes'] else 'NO HANDSHAKE — exercise 4 mode'})")
    print(f"authorized keys     : {len(keys0)} item(s) of laboratory key "
          f"material loaded for instructor unlock")
    if args.bind == "0.0.0.0":
        log.warning("web lab bound to all interfaces - classroom LANs only")
    print("\nCtrl-C to stop. Students see the locked capture until a key "
          "verifies.\n")
    if args.duration:
        import threading as _th
        _th.Timer(args.duration, httpd.shutdown).start()
    try:
        httpd.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        print("\nstopping the WPA lab...")
    finally:
        httpd.server_close()
    f = store.funnel()
    print(f"lab session: {f['visits']} page views, {f['tries']} key attempts, "
          f"{f['successes']} verified, {f['frames_decrypted']} frames unlocked")
    store.close()
    return 0


def wl_session_token() -> str:
    import secrets as _sec
    return _sec.token_urlsafe(9)


def _print_inventory_keep_short(analysis, result):
    ver = result["verdicts"]
    print_rows("Key verdicts",
               [("Key", "key"), ("Pair", "pair"), ("Verdict", "verdict"),
                ("Detail", "detail")], ver)
    dec = [r for r in result["rows"] if r["status"] == "decrypted"]
    if dec:
        print_rows(f"Decrypted traffic ({len(dec)} frames)",
                   [("#", "idx"), ("From", "sa"), ("To", "da"),
                    ("Proto", "plain_kind"), ("Content", "info")],
                   dec[:40])
    n_lock = sum(r["status"] in ("locked", "no-handshake")
                 for r in result["rows"])
    print(f"\nsummary: {len(result['rows'])} frames · "
          f"{len(result['sessions'])} verified session(s) · "
          f"{result['decrypted']} decrypted · {n_lock} remained sealed")


def _parse_since(raw: str) -> float:
    """'2d' / '36h' / '90m' / plain seconds -> seconds (0 = everything)."""
    raw = (raw or "").strip().lower()
    if not raw:
        return 0.0
    mult = 1.0
    for suf, m in (("d", 86400), ("h", 3600), ("m", 60), ("s", 1)):
        if raw.endswith(suf):
            mult = float(m)
            raw = raw[:-1]
            break
    try:
        return float(raw) * mult
    except ValueError:
        log.error("cannot parse --since %r (use 2d / 36h / 90m)", raw)
        return -1.0


def cmd_mac_lab(args) -> int:
    """MAC randomization & deanonymization laboratory."""
    import json as _json
    from . import devlab as dl
    from wifiscanner.research import DatabaseManager, EventBus, ResourceManager, ExperimentManager, DatasetManager, ProjectManager
    from wifiscanner.research.lab_integrations import TrackLabResearchAdapter

    db = DatabaseManager("sqlite:///research_labs.sqlite")
    db.initialize_schema()
    event_bus = EventBus(db)
    exp_mgr = ExperimentManager(db, event_bus, ResourceManager(db))
    dataset_mgr = DatasetManager(db)
    pm = ProjectManager(db)
    adapter = TrackLabResearchAdapter(db, exp_mgr, dataset_mgr)

    if args.action == "make-dataset":
        if not args.dataset:
            log.error("usage: wifiscanner mac-lab make-dataset DIR "
                      "[--seed N] [--fresh]")
            return 2
        meta = dl.generate_maclab_dataset(args.dataset, seed=args.seed,
                                          fresh=args.fresh)
                                          
        project_id = db.SessionLocal().execute(__import__("sqlalchemy").text("SELECT id FROM research_projects LIMIT 1")).scalar()
        if not project_id:
            project_id = pm.create_project("MAC Randomization Deanonymization")
            
        ds_id = adapter.import_tracking_dataset(args.dataset, meta)
        
        print(f"dataset written: {args.dataset} "
              f"({meta['frames']} frames; sensors: "
              f"{', '.join(meta['sensors'])}; 2-day span)")
        print(f"[Research Platform] Registered as Dataset ID: {ds_id}")
        print(f"  sensor pcaps : "
              f"{', '.join('sensor-' + s + '.pcap' for s in meta['sensors'])}")
        print(f"  ground truth : {args.dataset}/ground-truth.csv "
              f"(instructor-only, 0600 — never hand this to students)")
        print("\nDevices woven in:")
        print("  Device-A  — a randomized-MAC phone that rotates (the merge "
              "goal)")
        print("  Twins B1/B2 — identical fingerprints & SSIDs, yet "
              "provably distinct (simultaneous sightings — the trap)")
        print("  Device-C  — a stable laptop (control singleton)")
        print("  Device-D  — a stable IoT badge (cadence tell)")
        return 0

    if args.action == "exercises":
        print(dl.maclab_exercises())
        return 0

    if not args.dataset:
        log.error("this action needs a dataset DIR")
        return 2
    if not os.path.isdir(args.dataset):
        log.error("no such dataset: %s (build one: wifiscanner mac-lab "
                  "make-dataset %s)", args.dataset, args.dataset)
        return 2
    ds = dl.load_dataset(args.dataset)
    eng = dl.CorrelationEngine(ds["obs"])

    if args.action == "inventory":
        rows = []
        for m in eng.macs:
            d = eng.by_mac[m]
            rows.append({"mac": m,
                         "type": "randomized" if is_randomized(m) else "stable",
                         "vendor": dl.oui_lookup(m),
                         "frames": d["frames"],
                         "ssids": ",".join(sorted(d["ssids"])) or "-",
                         "fp": d["fp"][:30] + "…", "sensors":
                         ",".join(sorted(d["sensor_spans"]))})
        print_rows(f"MACs in {args.dataset} ({len(rows)})",
                   [("MAC", "mac"), ("Type", "type"), ("Vendor", "vendor"),
                    ("Frames", "frames"), ("Probed SSIDs", "ssids"),
                    ("IE fingerprint", "fp"), ("Sensors", "sensors")], rows)
        print("\nsome of these may be the same physical lab device with a "
              "rotated address — that is the exercise.")
        return 0

    if args.action == "correlate":
        matrix = eng.matrix()
        rows = [{"a": e["pair"][0], "b": e["pair"][1], "score": e["score"],
                 "verdict": e["verdict"],
                 "note": (e.get("caution")
                          or (e["anti"][0][2] if e["anti"]
                              else e["support"][0][2] if e["support"] else ""))
                 [:64]} for e in matrix[:args.limit]]
        print_rows("Pairwise evidence (highest confidence first)",
                   [("Device A", "a"), ("Device B", "b"), ("Score", "score"),
                    ("Verdict", "verdict"), ("Dominant fact", "note")], rows)
        print(f"\nengine clusters (threshold '{args.min_verdict}'): "
              "hypotheses, not facts —")
        for c in eng.clusters(min_verdict=args.min_verdict):
            mark = "✅" if c["size"] > 1 else "·"
            print(f" {mark} {', '.join(c['members'])}")
            print(f"     ↳ {c['note']}")
        print("\nacross the whole matrix: identical fingerprints are "
              "everywhere — only behavioural links justify a merge. "
              "Full reasoning: mac-lab explain DIR MAC1 MAC2.")
        return 0

    if args.action == "explain":
        if len(args.macs) != 2:
            log.error("usage: wifiscanner mac-lab explain DIR MAC1 MAC2")
            return 2
        m1, m2 = (x.strip().upper() for x in args.macs)
        if m1 not in eng.by_mac or m2 not in eng.by_mac:
            log.error("one of those MACs never appears in this dataset "
                      "(run mac-lab inventory DIR)")
            return 2
        e = eng.evidence(m1, m2)
        print(f"{m1}  ⇄  {m2}   →  score {e['score']}  [{e['verdict'].upper()}]")
        for sname, w, txt in e["support"]:
            print(f"  +  {sname:<12} +{w:g}   {txt}")
        for sname, w, txt in e["anti"]:
            print(f"  −  {sname:<12} {w:g}   {txt}")
        if e.get("caution"):
            print(f"\n⚠ {e['caution']}")
        print("\nremember: this is always a hypothesis. New anti-evidence "
              "(a simultaneous sighting) collapses any score.")
        return 0

    if args.action == "score":
        if not args.submit:
            log.error("score needs --submit answer.json "
                      "([[\"MAC\",\"MAC\"], ...]) or '-' for stdin")
            return 2
        raw = sys.stdin.read() if args.submit == "-" else \
            open(args.submit, encoding="utf-8").read()
        try:
            clusters = _json.loads(raw)
        except _json.JSONDecodeError as exc:
            log.error("bad answer file: %s", exc)
            return 2
        r = dl.score_maclab(ds["truth"], clusters)
        print(f"score: {r['score']}/100  (points {r['points']} of "
              f"{r['possible']} available)")
        for fb in r["feedback"]:
            print(f"  {fb}")
        return 0 if r["score"] >= 60 else 1

    # ------------------------------------------------------------------ web
    token = args.instructor_token or dl.new_token()
    db = args.db or "mac_lab.sqlite"
    store = dl.DevLabStore(db)
    try:
        app = dl.MacLabApp(ds, store, token)
        httpd = dl.make_maclab_server(args.bind, args.port, app)
    except OSError as exc:
        log.error("cannot bind %s:%s - %s", args.bind, args.port, exc)
        store.close()
        return 2
    host = "localhost" if args.bind in ("127.0.0.1", "::1") else args.bind
    base = f"http://{host}:{args.port}"
    print(f"student portal      : {base}/")
    print(f"instructor dashboard: {base}/i/{token}   (keep private)")
    print(f"dataset             : {args.dataset} "
          f"({len(eng.macs)} MACs, {len(ds['obs'])} probe frames)")
    if args.bind == "0.0.0.0":
        log.warning("web lab bound to all interfaces - classroom LANs only")
    print("\nGround truth never reaches the student pages; attempts are "
          "logged in the store. Ctrl-C to stop.\n")
    if args.duration:
        import threading as _th
        _th.Timer(args.duration, httpd.shutdown).start()
    try:
        httpd.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        print("\nstopping the MAC lab...")
    finally:
        httpd.server_close()
    f = store.funnel("mac")
    print(f"lab session: {f['views']} page views, {f['attempts']} scored "
          f"attempts, best {f['best_score']}/100")
    store.close()
    return 0


def cmd_track_lab(args) -> int:
    """Long-term device tracking & privacy laboratory."""
    import json as _json
    from . import devlab as dl
    from wifiscanner.research import DatabaseManager, EventBus, ResourceManager, ExperimentManager, DatasetManager, ProjectManager
    from wifiscanner.research.lab_integrations import TrackLabResearchAdapter

    db = DatabaseManager("sqlite:///research_labs.sqlite")
    db.initialize_schema()
    event_bus = EventBus(db)
    exp_mgr = ExperimentManager(db, event_bus, ResourceManager(db))
    dataset_mgr = DatasetManager(db)
    pm = ProjectManager(db)
    adapter = TrackLabResearchAdapter(db, exp_mgr, dataset_mgr)

    if args.action == "make-dataset":
        if not args.dataset:
            log.error("usage: wifiscanner track-lab make-dataset DIR "
                      "[--seed N] [--days 14] [--fresh]")
            return 2
        meta = dl.generate_tracklab_dataset(args.dataset, seed=args.seed,
                                            days=args.days, fresh=args.fresh)
                                            
        project_id = db.SessionLocal().execute(__import__("sqlalchemy").text("SELECT id FROM research_projects LIMIT 1")).scalar()
        if not project_id:
            project_id = pm.create_project("Tracking and Privacy Research")
            
        ds_id = adapter.import_tracking_dataset(args.dataset, meta)
        
        print(f"dataset written: {args.dataset} ({meta['frames']} frames, "
              f"{meta['days']} days, sensors: {', '.join(meta['sensors'])})")
        print(f"[Research Platform] Registered as Dataset ID: {ds_id}")
        print(f"  ground truth : {args.dataset}/ground-truth.csv "
              f"(instructor-only, 0600)")
        print("\nDevices woven in:")
        print("  Student-A — persistent MAC, a full weekday routine")
        print("  Decoy-A'  — same OUI + similar hours, DIFFERENT locations "
              "(the attribution trap)")
        print("  Visitor-B — MAC rotates every single visit (the privacy "
              "defence, working)")
        print("  Staff-IoT — stable badge doing a fixed daily loop")
        return 0

    if args.action == "exercises":
        print(dl.tracklab_exercises())
        return 0

    if not args.dataset:
        log.error("this action needs a dataset DIR")
        return 2
    if not os.path.isdir(args.dataset):
        log.error("no such dataset: %s (build one: wifiscanner track-lab "
                  "make-dataset %s)", args.dataset, args.dataset)
        return 2
    ds = dl.load_dataset(args.dataset)
    since = _parse_since(getattr(args, "since", "") or "")
    if since < 0:
        return 2
    tr = dl.Tracker(ds["obs"], since_s=since)

    if args.action == "inventory":
        rows = [{"mac": t["mac"], "vendor": t["vendor"],
                 "type": "random" if t["randomized"] else "stable",
                 "frames": t["frames"], "visits": t["visits"],
                 "days": t["days"],
                 "seen": ",".join(t["sensors"])} for t in tr.table()[:40]]
        print_rows(f"Presence in {args.dataset}"
                   + (f" (last {args.since})" if since else ""),
                   [("MAC", "mac"), ("Vendor", "vendor"), ("Type", "type"),
                    ("Frames", "frames"), ("Visits", "visits"),
                    ("Days", "days"), ("Seen at", "seen")], rows)
        return 0

    if args.action == "history":
        if args.mac:
            mac = args.mac.strip().upper()
            p = tr.pattern(mac)
            if not p["visits"]:
                log.error("%s has no observations in this window", mac)
                return 2
            print(f"{mac} — {p['visit_count']} visits, "
                  f"{len(p['days_present'])} distinct days")
            rows = [{"day": time.strftime("%a %m-%d", time.localtime(s)),
                     "from": time.strftime("%H:%M", time.localtime(s)),
                     "dwell_min": max(1, round((e - s) / 60)),
                     "sensor": sens, "frames": n}
                    for sens, s, e, n in p["visits"]]
            print_rows("Visit timeline",
                       [("Day", "day"), ("From", "from"),
                        ("Dwell (min)", "dwell_min"), ("Sensor", "sensor"),
                        ("Frames", "frames")], rows)
            print("\n" + dl.heatmap_ascii(p["hours"]))
        else:
            rows, t0, t1 = dl.timeline_rows(tr.obs, bucket_s=7200)
            print(f"timeline buckets of 2h, "
                  f"{time.strftime('%m-%d %H:%M', time.localtime(t0))} → "
                  f"{time.strftime('%m-%d %H:%M', time.localtime(t1))}")
            for r in rows[:24]:
                cells = "".join(c or "." for c in r["cells"])
                tag = "R" if r["randomized"] else "S"
                print(f"{tag} {r['mac']}  {cells}")
            print("R = randomized MAC, S = stable; letters = sensor initial")
        return 0

    if args.action == "patterns":
        macs = ([args.mac.strip().upper()] if args.mac else
                [t["mac"] for t in tr.table()[:8]])
        for mac in macs:
            p = tr.pattern(mac)
            if not p["visits"]:
                continue
            tk = tr.trackability(mac)
            print(f"\n{mac} — {p['vendor']}"
                  + ("  (randomized)" if p["randomized"] else "  (persistent)"))
            print(f"  {tk['verdict']}  [{tk['reason']}]")
            print(f"  hours: {dl.heatmap_ascii(p['hours'])}")
            wd = " ".join(f"{d}:{c}" for d, c in zip(
                "Mon Tue Wed Thu Fri Sat Sun".split(), p["weekdays"]) if c)
            print(f"  weekdays: {wd or '—'}")
            dwell = ", ".join(f"{k} {v}min" for k, v in
                              p["dwell_min"].items())
            print(f"  dwell: {dwell or '—'}")
            for (a, b), n in sorted(p["edges"].items(),
                                    key=lambda kv: -kv[1]):
                print(f"  edge: {a} → {b} ×{n}")
        return 0

    if args.action == "compare":
        since_s = since or 2 * 86400
        short = dl.Tracker(ds["obs"], since_s=since_s)
        full = dl.Tracker(ds["obs"])
        label = args.since or "2d"
        print(f"last {label} vs full "
              f"{ds['manifest'].get('days', '?')}-day history\n")
        for title, trk in ((f"window: {label}", short),
                           ("window: full dataset", full)):
            print(f"■ {title}")
            rows = [{"mac": t["mac"], "visits": t["visits"], "days": t["days"],
                     "seen": ",".join(t["sensors"])}
                    for t in trk.table()[:8]]
            print_rows("", [("MAC", "mac"), ("Visits", "visits"),
                            ("Days", "days"), ("Seen at", "seen")], rows)
            print()
        print("same radio, same students — only retention changed. "
              "Every additional day of logs is additional inference the "
              "collector holds.")
        return 0

    if args.action == "score":
        if not args.answers:
            log.error("score needs --answers answers.json (or '-' for stdin)")
            return 2
        raw = sys.stdin.read() if args.answers == "-" else \
            open(args.answers, encoding="utf-8").read()
        try:
            answers = _json.loads(raw)
        except _json.JSONDecodeError as exc:
            log.error("bad answer file: %s", exc)
            return 2
        r = dl.score_tracklab(ds["truth"], answers)
        print(f"score: {r['score']}/100  (points {r['points']} of "
              f"{r['possible']})")
        for fb in r["feedback"]:
            print(f"  {fb}")
        return 0 if r["score"] >= 60 else 1

    # ------------------------------------------------------------------ web
    token = args.instructor_token or dl.new_token()
    db = args.db or "track_lab.sqlite"
    store = dl.DevLabStore(db)
    try:
        app = dl.TrackLabApp(ds, store, token)
        httpd = dl.make_tracklab_server(args.bind, args.port, app)
    except OSError as exc:
        log.error("cannot bind %s:%s - %s", args.bind, args.port, exc)
        store.close()
        return 2
    host = "localhost" if args.bind in ("127.0.0.1", "::1") else args.bind
    base = f"http://{host}:{args.port}"
    print(f"student portal      : {base}/")
    print(f"instructor dashboard: {base}/i/{token}   (keep private)")
    print(f"dataset             : {args.dataset} "
          f"({len(tr.table())} MACs over "
          f"{ds['manifest'].get('days', '?')} days)")
    if args.bind == "0.0.0.0":
        log.warning("web lab bound to all interfaces - classroom LANs only")
    print("\nGround truth never reaches the student pages; attempts are "
          "logged. Ctrl-C to stop.\n")
    if args.duration:
        import threading as _th
        _th.Timer(args.duration, httpd.shutdown).start()
    try:
        httpd.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        print("\nstopping the tracking lab...")
    finally:
        httpd.server_close()
    f = store.funnel("track")
    print(f"lab session: {f['views']} page views, {f['attempts']} quiz "
          f"attempts, best {f['best_score']}/100")
    store.close()
    return 0


def cmd_stealth_lab(args) -> int:
    """Hidden-monitoring & stealth-detection laboratory."""
    import json as _json
    from . import hidmon as hm

    if args.action == "make-scenario":
        if not args.dataset:
            log.error("usage: wifiscanner stealth-lab make-scenario DIR "
                      "[--seed N] [--fresh]")
            return 2
        meta = hm.generate_scenario(args.dataset, seed=args.seed,
                                    fresh=args.fresh)
        print(f"scenario written: {args.dataset} ({meta['rows']} telemetry "
              f"rows over {meta['ticks']} ticks; host {meta['host']!r})")
        print("  scenario.json / telemetry.json : shareable with students")
        print(f"  {args.dataset}/ground-truth.json : INSTRUCTOR-ONLY "
              f"(0600) — never hand out")
        print("\nBeats woven in: install → 6 h keepalives → NIGHT FLIP "
              "(cadence 40×, CPU spikes) → concealment (ps-vs-ss mismatch, "
              "auth.log gap) → respawn/rename → unlink-while-running. "
              "Plus one registered IT monitor students must NOT accuse.")
        return 0

    if args.action == "exercises":
        print(hm.stealth_exercises())
        return 0

    if not args.dataset:
        log.error("this action needs a scenario DIR")
        return 2
    if not os.path.isdir(args.dataset):
        log.error("no such scenario: %s (build one: wifiscanner stealth-lab "
                  "make-scenario %s)", args.dataset, args.dataset)
        return 2
    scen = hm.load_scenario(args.dataset)
    eng = hm.StealthEngine(scen)
    tick = args.tick if args.tick else scen["manifest"]["ticks"] - 1

    if args.action == "telemetry":
        kinds = dict(procs="proc", listeners="conn", files="file",
                     auth="auth")
        rows = [r for r in scen["telem"][kinds[args.kind]]
                if r["t"] <= tick]
        if args.day:
            lo, hi = (args.day - 1) * 96, args.day * 96
            rows = [r for r in rows if lo <= r["t"] < hi]
        if args.kind == "procs":
            rows = sorted(rows, key=lambda r: (r["t"], -r["cpu"]))[-120:]
            out = [{"t": hm.fmt_tick(scen["manifest"]["start"], r["t"]),
                    "pid": r["pid"], "ppid": r["ppid"], "user": r["user"],
                    "name": r["name"] + ("" if r["visible"] else " ⚠HIDDEN"),
                    "cpu": r["cpu"], "rss": r["rss"],
                    "owner": r.get("owner", "?")} for r in rows]
            print_rows(f"process table (up to tick {tick})",
                       [("time", "t"), ("pid", "pid"), ("ppid", "ppid"),
                        ("user", "user"), ("name", "name"),
                        ("cpu%", "cpu"), ("rss", "rss"), ("pkg-owner",
                                                         "owner")], out)
        elif args.kind == "listeners":
            rows = rows[-120:]
            out = [{"t": hm.fmt_tick(scen["manifest"]["start"], r["t"]),
                    "by_key": r["key"], "proto": r["proto"],
                    "flow": f"{r['src']} -> {r['dst']}", "bytes": r["bytes"]}
                   for r in rows]
            print_rows(f"connection table (up to tick {tick})",
                       [("time", "t"), ("by", "by_key"), ("proto", "proto"),
                        ("flow", "flow"), ("bytes", "bytes")], out)
        elif args.kind == "files":
            out = [{"t": hm.fmt_tick(scen["manifest"]["start"], r["t"]),
                    "path": r["path"], "op": r["op"], "by": r["by"]}
                   for r in rows[-120:]]
            print_rows("file events",
                       [("time", "t"), ("path", "path"), ("op", "op"),
                        ("by", "by")], out)
        else:
            out = [{"t": hm.fmt_tick(scen["manifest"]["start"], r["t"]),
                    "line": r["line"]} for r in rows[-120:]]
            print_rows("auth.log", [("time", "t"), ("line", "line")], out)
        return 0

    if args.action == "hunt":
        league = eng.league()
        out = [{"entity": r["key"], "name": r["name"], "score": r["score"],
                "verdict": r["verdict"],
                "top_signal": r["signals"][0][0] if r["signals"] else "-"}
               for r in league if r["score"] > 0]
        print_rows("hunter's league (explainable engine scoring)",
                   [("entity", "entity"), ("name", "name"),
                    ("score", "score"), ("verdict", "verdict"),
                    ("top signal", "top_signal")], out)
        print("\nengine agreement is NOT the answer key — prove each signal "
              "in `stealth-lab explain DIR KEY`, then submit with "
              "`stealth-lab score`.")
        return 0

    if args.action == "explain":
        key = (args.key or "").strip()
        a = eng.analyze(key)
        if not a:
            log.error("unknown entity key %r (see telemetry/hunt)", key)
            return 2
        print(f"{key} — '{a['name']}'  score {a['score']}/100  "
              f"[{a['verdict'].upper()}]  first seen {a['first_seen']}")
        for s, txt, w in a["signals"]:
            print(f"  +{w:<4} {s:<14} {txt}")
        if not a["signals"]:
            print("  no signals of suspicion — that's a finding too")
        return 0

    if args.action == "compare":
        a, b = eng.analyze(hm.IT_MONITOR), eng.analyze("IMPLANT")
        for ent, title in ((a, "registered IT monitor"),
                           (b, "the unknown component")):
            print(f"\n■ {title}: score {ent['score']}/100 [{ent['verdict']}]")
            for s, txt, w in ent["signals"]:
                print(f"   {w:+d}  {s}: {txt}")
        print("\nsame host, same days. Provenance + stability vs mimicry + "
              "concealment — the two poles of 'monitoring'.")
        return 0

    if args.action == "alerts":
        for a2 in eng.alerts():
            print(f"  t={a2['t']:>4}  [{a2['kind']:<10}] {a2['text']}")
        print("\nthe 'normal → suspicious' transition is always a "
              "measurable transition — never a vibe.")
        return 0

    if args.action == "score":
        if not args.answers:
            log.error("score needs --answers answers.json (or '-' for stdin)")
            return 2
        raw = sys.stdin.read() if args.answers == "-" else \
            open(args.answers, encoding="utf-8").read()
        try:
            answers = _json.loads(raw)
        except _json.JSONDecodeError as exc:
            log.error("bad answer file: %s", exc)
            return 2
        r = hm.score_stealth(scen["truth"], answers)
        print(f"score: {r['score']}/100  (points {r['points']} of "
              f"{r['possible']})")
        for fb in r["feedback"]:
            print(f"  {fb}")
        return 0 if r["score"] >= 60 else 1

    # ----------------------------------------------------------------- web
    token = args.instructor_token or hm.new_token()
    db = args.db or "stealth_lab.sqlite"
    store = hm.DevLabStore(db)
    try:
        app = hm.StealthApp(scen, store, token)
        httpd = hm.make_stealth_server(args.bind, args.port, app)
    except OSError as exc:
        log.error("cannot bind %s:%s - %s", args.bind, args.port, exc)
        store.close()
        return 2
    host = "localhost" if args.bind in ("127.0.0.1", "::1") else args.bind
    base = f"http://{host}:{args.port}"
    print(f"student portal      : {base}/")
    print(f"instructor dashboard: {base}/i/{token}   (keep private)")
    print(f"scenario            : {args.dataset} "
          f"({scen['manifest']['ticks']} ticks, host "
          f"{scen['manifest']['host']})")
    if args.bind == "0.0.0.0":
        log.warning("web lab bound to all interfaces - classroom LANs only")
    print("\nGround truth never reaches the student pages; attempts are "
          "logged. Ctrl-C to stop.\n")
    if args.duration:
        import threading as _th
        _th.Timer(args.duration, httpd.shutdown).start()
    try:
        httpd.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        print("\nstopping the stealth lab...")
    finally:
        httpd.server_close()
    f = store.funnel("stealth")
    print(f"lab session: {f['views']} page views, {f['attempts']} quiz "
          f"attempts, best {f['best_score']}/100")
    store.close()
    return 0


def cmd_response_lab(args) -> int:
    """Automatic (offensive) response laboratory."""
    import json as _json
    from . import autoresp as ar

    if args.action == "cast":
        print_rows("Designated lab test devices",
                   [("device", "n"), ("MAC", "m"), ("role", "d")],
                   [dict(n=n, m=m, d=d) for n, m, d in
                    ar.ResponseWebApp.CAST])
        print("\nscope rule: policies refuse to act on anything else "
              "(`out-of-scope` in decide()).")
        return 0

    if args.action == "rules":
        print_rows("rulebook",
                   [("id", "rid"), ("kind", "kind"), ("rate", "rate"),
                    ("action", "action"), ("severity", "severity"),
                    ("why", "why")],
                   [dict(r, rate=f"{r['threshold']}/{r['window']}")
                    for r in ar.default_rules()])
        print("\nR6 ships DISABLED on purpose — enable it via "
              "`--enable-rule R6` and watch your own IT scanner burn unless "
              "it is allowlisted.")
        return 0

    if args.action == "exercises":
        print(ar.response_exercises())
        return 0

    if args.action == "simulate":
        lab = ar.ResponseLab(seed=args.seed, n_ticks=args.ticks)
        lab.mode = args.mode
        if args.clear_allowlist:
            lab.allowlist = set()
        for rid in args.enable_rule:
            lab.enabled_rules.add(rid)
        lab.run()
        m = lab.metrics()
        chain = [a for a in lab.audit if a["phase"] != "detect"
                 or "flood" in str(a.get("detail", ""))]
        interesting = [a for a in lab.audit if a["phase"] in
                       ("decision", "response", "result", "rollback")]
        print_rows(f"pipeline decisions (mode={args.mode})",
                   [("#", "t"), ("phase", "phase"), ("detail", "what")],
                   [dict(t=a["t"], phase=a["phase"],
                         what=ar._describe_audit(a)[:90])
                    for a in interesting][:60])
        print(f"\nmetrics: enforced={m['enforced_total']} "
              f"true+={m['true_positives']} false+={m['false_positives']} "
              f"neighbour-blocked={m['blocked_neighbor']} "
              f"audit-entries={m['audit_entries']}")
        if lab.firewall:
            print_rows("final lab firewall table",
                       [("MAC", "mac"), ("action", "action"),
                        ("rule", "rule"), ("tick", "tick")],
                       [dict(mac=k, **v) for k, v in lab.firewall.items()])
        if lab.pending:
            print(f"pending approvals: {[p['pending_id'] for p in lab.pending if not p.get('closed')]}")
        if m["false_positives"]:
            print("\n🚨 friendly fire! The allowlist or rule thresholds need "
                  "work — THAT exercise is the point of this lab.")
        return 0

    if args.action == "score":
        if not args.answers:
            log.error("score needs --answers answers.json (or '-' for stdin)")
            return 2
        raw = sys.stdin.read() if args.answers == "-" else \
            open(args.answers, encoding="utf-8").read()
        try:
            answers = _json.loads(raw)
        except _json.JSONDecodeError as exc:
            log.error("bad answer file: %s", exc)
            return 2
        r = ar.score_response_answers(answers)
        print(f"score: {r['score']}/100  (points {r['points']} of "
              f"{r['possible']})")
        for fb in r["feedback"]:
            print(f"  {fb}")
        return 0 if r["score"] >= 60 else 1

    # ----------------------------------------------------------------- web
    token = args.instructor_token or ar.new_token()
    db = args.db or "response_lab.sqlite"
    store = ar.DevLabStore(db)
    app = ar.ResponseWebApp(store, token, seed=args.seed,
                            n_ticks=args.ticks)
    try:
        httpd = ar.make_response_server(args.bind, args.port, app)
    except OSError as exc:
        log.error("cannot bind %s:%s - %s", args.bind, args.port, exc)
        store.close()
        return 2
    host = "localhost" if args.bind in ("127.0.0.1", "::1") else args.bind
    base = f"http://{host}:{args.port}"
    print(f"student portal      : {base}/")
    print(f"instructor console  : {base}/i/{token}   (keep private)")
    print(f"simulation          : seed {args.seed}, {args.ticks} ticks, "
          f"mode={app.lab.mode} (students cannot change it)")
    if args.bind == "0.0.0.0":
        log.warning("web lab bound to all interfaces - classroom LANs only")
    print("\nNothing real is ever blocked: the firewall is a table in "
          "this process. Ctrl-C to stop.\n")
    if args.duration:
        import threading as _th
        _th.Timer(args.duration, httpd.shutdown).start()
    try:
        httpd.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        print("\nstopping the response lab...")
    finally:
        httpd.server_close()
    f = store.funnel("response")
    print(f"lab session: {f['views']} page views, {f['attempts']} quiz "
          f"attempts, best {f['best_score']}/100")
    store.close()
    return 0


def cmd_scan_lab(args) -> int:
    """Large-scale scanning & scope-control laboratory."""
    import json as _json
    from . import scanlab as sl

    if args.action == "make-dataset":
        if not args.dataset:
            log.error("usage: wifiscanner scan-lab make-dataset DIR "
                      "[--seed N] [--size 300] [--fresh]")
            return 2
        meta = sl.generate_inventory(args.dataset, seed=args.seed,
                                     size=args.size, fresh=args.fresh)
        print(f"lab estate written: {args.dataset} ({meta['hosts']} assets, "
              f"{meta['online']} online, {meta['services']} services, "
              f"{meta['conflicts']} duplicate-IP conflicts to find)")
        print(f"  inventory.json  : shareable with students")
        print(f"  manifest.json   : lab metadata")
        print(f"\nothing leaves the subnet {sl.SUBNET}.* — and nothing "
              f"real is on it anyway.")
        return 0

    if args.action == "exercises":
        print(sl.scan_exercises())
        return 0

    if not args.dataset:
        log.error("this action needs a dataset DIR")
        return 2
    if not os.path.isdir(args.dataset):
        log.error("no such dataset: %s (build one: wifiscanner scan-lab "
                  "make-dataset %s)", args.dataset, args.dataset)
        return 2
    ds = sl.load_inventory(args.dataset)
    eng = sl.ScanLabEngine(ds)

    if args.action == "inventory":
        inv = eng.inv
        kinds = __import__("collections").Counter(a["kind"] for a in
                                                  inv["assets"])
        print(f"estate {inv['subnet']}.*: {len(inv['assets'])} assets — "
              + ", ".join(f"{n}×{k}" for k, n in kinds.most_common()))
        print(f"online: {sum(1 for a in inv['assets'] if a['online'])} · "
              f"service probes available: {', '.join(sl.SERVICES)}")
        print(f"duplicate-IP conflicts: {len(inv['duplicate_conflicts'])} "
              f"(find them!)")
        rows = [dict(ip=a["ip"], kind=a["kind"],
                     state="up" if a["online"] else "down",
                     services=",".join(a["services"])) for a in
                inv["assets"][:60]]
        print_rows("first 60 assets",
                   [("IP", "ip"), ("kind", "kind"), ("state", "state"),
                    ("services", "services")], rows)
        return 0

    if args.action == "scan":
        if not args.targets:
            log.error("scan needs --targets ip,ip,... (or '*' for the "
                      "registered estate)")
            return 2
        targets = [a["ip"] for a in eng.inv["assets"]] \
            if args.targets.strip() == "*" else \
            [t.strip() for t in args.targets.split(",") if t.strip()]
        svcs = [s.strip() for s in args.services.split(",")
                if s.strip()] or list(sl.SERVICES)
        job = eng.submit(targets, svcs, args.rate, args.concurrency,
                         by="cli")
        print(f"job {job.id} started: {len(targets)} targets × "
              f"{len(svcs)} services = {job.progress['total']} probes; "
              f"rate {args.rate or '∞'}/s, workers {args.concurrency}")
        while job.status in ("pending", "running"):
            p = eng.jobs[job.id].snapshot()
            print(f"\r  {p['done']:>6}/{p['total']:>6} probes · "
                  f"{p['hits']:>4} hits · {p['refused']} refused",
                  end="", flush=True)
            time.sleep(0.25)
        print()
        s = eng.jobs[job.id].snapshot()
        print(f"\nDONE [{s['status']}] {s['done']}/{s['total']} probes, "
              f"{s['hits']} hits, {s['refused']} refused, "
              f"{s['violations']} scope alerts, {s['duration_ms']} ms")
        if job.scope_violations:
            print_rows("scope violations (refused BEFORE probing)",
                       [("IP", "ip"), ("why", "why")],
                       job.scope_violations[:20])
            print("each one logged a sentinel alert. Intended exercise "
                  "behaviour — check with your instructor if you weren't "
                  "trying to breach.")
        rows = [dict(ip=r["ip"], kind=r["kind"], service=r["service"],
                     via=r["via"], lat=r["latency_ms"]) for r in
                job.results[:40]]
        print_rows("discoveries (first 40)",
                   [("IP", "ip"), ("kind", "kind"), ("service", "service"),
                    ("via", "via"), ("lat ms", "lat")], rows)
        return 0 if not job.scope_violations else 1

    if args.action == "compare":
        c = eng.compare_modes()
        print(f"inventoried: {c['inventoried_assets']} assets")
        print_rows("targeted vs uncontrolled",
                   [("metric", "m"), ("targeted", "t"),
                    ("uncontrolled", "u")],
                   [dict(m="targets", t=c["targeted"]["targets"],
                         u=c["uncontrolled"]["targets"]),
                    dict(m="probes", t=c["targeted"]["probes"],
                         u=c["uncontrolled"]["probes"]),
                    dict(m="scope violations",
                         t=c["targeted"]["scope_violations"],
                         u=c["uncontrolled"]["scope_violations"])])
        print(f"\n{c['moral']}")
        return 0

    if args.action == "score":
        if not args.answers:
            log.error("score needs --answers answers.json (or '-' for stdin)")
            return 2
        raw = sys.stdin.read() if args.answers == "-" else \
            open(args.answers, encoding="utf-8").read()
        try:
            answers = _json.loads(raw)
        except _json.JSONDecodeError as exc:
            log.error("bad answers: %s", exc)
            return 2
        r = sl.score_scanlab(eng.inv, answers)
        print(f"score: {r['score']}/100  ({r['points']} of {r['possible']})")
        for fb in r["feedback"]:
            print(f"  {fb}")
        return 0 if r["score"] >= 60 else 1

    # ----------------------------------------------------------------- web
    token = args.instructor_token or sl.new_token()
    db = args.db or "scan_lab.sqlite"
    store = sl.DevLabStore(db)
    try:
        app = sl.ScanWebApp(ds, store, token)
        httpd = sl.make_scan_server(args.bind, args.port, app)
    except OSError as exc:
        log.error("cannot bind %s:%s - %s", args.bind, args.port, exc)
        store.close()
        return 2
    host = "localhost" if args.bind in ("127.0.0.1", "::1") else args.bind
    base = f"http://{host}:{args.port}"
    print(f"student console     : {base}/console")
    print(f"instructor dashboard: {base}/i/{token}   (keep private)")
    print(f"estate              : {args.dataset} "
          f"({len(ds['inventory']['assets'])} assets on "
          f"{ds['inventory']['subnet']}.*)")
    if args.bind == "0.0.0.0":
        log.warning("web lab bound to all interfaces - classroom LANs only")
    print("\nall scans are simulated against the inventory — nothing "
          "touches a network. Ctrl-C to stop.\n")
    if args.duration:
        import threading as _th
        _th.Timer(args.duration, httpd.shutdown).start()
    try:
        httpd.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        print("\nstopping the scan lab...")
    finally:
        httpd.server_close()
    f = store.funnel("scan")
    print(f"lab session: {f['views']} page views, {f['attempts']} scored "
          f"attempts, best {f['best_score']}/100")
    store.close()
    return 0


def cmd_cred_lab(args) -> int:
    """Credential & session security analysis laboratory."""
    import json as _json
    from . import credlab as cr

    if args.action == "make-fixture":
        if not args.pcap:
            log.error("usage: wifiscanner cred-lab make-fixture lesson.pcap "
                      "[--seed 13] [--students 8]")
            return 2
        meta = cr.build_credential_fixture(args.pcap, seed=args.seed,
                                           students=args.students)
        print(f"lab capture written: {args.pcap} ({meta['frames']} frames)")
        print(f"  synthetic lab accounts: {len(meta['identities'])} "
              f"(LAB-STUDENT-01…; passwords like 'heron-5763-lab')")
        print(f"  legs: A = plaintext HTTP/FTP/Telnet/SNMPv1 · B = TLS")
        log.warning("keep the printed identities together with the "
                    "capture in instructor notes; both are synthetic")
        return 0

    if args.action == "exercises":
        print(cr.cred_exercises())
        return 0

    if not args.pcap:
        log.error("this action needs a capture file")
        return 2
    if not os.path.exists(args.pcap):
        log.error("no such capture: %s (make one: cred-lab make-fixture "
                  "lesson.pcap)", args.pcap)
        return 2
    analysis = cr.dissect_capture(args.pcap)

    if args.action == "dissect":
        st = analysis["stats"]
        print(f"{args.pcap}: {analysis['frames']} frames · tcp={st['tcp']} "
              f"udp={st['udp']} of which http={st['http']} ftp={st['ftp']} "
              f"telnet={st['telnet']} snmp={st['snmp']} tls={st['tls']}")
        print_rows("frame inventory",
                   [("bucket", "k"), ("frames", "v")],
                   [dict(k=k, v=v) for k, v in st.items()])
        print(f"\nexposure rows: {len(analysis['exposures'])} (leg A) · "
              f"TLS records: {len(analysis['tls'])} (leg B) — "
              f"`cred-lab exposures|tls` for detail")
        return 0

    if args.action == "exposures":
        rows = [dict(t=time.strftime("%H:%M:%S", time.localtime(e["when"])),
                     proto=e["proto"], field=e["field"], val=e["leaked"],
                     src=e["src"]) for e in analysis["exposures"][:120]]
        print_rows("what a passive watcher steals (leg A)",
                   [("time", "t"), ("proto", "proto"), ("field", "field"),
                    ("value", "val"), ("src", "src")], rows)
        print("\nbase64 is encoding; cookies are bearer instruments; "
              "telnet is keystroke radio.")
        return 0

    if args.action == "tls":
        rows = [dict(t=time.strftime("%H:%M:%S", time.localtime(r["when"])),
                     kind=r["kind"], size=r["size"], readable=r["readable"])
                for r in analysis["tls"][:80]]
        print_rows("leg B (TLS) — same work, no leaks",
                   [("time", "t"), ("kind", "kind"), ("bytes", "size"),
                    ("readable", "readable")], rows)
        return 0

    if args.action == "alerts":
        al = cr.insecure_alerts(analysis["exposures"])
        print_rows("insecure-auth alerts raised",
                   [("proto", "proto"), ("count", "count"), ("msg", "msg")],
                   al)
        return 0 if not al else 0

    if args.action == "compare":
        print_rows("leg A — what the watcher steals",
                   [("proto", "proto"), ("leaks", "leaks"),
                    ("what", "steal"), ("risk", "risk")],
                   cr.exposure_summary(analysis["exposures"]))
        t = cr.protection_summary(analysis["tls"])
        print(f"\nleg B: {t['encrypted']} opaque app records + "
              f"{t['handshake_records']} handshakes; visible: {t['visible']}")
        print(f"gone: {t['invisible']}")
        return 0

    if args.action == "report":
        out = args.output or "credlab_report"
        os.makedirs(out, exist_ok=True)
        paths = []
        # CSVs
        import csv as _csv
        p1 = os.path.join(out, "credlab_exposures.csv")
        with open(p1, "w", newline="") as fh:
            w = _csv.DictWriter(fh, fieldnames=["when", "proto", "line",
                                                "field", "leaked", "src",
                                                "dst"])
            w.writeheader()
            w.writerows(analysis["exposures"])
        paths.append(p1)
        p2 = os.path.join(out, "credlab_tls.csv")
        with open(p2, "w", newline="") as fh:
            w = _csv.DictWriter(fh, fieldnames=["when", "kind", "size",
                                                "src", "dst", "readable"])
            w.writeheader()
            w.writerows(analysis["tls"])
        paths.append(p2)
        p3 = os.path.join(out, "credlab_report.md")
        sums = cr.exposure_summary(analysis["exposures"])
        al = cr.insecure_alerts(analysis["exposures"])
        with open(p3, "w") as fh:
            fh.write(f"# Credential security lab report\n"
                     f"capture: `{args.pcap}` · {analysis['frames']} frames\n"
                     f"\n## leg A exposures ({len(analysis['exposures'])})\n")
            for s in sums:
                fh.write(f"- **{s['proto']}**: {s['leaks']} leaks — "
                         f"{s['steal']} → {s['risk']}\n")
            fh.write(f"\n## insecure-auth alerts ({len(al)})\n")
            for a in al:
                fh.write(f"- {a['msg']}\n")
            fh.write(f"\n## leg B (TLS)\n{cr.protection_summary(analysis['tls'])['note']}\n")
        paths.append(p3)
        for p in paths:
            print(f"  -> {p}")
        return 0

    if args.action == "score":
        if not args.answers:
            log.error("score needs --answers answers.json (or '-' for stdin)")
            return 2
        raw = sys.stdin.read() if args.answers == "-" else \
            open(args.answers, encoding="utf-8").read()
        try:
            answers = _json.loads(raw)
        except _json.JSONDecodeError as exc:
            log.error("bad answers: %s", exc)
            return 2
        r = cr.score_credlab(answers)
        print(f"score: {r['score']}/100  ({r['points']} of {r['possible']})")
        for fb in r["feedback"]:
            print(f"  {fb}")
        return 0 if r["score"] >= 60 else 1

    # ----------------------------------------------------------------- web
    token = args.instructor_token or cr.new_token()
    db = args.db or "cred_lab.sqlite"
    store = cr.DevLabStore(db)
    import random as _r
    ids = cr._mk_identities(_r.Random(args.seed), args.students)
    try:
        app = cr.CredWebApp(args.pcap, ids, store, token)
        httpd = cr.make_cred_server(args.bind, args.port, app)
    except OSError as exc:
        log.error("cannot bind %s:%s - %s", args.bind, args.port, exc)
        store.close()
        return 2
    host = "localhost" if args.bind in ("127.0.0.1", "::1") else args.bind
    base = f"http://{host}:{args.port}"
    print(f"student portal      : {base}/")
    print(f"instructor dashboard: {base}/i/{token}   (keep private)")
    print(f"capture             : {args.pcap} ({analysis['frames']} frames; "
          f"{len(analysis['exposures'])} exposure rows)")
    if args.bind == "0.0.0.0":
        log.warning("web lab bound to all interfaces - classroom LANs only")
    print("\nall identities are synthetic (LAB-STUDENT-*). Ctrl-C to stop.\n")
    if args.duration:
        import threading as _th
        _th.Timer(args.duration, httpd.shutdown).start()
    try:
        httpd.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        print("\nstopping the credential lab...")
    finally:
        httpd.server_close()
    f = store.funnel("cred")
    print(f"lab session: {f['views']} page views, {f['attempts']} quiz "
          f"attempts, best {f['best_score']}/100")
    store.close()
    return 0



def cmd_priv_lab(args) -> int:
    from . import privlab as P
    if args.action == "make-dataset":
        out = args.data or args.db
        if not out:
            print("priv-lab make-dataset needs a DIR")
            return 2
        P.cmd_make_dataset(out, seed=args.seed, devices=args.devices,
                           days=args.days, fresh=args.fresh)
        return 0
    db = args.db or args.data or "privlab_data"
    if args.action == "inventory":
        P.cmd_inventory(db); return 0
    if args.action == "correlate":
        return P.cmd_correlate(db, target=args.target)
    if args.action == "compare":
        return P.cmd_compare(db)
    if args.action == "exercises":
        return P.cmd_exercises(db)
    if args.action == "score":
        if not args.answers:
            print("priv-lab score needs --answers JSON|-"); return 2
        return P.cmd_score(db, args.answers)
    if args.action == "web":
        P.cmd_inventory(db)
        ds = P.load_dataset(db)
        store = P.DevLabStore(args.db if args.db and
                              args.db.endswith(".sqlite") else ":memory:"
                              if args.db == ":memory:" else
                              (args.db + ".sqlite" if args.db else
                               "priv_lab.sqlite"))
        if args.instructor_token:
            tok = args.instructor_token
        else:
            tok = P.new_token()
        print(f"instructor: /i/{tok}")
        app = P.PrivLabApp(ds, store, tok)
        srv = P.make_priv_server(args.bind, args.port, app)
        log.warning("web lab bound to %s:%s — classroom LANs only",
                    args.bind, args.port)
        if args.duration:
            import threading as _th
            _th.Timer(args.duration, srv.shutdown).start()
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            pass
        return 0
    return 2


def cmd_rf_lab(args) -> int:
    from . import rflab as R
    if args.action == "baseline":
        R.cmd_baseline(args.seed); return 0
    if args.action == "inject":
        R.cmd_inject(args.seed, args.interferer, args.intensity,
                     args.ticks); return 0
    if args.action == "compare":
        return R.cmd_compare(args.seed, args.interferer, args.intensity)
    if args.action == "investigate":
        R.cmd_investigate(args.seed, args.interferer, args.intensity)
        return 0
    if args.action == "resilience":
        return R.cmd_resilience(args.seed, args.ap, args.channel,
                                args.interferer, args.intensity)
    if args.action == "exercises":
        return R.cmd_exercises()
    if args.action == "score":
        if not args.answers:
            print("rf-lab score needs --answers JSON|-"); return 2
        return R.cmd_score(args.answers)
    if args.action == "web":
        sess = R.InterferenceSession(args.seed)
        store = R.DevLabStore(args.db or ":memory:")
        tok = args.instructor_token or R.new_token()
        print(f"instructor: /i/{tok}")
        app = R.RFLabApp(sess, store, tok)
        srv = R.make_rf_server(args.bind, args.port, app)
        log.warning("web lab bound to %s:%s — classroom LANs only",
                    args.bind, args.port)
        if args.duration:
            import threading as _th
            _th.Timer(args.duration, srv.shutdown).start()
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            pass
        return 0
    return 2


def cmd_handshake_lab(args) -> int:
    from . import hsaudit as H
    if args.action == "make-dataset":
        out = args.data or args.db
        if not out:
            print("handshake-lab make-dataset needs a DIR")
            return 2
        H.cmd_make_dataset(out, seed=args.seed, fresh=args.fresh)
        return 0
    db = args.db or args.data or "handshake_lab_data"
    if args.action == "inventory":
        H.cmd_inventory(db); return 0
    if args.action == "analyze":
        return H.cmd_analyze(db, args.tier)
    if args.action == "audit":
        return H.cmd_audit(db, args.tier, quiet=args.quiet)
    if args.action == "compare":
        return H.cmd_compare(db)
    if args.action == "authenticate":
        pw = args.password
        if not pw:
            print("handshake-lab authenticate needs --password "
                  "(alleged credential, post-audit)")
            return 2
        return H.cmd_authenticate(db, args.tier, pw)
    if args.action == "exercises":
        return H.cmd_exercises()
    if args.action == "score":
        if not args.answers:
            print("handshake-lab score needs --answers JSON|-")
            return 2
        return H.cmd_score(args.answers)
    if args.action == "web":
        import os as _os
        from .devlab import DevLabStore
        ds = H.load_dataset(db)
        sq = args.db if args.db.endswith(".sqlite") else             (_os.path.join(db, "hs_lab.sqlite"))
        store = DevLabStore(sq)
        tok = args.instructor_token or H.new_token()
        print(f"instructor: /i/{tok}")
        app = H.HsLabApp(ds, store, tok)
        srv = H.make_hs_server(args.bind, args.port, app)
        log.warning("web lab bound to %s:%s — classroom LANs only",
                    args.bind, args.port)
        if args.duration:
            import threading as _th
            _th.Timer(args.duration, srv.shutdown).start()
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            pass
        return 0
    return 2


def cmd_interfaces(args) -> int:
    ifaces = survey.list_interfaces()
    print(f"platform      : {os_name()}")
    print(f"root/admin    : {is_root()}")
    print(f"backends      : {', '.join(survey.available_backends()) or 'none'}")
    print(f"scapy         : {'yes' if sniffer.scapy_available() else 'no (pip install scapy)'}")
    print(f"OUI database  : {db_size()} vendor prefixes")
    print(f"\nwireless interfaces ({len(ifaces)}):")
    for i in ifaces:
        extra = " ".join(f"{k}={v}" for k, v in i.items() if k != "name")
        print(f"  - {i['name']:<12} {extra}")
    if not ifaces:
        print("  (none detected)")
    return 0


# --------------------------------------------------------------------- main

def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    setup_logging(args.verbose, args.quiet)
    if not args.no_banner and not args.quiet:
        print_banner()
        if _RICH:
            console.print(f"[dim]{LEGAL}[/]\n")
        else:
            print(LEGAL + "\n")
    fn = {"scan": cmd_scan, "monitor": cmd_monitor, "full": cmd_full,
          "detail": cmd_detail, "devices": cmd_devices, "watch": cmd_watch,
          "offline": cmd_offline, "interfaces": cmd_interfaces,
          "own": cmd_own, "record": cmd_record, "presence": cmd_presence,
          "locate": cmd_locate, "trail": cmd_trail, "capture": cmd_capture,
          "traffic": cmd_traffic, "ids": cmd_ids, "audit": cmd_audit,
          "frames": cmd_frames, "inject": cmd_inject, "db": cmd_db,
          "lab": cmd_lab, "wpa-lab": cmd_wpa_lab,
          "mac-lab": cmd_mac_lab, "track-lab": cmd_track_lab,
          "stealth-lab": cmd_stealth_lab,
          "response-lab": cmd_response_lab,
          "scan-lab": cmd_scan_lab, "cred-lab": cmd_cred_lab,
    "priv-lab": cmd_priv_lab, "rf-lab": cmd_rf_lab,
    "handshake-lab": cmd_handshake_lab, "research-ui": cmd_research_ui}[args.cmd]
    try:
        return fn(args)
    except KeyboardInterrupt:
        print("\ninterrupted.")
        return 130
    except PermissionError as exc:
        log.error("%s", exc)
        return 13
    except Exception as exc:
        log.error("fatal: %s", exc)
        if args.verbose:
            raise
        return 1


if __name__ == "__main__":
    sys.exit(main())
