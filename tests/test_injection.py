"""Tests for the defensive, consent-gated packet-injection module.

These tests never transmit: every live path is exercised through dry runs
(no radio) or offline synthesis. The point of the suite is to prove BOTH that
the defensive functionality works AND that the safety gates refuse abuse.
Run:  python -m pytest tests/test_injection.py -v
"""
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from wifiscanner import inject as ij


# ------------------------------------------------------------ frame builders

def test_probe_request_is_well_formed():
    pkt = ij.build_probe_request("0A:1B:2C:3D:4E:5F", ssid="MyNet")
    from scapy.all import Dot11
    d = pkt.getlayer(Dot11)
    assert d.type == 0 and d.subtype == 4           # management, probe request
    assert ij.normalize(d.addr2) == "0A:1B:2C:3D:4E:5F"
    assert ij.normalize(d.addr1) == "FF:FF:FF:FF:FF:FF"   # broadcast destination
    assert ij._elt_ssid(pkt) == "MyNet"
    # wildcard probe carries an empty SSID
    wild = ij.build_probe_request("0A:1B:2C:3D:4E:5F")
    assert ij._elt_ssid(wild) == ""


def test_canary_token_roundtrip_in_frame():
    token = ij.new_canary_token()
    assert token.startswith(ij.CANARY_PREFIX)
    pkt = ij.build_probe_request("0A:1B:2C:3D:4E:5F", ssid=token)
    assert ij._elt_ssid(pkt) == token


def test_deauth_frame_addrs_and_reason():
    pkt = ij.build_deauth("AA:BB:CC:DD:EE:FF", "AC:BC:32:01:02:03")
    from scapy.all import Dot11
    from scapy.layers.dot11 import Dot11Deauth
    d = pkt.getlayer(Dot11)
    assert d.type == 0 and d.subtype == ij.SUBTYPE_DEAUTH == 12
    assert ij.normalize(d.addr1) == "AC:BC:32:01:02:03"   # unicast victim only
    assert ij.normalize(d.addr2) == "AA:BB:CC:DD:EE:FF"
    assert pkt.getlayer(Dot11Deauth).reason == ij.DEAUTH_REASON


def test_disassoc_frame_is_subtype_10():
    from scapy.all import Dot11
    from scapy.layers.dot11 import Dot11Disas
    pkt = ij.build_disassoc("AA:BB:CC:DD:EE:FF", "AC:BC:32:01:02:03")
    d = pkt.getlayer(Dot11)
    assert d.type == 0 and d.subtype == ij.SUBTYPE_DISASSOC == 10
    assert pkt.getlayer(Dot11Disas).reason == ij.DISASOC_REASON
    assert ij.normalize(d.addr1) == "AC:BC:32:01:02:03"
    # sta-to-ap direction flips the addresses
    pkt2 = ij.build_disassoc("AA:BB:CC:DD:EE:FF", "AC:BC:32:01:02:03",
                             direction="sta-to-ap")
    d2 = pkt2.getlayer(Dot11)
    assert ij.normalize(d2.addr1) == "AA:BB:CC:DD:EE:FF"
    assert ij.normalize(d2.addr2) == "AC:BC:32:01:02:03"


def test_frame_summary_names_disassoc_and_deauth():
    da = ij.frame_summary(ij.build_deauth("AA:BB:CC:DD:EE:FF", "AC:BC:32:01:02:03"))
    di = ij.frame_summary(ij.build_disassoc("AA:BB:CC:DD:EE:FF", "AC:BC:32:01:02:03"))
    assert da.startswith("deauth") and di.startswith("disassoc")


def test_kick_burst_alternates_both_types():
    with tempfile.TemporaryDirectory() as td:
        audit = ij.AuditLog(os.path.join(td, "a.csv"))
        inj = ij.Injector("wlan0", mode="deauth", dry_run=True, audit=audit)
        inj.kick_burst("AA:BB:CC:DD:EE:FF", "AC:BC:32:01:02:03", 4,
                       frame_type="both", direction="ap-to-sta")
        frames = [r["frame"] for r in audit.rows]
        assert frames == ["deauth", "disassoc", "deauth", "disassoc"]
        assert inj.sent == 0 and inj.built == 4
        audit.close()


def test_deauth_count_hard_capped():
    # deauth mode allows a larger one-shot test burst than the tiny pmf-test
    # probe, but is still hard-capped so a single run can never be a DoS.
    assert ij.clamp_count("deauth", 9999) == ij.MAX_KICK_BURST
    assert ij.clamp_count("deauth", 9999) <= 60
    assert ij.clamp_count("pmf-test", 9999) == ij.MAX_DEAUTH_BURST == 4


def test_random_local_mac_is_unicast_and_locally_administered():
    for _ in range(20):
        mac = ij.random_local_mac()
        first = int(mac[:2], 16)
        assert first & 0x01 == 0                      # unicast (I/G clear)
        assert first & 0x02 == 0x02                   # locally administered
        assert not ij.is_multicast(mac)


# ------------------------------------------------------- evil-twin beacon

def test_build_beacon_is_beacon_only_with_correct_ie():
    from scapy.all import Dot11
    from scapy.layers.dot11 import Dot11Beacon, Dot11Elt
    pkt = ij.build_beacon("02:11:22:33:44:55", "HomeFiber", 6, "open")
    d = pkt.getlayer(Dot11)
    assert d.type == 0 and d.subtype == 8
    assert ij.normalize(d.addr1) == "FF:FF:FF:FF:FF:FF"   # broadcast
    assert ij._elt_ssid(pkt) == "HomeFiber"
    assert pkt.haslayer(Dot11Beacon)
    # open clone advertises NO RSN and no privacy bit
    elts = pkt.getlayer(Dot11Elt)
    ids = []
    while elts is not None:
        ids.append(elts.ID)
        elts = elts.payload.getlayer(Dot11Elt)
    assert 48 not in ids                     # no RSN for open
    w2 = ij.build_beacon("02:66:77:88:99:AA", "HomeFiber", 11, "wpa2")
    w2d = w2.getlayer(Dot11Beacon)
    assert int(w2d.cap) & 0x10               # privacy bit set for WPA2
    # beacon-only: a beacon frame, with NO auth/assoc/response layer that a
    # client could complete a connection through
    from scapy.layers.dot11 import (Dot11AssoReq, Dot11AssoResp, Dot11Auth)
    for cls in (Dot11AssoReq, Dot11AssoResp, Dot11Auth):
        assert not pkt.haslayer(cls)
        assert not w2.haslayer(cls)


def test_validate_twin_refuses_blank_and_bad_security():
    try:
        ij.validate_twin("", 6, "open")
        assert False
    except ij.InjectionError:
        pass
    try:
        ij.validate_twin("HomeFiber", 6, "wpa3-clone")
        assert False
    except ij.InjectionError:
        pass
    try:
        ij.validate_twin("HomeFiber", 6, "open", bssid="FF:FF:FF:FF:FF:FF")
        assert False
    except ij.InjectionError:
        pass
    ssid, ch, sec, bssid = ij.validate_twin("HomeFiber", 6, "open")
    assert ssid == "HomeFiber" and ch == 6 and sec == "open"
    assert bssid and not ij.is_multicast(bssid)     # default random LAA
    # explicit bssid honoured
    _, _, _, b2 = ij.validate_twin("HomeFiber", 11, "wpa2", "AA:BB:CC:00:00:01")
    assert b2 == "AA:BB:CC:00:00:01"


def test_gate_evil_twin_requires_yes():
    try:
        ij.gate_transmission("evil-twin", transmit=True, authorized=True,
                             confirmed=False, _root=True)
        assert False
    except ij.InjectionError as exc:
        assert "--yes" in str(exc) and "beacon-only" in str(exc)
    ij.gate_transmission("evil-twin", transmit=True, authorized=True,
                         confirmed=True, _root=True)


def test_twin_duration_capped():
    assert ij.clamp_twin_duration(9999) == ij.MAX_TWIN_DURATION_S
    assert ij.clamp_twin_duration(10) == 10.0


def test_twin_beacons_dry_run_sends_none_and_live_is_bounded():
    import scapy.all as sc
    with tempfile.TemporaryDirectory() as td:
        audit = ij.AuditLog(os.path.join(td, "a.csv"))
        # dry run
        inj = ij.Injector("wlan0", mode="evil-twin", dry_run=True, audit=audit)
        n = inj.twin_beacons("HomeFiber", "02:11:22:33:44:55", 6, "open", 5.0)
        assert n == 1 and inj.sent == 0
        # live (mocked sendp) must self-terminate and stay under the cap
        sent = []
        orig = sc.sendp
        sc.sendp = lambda pkt, **k: sent.append(pkt)
        try:
            inj2 = ij.Injector("wlan0", mode="evil-twin", dry_run=False,
                               audit=audit, interval=ij.BEACON_INTERVAL_S)
            n2 = inj2.twin_beacons("HomeFiber", "02:11:22:33:44:55", 6, "open",
                                   2.0)
        finally:
            sc.sendp = orig
            audit.close()
        assert len(sent) == n2
        assert 0 < n2 <= ij.MAX_TWIN_BEACONS
        assert inj2.sent == n2
        # every frame is a beacon, never assoc/auth/data
        from scapy.all import Dot11
        assert all(p.getlayer(Dot11).subtype == 8 for p in sent)


def test_evil_twin_clone_is_detected_as_rogue_and_warden():
    """The beacon-only drill must trip BOTH detectors, with no serving AP."""
    from wifiscanner.engine import Engine
    from wifiscanner.models import AccessPoint
    from wifiscanner.defense import Watchdog
    clone = ij.build_beacon("02:11:22:33:44:55", "HomeFiber", 6, "open")
    sn = __import__("wifiscanner.backends.sniffer", fromlist=["MonitorSniffer"]).MonitorSniffer(iface="offline")
    sn._handle(clone)
    eng = Engine()
    eng.ingest([AccessPoint(bssid="F0:9F:C2:11:22:33", ssid="HomeFiber",
                            vendor="Ubiquiti", security=["WPA2"], channel=6,
                            frequency=2437, rssi=-50)])
    eng.ingest(sn.results())
    rogues = eng.rogue_candidates(known_bssids={"F0:9F:C2:11:22:33"})
    assert any(r["verdict"] == "likely-rogue" and "open-clone" in r["indicators"]
               for r in rogues)
    wd = Watchdog(window_s=60, cooldown_s=0,
                  known_bssids={"F0:9F:C2:11:22:33"})
    wd.feed(clone)
    assert "unknown-bss" in {a.kind for a in wd.alerts}


# ------------------------------------------------------------------ gating

def test_gate_dry_run_needs_nothing():
    # dry run: never raises, even without root / flags
    ij.gate_transmission("probe", transmit=False, authorized=False,
                         _root=False)


def test_gate_requires_authorization():
    try:
        ij.gate_transmission("canary", transmit=True, authorized=False,
                             _root=True)
        assert False, "must refuse without --authorized"
    except ij.InjectionError as exc:
        assert "--authorized" in str(exc)


def test_gate_requires_root():
    try:
        ij.gate_transmission("probe", transmit=True, authorized=True,
                             _root=False)
        assert False, "must refuse without root"
    except ij.InjectionError as exc:
        assert "root" in str(exc)


def test_gate_pmf_test_requires_yes():
    # authorized + root but pmf-test missing --yes -> refuse
    try:
        ij.gate_transmission("pmf-test", transmit=True, authorized=True,
                             confirmed=False, _root=True)
        assert False, "pmf-test must require --yes"
    except ij.InjectionError as exc:
        assert "--yes" in str(exc)
    # and with --yes it passes
    ij.gate_transmission("pmf-test", transmit=True, authorized=True,
                         confirmed=True, _root=True)


def test_pmf_targets_reject_broadcast_and_missing():
    for bad in ((ij.BROADCAST, "AC:BC:32:01:02:03"),     # broadcast BSSID
                ("AA:BB:CC:DD:EE:FF", ij.BROADCAST),     # broadcast client
                ("", "AC:BC:32:01:02:03"),               # missing bssid
                ("AA:BB:CC:DD:EE:FF", "")):              # missing client
        try:
            ij.validate_pmf_targets(*bad)
            assert False, f"must refuse {bad}"
        except ij.InjectionError:
            pass
    b, c = ij.validate_pmf_targets("aa:bb:cc:dd:ee:ff", "ac:bc:32:01:02:03")
    assert b == "AA:BB:CC:DD:EE:FF" and c == "AC:BC:32:01:02:03"


def test_count_hard_caps():
    assert ij.clamp_count("pmf-test", 999) == ij.MAX_DEAUTH_BURST
    assert ij.clamp_count("pmf-test", 999) < 5          # below IDS flood n=5
    assert ij.clamp_count("probe", 999) == ij.MAX_PROBE_PER_CHANNEL
    assert ij.clamp_count("canary", 999) == ij.MAX_CANARY_PER_CHANNEL
    assert ij.clamp_count("probe", 0) == 1


def test_parse_channels():
    assert ij.parse_channels("1, 6 ,11") == [1, 6, 11]
    assert ij.parse_channels("") == [1, 6, 11]
    assert ij.parse_channels("6,6,6") == [6]


# ------------------------------------------------------------- dry-run TX path

def test_dry_run_emits_zero_frames_and_logs():
    with tempfile.TemporaryDirectory() as td:
        audit = ij.AuditLog(os.path.join(td, "audit.csv"))
        inj = ij.Injector("wlan0", mode="canary", dry_run=True, audit=audit)
        sent = [0]
        # patch sendp so a real transmit would be caught
        import scapy.all as sc
        orig = sc.sendp
        sc.sendp = lambda *a, **k: sent.__setitem__(0, sent[0] + 1)
        try:
            inj.canary_sweep([1, 6], "WIFISCANNER-CANARY-ABCDEF",
                             ij.clamp_count("canary", 2))
        finally:
            sc.sendp = orig
            audit.close()
        assert sent[0] == 0                            # nothing hit the radio
        assert inj.sent == 0 and inj.built == 4
        assert len(audit.rows) == 4
        assert all(r["dry_run"] == 1 and r["tx"] == 0 for r in audit.rows)
        assert os.stat(os.path.join(td, "audit.csv")).st_mode & 0o077 == 0


def test_frame_summary_describes_builders():
    assert "probe-request" in ij.frame_summary(
        ij.build_probe_request("0A:1B:2C:3D:4E:5F", "X"))
    assert "deauth" in ij.frame_summary(
        ij.build_deauth("AA:BB:CC:DD:EE:FF", "AC:BC:32:01:02:03"))


# ------------------------------------------------------------- PMF verdict

def _ev(kind, src, dst, bssid, ts):
    return ij.AirEvent(ts, kind, src, dst, bssid)


def test_pmf_verdict_pass_when_client_stays():
    ap, cli = "AA:BB:CC:DD:EE:FF", "AC:BC:32:01:02:03"
    events = [_ev("data", cli, ap, ap, 10.0),
              _ev("deauth", ap, cli, ap, 12.0),
              _ev("data", cli, ap, ap, 13.0),
              _ev("data", ap, cli, ap, 14.0)]
    rep = ij.pmf_verdict(events, ap, cli, burst_ts=12.0)
    assert rep["verdict"] == "pass" and rep["pmf_protected"] is True


def test_pmf_verdict_fail_when_client_reassociates():
    ap, cli = "AA:BB:CC:DD:EE:FF", "AC:BC:32:01:02:03"
    events = [_ev("data", cli, ap, ap, 10.0),
              _ev("deauth", ap, cli, ap, 12.0),
              _ev("assoc", cli, ap, ap, 13.0),
              _ev("eapol", cli, ap, ap, 13.5)]
    rep = ij.pmf_verdict(events, ap, cli, burst_ts=12.0)
    assert rep["verdict"] == "fail" and rep["pmf_protected"] is False
    assert "PMF" in rep["detail"]


def test_kick_verdict_counts_disassoc_as_kick():
    ap, cli = "AA:BB:CC:DD:EE:FF", "AC:BC:32:01:02:03"
    # a disassociation-only burst that still kicks the client
    events = [_ev("data", cli, ap, ap, 10.0),
              _ev("disassoc", ap, cli, ap, 12.0),
              _ev("assoc", cli, ap, ap, 13.0)]
    rep = ij.kick_verdict(events, ap, cli, burst_ts=12.0)
    assert rep["verdict"] == "fail"
    assert rep["disassocs_observed"] >= 1 and rep["deauths_observed"] == 0
    assert rep["kicks_observed"] == rep["disassocs_observed"]


def test_kick_verdict_pass_on_disassoc_when_client_stays():
    ap, cli = "AA:BB:CC:DD:EE:FF", "AC:BC:32:01:02:03"
    events = [_ev("data", cli, ap, ap, 10.0),
              _ev("disassoc", ap, cli, ap, 12.0),
              _ev("data", cli, ap, ap, 13.0)]
    rep = ij.kick_verdict(events, ap, cli, burst_ts=12.0)
    assert rep["verdict"] == "pass" and rep["pmf_protected"] is True


def test_pmf_verdict_inconclusive_when_idle():
    ap, cli = "AA:BB:CC:DD:EE:FF", "AC:BC:32:01:02:03"
    rep = ij.pmf_verdict([], ap, cli, burst_ts=12.0)
    assert rep["verdict"] == "inconclusive" and rep["pmf_protected"] is None


# ---------------------------------------------------------- canary detection

def test_canary_results_matches_token_or_src():
    token = "WIFISCANNER-CANARY-010203"
    src = "0A:1B:2C:3D:4E:5F"
    events = [ij.AirEvent(1.0, "probe", src, "ff:ff:ff:ff:ff:ff",
                          "ff:ff:ff:ff:ff:ff", -42, token),
              ij.AirEvent(2.0, "beacon", "AA:BB:CC:DD:EE:FF",
                          "ff:ff:ff:ff:ff:ff", "AA:BB:CC:DD:EE:FF", -70, "Net")]
    rep = ij.canary_results(events, src, token)
    assert rep["heard"] == 1 and rep["rssi_dbm"] == -42


# ---------------------------------------------------------- IDS self-test

def test_ids_selftest_all_signatures_detected():
    rep = ij.run_ids_selftest()
    assert rep["total"] == 5              # deauth + disassoc + reauth + beacon + warden
    assert rep["passed"] == 5, [(r["scenario"], r["missing"])
                                for r in rep["rows"] if r["status"] != "PASS"]
    for r in rep["rows"]:
        assert r["status"] == "PASS" and r["missing"] == ""
    assert any("disassociation" in r["scenario"] for r in rep["rows"])


def test_ids_detects_disassoc_and_ignores_auth_subtype():
    """Regression: disassoc is subtype 10, auth is 11 (not a kick)."""
    from scapy.all import RadioTap, Dot11
    from scapy.layers.dot11 import Dot11Disas, Dot11Auth
    from wifiscanner.defense import Watchdog
    ap, sta = "F0:9F:C2:11:22:34", "AC:BC:32:01:02:99"

    def disas():
        return (RadioTap() / Dot11(type=0, subtype=10, addr1=sta, addr2=ap,
                                   addr3=ap) / Dot11Disas(reason=8))

    def auth():
        return (RadioTap() / Dot11(type=0, subtype=11, addr1=ap, addr2=sta,
                                   addr3=ap) / Dot11Auth())

    wd = Watchdog(window_s=60, flood_frames=5, cooldown_s=0,
                  known_bssids={ap})
    for _ in range(6):
        wd.feed(disas())
    assert any(a.kind == "deauth-flood" for a in wd.alerts), \
        "disassociation flood must be detected"

    wd2 = Watchdog(window_s=60, flood_frames=5, cooldown_s=0)
    for _ in range(30):
        wd2.feed(auth())     # subtype 11 = authentication, NOT a kick
    assert not any(a.kind == "deauth-flood" for a in wd2.alerts), \
        "authentication frames must not be miscounted as deauths"


def test_ids_selftest_writes_pcap_capable_of_feeding_ids():
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "canary.pcap")
        rep = ij.run_ids_selftest(write_pcap=path)
        assert os.path.exists(path)
        assert os.stat(path).st_mode & 0o077 == 0      # owner-only
        from scapy.all import rdpcap
        frames = rdpcap(path)
        assert len(frames) == rep["frames"]
        # the offline pcap must actually trigger the IDS (with the same
        # known-good baseline the selftest used)
        from wifiscanner.defense import Watchdog
        wd = Watchdog(window_s=60, cooldown_s=0,
                      known_bssids={rep["own_bssid"]})
        for f in frames:
            wd.feed(f)
        kinds = {a.kind for a in wd.alerts}
        assert "deauth-flood" in kinds and "unknown-bss" in kinds


# ---------------------------------------------------------------- CLI guardrails

def test_cli_inject_help():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for args in (["inject", "--help"],):
        p = subprocess.run([sys.executable, "main.py"] + args, cwd=root,
                           capture_output=True, text=True, timeout=60)
        assert p.returncode == 0 and "dry run" in p.stdout.lower()


def test_cli_ids_selftest_exit_zero_and_runs():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with tempfile.TemporaryDirectory() as td:
        p = subprocess.run([sys.executable, "main.py", "--no-banner", "-q",
                            "inject", "--mode", "ids-selftest", "-o", td],
                           cwd=root, capture_output=True, text=True, timeout=120)
        assert p.returncode == 0, p.stderr
        assert "5/5" in p.stdout and "PASS" in p.stdout
        assert os.path.exists(os.path.join(td, "ids_selftest.pcap"))


def test_cli_dry_run_transmits_nothing_writes_audit():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with tempfile.TemporaryDirectory() as td:
        p = subprocess.run([sys.executable, "main.py", "--no-banner", "-q",
                            "inject", "--mode", "canary", "-i", "wlan0",
                            "--channels", "1,6,11", "--count", "1", "-o", td],
                           cwd=root, capture_output=True, text=True, timeout=60)
        assert p.returncode == 0, p.stderr
        assert "DRY RUN" in p.stdout and "transmitted: 0" in p.stdout
        assert os.path.exists(os.path.join(td, "injection_audit.csv"))
        # no pcap should be written in a dry run
        assert not os.path.exists(os.path.join(td, "canary.pcap"))


def test_cli_transmit_without_authorization_refused():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    p = subprocess.run([sys.executable, "main.py", "--no-banner", "-q",
                        "inject", "--mode", "canary", "-i", "wlan0",
                        "--transmit", "-o", "/tmp/inj-refuse"],
                       cwd=root, capture_output=True, text=True, timeout=60)
    assert p.returncode == 2
    assert "--authorized" in (p.stderr + p.stdout)


def test_cli_pmf_broadcast_target_refused():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    p = subprocess.run([sys.executable, "main.py", "--no-banner", "-q",
                        "inject", "--mode", "pmf-test", "-i", "wlan0",
                        "--bssid", "AA:BB:CC:DD:EE:FF",
                        "--client", "FF:FF:FF:FF:FF:FF", "-o", "/tmp/inj-ref2"],
                       cwd=root, capture_output=True, text=True, timeout=60)
    assert p.returncode == 2
    assert "broadcast" in (p.stderr + p.stdout).lower()


def test_cli_pmf_requires_yes_even_when_authorized():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    p = subprocess.run([sys.executable, "main.py", "--no-banner", "-q",
                        "inject", "--mode", "pmf-test", "-i", "wlan0",
                        "--bssid", "AA:BB:CC:DD:EE:FF",
                        "--client", "0A:1B:2C:3D:4E:5F",
                        "--transmit", "--authorized", "-o", "/tmp/inj-ref3"],
                       cwd=root, capture_output=True, text=True, timeout=60)
    # non-root box: consent check for --yes must fire before/independently
    assert p.returncode == 2
    assert "--yes" in (p.stderr + p.stdout) or "root" in (p.stderr + p.stdout)


def test_cli_deauth_dry_run_alternates_frames_and_transmits_nothing():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with tempfile.TemporaryDirectory() as td:
        p = subprocess.run([sys.executable, "main.py", "--no-banner", "-q",
                            "inject", "--mode", "deauth", "-i", "wlan0", "-c",
                            "6", "--frame-type", "both", "--bssid",
                            "AA:BB:CC:DD:EE:FF", "--client",
                            "AC:BC:32:01:02:03", "--count", "4", "-o", td],
                           cwd=root, capture_output=True, text=True, timeout=60)
        assert p.returncode == 0, p.stderr
        assert "DRY RUN" in p.stdout and "transmitted: 0" in p.stdout
        import csv as _csv
        with open(os.path.join(td, "injection_audit.csv"),
                  encoding="utf-8-sig") as fh:
            rows = list(_csv.DictReader(fh))
        frames = [r["frame"] for r in rows]
        assert frames == ["deauth", "disassoc", "deauth", "disassoc"]
        assert all(r["tx"] == "0" and r["dry_run"] == "1" for r in rows)
        assert not os.path.exists(os.path.join(td, "deauth.pcap"))


def test_cli_evil_twin_dry_run_and_gates():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with tempfile.TemporaryDirectory() as td:
        # dry run: advertises the clone, transmits nothing, writes audit
        p = subprocess.run([sys.executable, "main.py", "--no-banner", "-q",
                            "inject", "--mode", "evil-twin", "--ssid",
                            "OwnNet", "--security", "open", "-c", "6", "-i",
                            "wlan0", "--duration", "5", "-o", td],
                           cwd=root, capture_output=True, text=True, timeout=60)
        assert p.returncode == 0, p.stderr
        assert "beacon ONLY" in p.stdout and "transmitted: 0" in p.stdout
        import csv as _csv
        with open(os.path.join(td, "injection_audit.csv"),
                  encoding="utf-8-sig") as fh:
            rows = list(_csv.DictReader(fh))
        assert rows and rows[0]["frame"] == "beacon"
        assert rows[0]["dry_run"] == "1"
    # transmit without --yes is refused
    p = subprocess.run([sys.executable, "main.py", "--no-banner", "-q",
                        "inject", "--mode", "evil-twin", "--ssid", "OwnNet",
                        "-i", "wlan0", "--transmit", "--authorized",
                        "-o", "/tmp/inj-et1"],
                       cwd=root, capture_output=True, text=True, timeout=60)
    assert p.returncode == 2 and "--yes" in (p.stderr + p.stdout)
    # missing ssid is refused
    p = subprocess.run([sys.executable, "main.py", "--no-banner", "-q",
                        "inject", "--mode", "evil-twin", "-i", "wlan0",
                        "-o", "/tmp/inj-et2"],
                       cwd=root, capture_output=True, text=True, timeout=60)
    assert p.returncode == 2 and "--ssid" in (p.stderr + p.stdout)


def test_cli_deauth_requires_yes_and_refuses_broadcast():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    # missing --yes
    p = subprocess.run([sys.executable, "main.py", "--no-banner", "-q",
                        "inject", "--mode", "deauth", "-i", "wlan0",
                        "--bssid", "AA:BB:CC:DD:EE:FF",
                        "--client", "AC:BC:32:01:02:03",
                        "--transmit", "--authorized", "-o", "/tmp/inj-da1"],
                       cwd=root, capture_output=True, text=True, timeout=60)
    assert p.returncode == 2 and "--yes" in (p.stderr + p.stdout)
    # broadcast client
    p = subprocess.run([sys.executable, "main.py", "--no-banner", "-q",
                        "inject", "--mode", "deauth", "-i", "wlan0",
                        "--bssid", "AA:BB:CC:DD:EE:FF",
                        "--client", "FF:FF:FF:FF:FF:FF", "-o", "/tmp/inj-da2"],
                       cwd=root, capture_output=True, text=True, timeout=60)
    assert p.returncode == 2 and "broadcast" in (p.stderr + p.stdout).lower()


if __name__ == "__main__":
    fns = [(n, f) for n, f in sorted(globals().items())
           if n.startswith("test_") and callable(f)]
    failed = 0
    for name, fn in fns:
        try:
            fn()
            print(f"  PASS  {name}")
        except Exception as exc:
            failed += 1
            print(f"  FAIL  {name}: {type(exc).__name__}: {exc}")
    print(f"\n{len(fns) - failed}/{len(fns)} tests passed")
    sys.exit(1 if failed else 0)
