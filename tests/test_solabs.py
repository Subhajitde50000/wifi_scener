"""Tests for the stealth-detection lab (wifiscanner/hidmon.py + `stealth-lab`)
and the automatic-response lab (wifiscanner/autoresp.py + `response-lab`).

Run:  python3 -m pytest tests/test_solabs.py -q
or:   python3 tests/test_solabs.py
"""
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from wifiscanner import hidmon as H  # noqa: E402
from wifiscanner import autoresp as R  # noqa: E402

MAIN = ROOT / "main.py"


def _cli(*argv, inp=None):
    return subprocess.run(
        [sys.executable, str(MAIN), "--no-banner", "-q", *argv],
        capture_output=True, text=True, timeout=600, input=inp,
        cwd=str(ROOT))


class StealthScenarioTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory(prefix="hidmon-")
        cls.dir = os.path.join(cls._tmp.name, "sc")
        H.generate_scenario(cls.dir, seed=10)
        cls.scen = H.load_scenario(cls.dir)
        cls.eng = H.StealthEngine(cls.scen)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_layout_and_permissions(self):
        names = os.listdir(self.dir)
        for n in ("scenario.json", "telemetry.json", "ground-truth.json"):
            self.assertIn(n, names)
        mode = os.stat(os.path.join(self.dir,
                                    "ground-truth.json")).st_mode
        self.assertEqual(mode & 0o777, 0o600)
        telem = self.scen["telem"]
        for k in ("proc", "conn", "file", "auth", "services"):
            self.assertIn(k, telem)
        self.assertGreater(len(telem["proc"]), 1000)

    def test_deterministic(self):
        with tempfile.TemporaryDirectory() as td:
            d2 = os.path.join(td, "b")
            H.generate_scenario(d2, seed=10)
            a = json.load(open(os.path.join(self.dir, "telemetry.json")))
            b = json.load(open(os.path.join(d2, "telemetry.json")))
            self.assertEqual(a, b)

    def test_existing_dir_guard(self):
        with self.assertRaises(FileExistsError):
            H.generate_scenario(self.dir, seed=99)

    def test_engine_verdicts(self):
        imp = self.eng.analyze("IMPLANT")
        self.assertEqual(imp["verdict"], "covert implant")
        self.assertGreaterEqual(imp["score"], 75)
        sigs = {s for s, _, _ in imp["signals"]}
        for needed in ("name_mimic", "concealment", "c2_egress",
                       "cadence_flip", "night_delta", "respawn",
                       "unlink", "audit_gap", "hidden_stage", "unowned"):
            self.assertIn(needed, sigs)
        it = self.eng.analyze(H.IT_MONITOR)
        self.assertEqual(it["score"], 0)
        self.assertEqual(it["verdict"], "benign")
        # nothing else above watchlist: noise discipline
        for r in self.eng.league():
            if r["key"] != "IMPLANT":
                self.assertLess(r["score"], 50, r["key"])

    def test_alerts_have_the_four_beats(self):
        kinds = {a["kind"] for a in self.eng.alerts()}
        self.assertTrue({"install", "flip", "conceal", "audit-gap"}
                        <= kinds)

    def test_scoring_paths(self):
        truth = self.scen["truth"]
        good = {"q_implant": truth["implant"]["name"],
                "q_first_signal": "name-mimic",
                "q_concealment": "ps-vs-ss",
                "q_flip": "day2 night", "q_keep": H.IT_MONITOR}
        r = H.score_stealth(truth, good)
        self.assertEqual(r["score"], 100.0)
        # gen-2 name also accepted
        good2 = dict(good, q_implant=truth["implant"]["name_gen2"])
        self.assertEqual(H.score_stealth(truth, good2)["score"], 100.0)
        trap = dict(good, q_implant=H.IT_MONITOR)
        r2 = H.score_stealth(truth, trap)
        self.assertLess(r2["score"], 75)
        self.assertTrue(any("FALSE ACCUSATION" in f for f in
                            r2["feedback"]))
        self.assertLess(H.score_stealth(truth, {})["score"], 1.0)


class ResponseCoreTests(unittest.TestCase):
    def test_dry_run_enforces_nothing(self):
        lab = R.ResponseLab(seed=11)
        lab.mode = "dry-run"
        lab.run()
        m = lab.metrics()
        self.assertEqual(m["enforced_total"], 0)
        self.assertEqual(lab.firewall, {})
        notes = {a.get("note") for a in lab.audit if a["phase"] == "result"}
        self.assertIn("would-block", notes)

    def test_auto_enforces_only_attacker_with_sane_allowlist(self):
        lab = R.ResponseLab(seed=11)
        lab.mode = "auto"
        lab.run()
        self.assertEqual(set(lab.firewall), {R.ATTACKER_MAC})
        m = lab.metrics()
        self.assertEqual(m["true_positives"], 1)
        self.assertEqual(m["false_positives"], 0)
        self.assertEqual(m["blocked_neighbor"], 0)

    def test_aggressive_without_allowlist_is_friendly_fire(self):
        lab = R.ResponseLab(seed=11)
        lab.mode = "auto"
        lab.allowlist = set()
        lab.enabled_rules.add("R6")
        lab.run()
        m = lab.metrics()
        self.assertEqual(m["false_positives"], 1)
        self.assertIn(R.ITSCAN_MAC, lab.firewall)
        self.assertIn(R.ATTACKER_MAC, lab.firewall)

    def test_allowlist_fixes_the_fp(self):
        lab = R.ResponseLab(seed=11)
        lab.mode = "auto"
        lab.enabled_rules.add("R6")
        lab.run()
        self.assertEqual(lab.metrics()["false_positives"], 0)
        self.assertIn(R.ATTACKER_MAC, lab.firewall)
        self.assertNotIn(R.ITSCAN_MAC, lab.firewall)

    def test_approval_mode_queue_approve_deny(self):
        lab = R.ResponseLab(seed=11)
        lab.mode = "approval"
        lab.run()
        self.assertEqual(lab.firewall, {})
        pend = [p for p in lab.pending if not p.get("closed")]
        self.assertTrue(pend)
        self.assertTrue(lab.approve(pend[0]["pending_id"]))
        self.assertTrue(lab.firewall)
        if len(pend) > 1:
            self.assertTrue(lab.deny(pend[1]["pending_id"]))
            self.assertTrue(any(a["phase"] == "result" and
                                a.get("note") == "denied-by-instructor"
                                for a in lab.audit))

    def test_manual_mode_no_action(self):
        lab = R.ResponseLab(seed=11)
        lab.mode = "manual"
        lab.run()
        self.assertEqual(lab.firewall, {})
        self.assertEqual(lab.metrics()["enforced_total"], 0)

    def test_rollback(self):
        lab = R.ResponseLab(seed=11)
        lab.mode = "auto"
        lab.run()
        self.assertTrue(lab.rollback(R.ATTACKER_MAC))
        self.assertEqual(lab.firewall, {})
        self.assertFalse(lab.rollback(R.ATTACKER_MAC))  # nothing left

    def test_neighbour_never_blocked(self):
        for mode in R.MODES:
            lab = R.ResponseLab(seed=11)
            lab.mode = mode
            lab.allowlist = set()
            lab.enabled_rules.add("R6")
            lab.run()
            self.assertNotIn(R.NEIGHBOR_MAC, lab.firewall, mode)

    def test_scope_refuses_non_lab_devices(self):
        lab = R.ResponseLab(seed=11)
        lab._now_tick = 99
        lab._windows[("deauth", "EVIL-NET")].extend(range(94, 99))
        dec = lab.decide(dict(rule="R1", src="EVIL-NET", magnitude=9,
                              severity="high", why="", action="block",
                              tick=99))
        self.assertEqual(dec["decision"], "out-of-scope")

    def test_audit_chain_phases(self):
        lab = R.ResponseLab(seed=11)
        lab.mode = "auto"
        lab.run()
        phases = {a["phase"] for a in lab.audit}
        self.assertTrue({"detect", "decision", "response", "result"}
                        <= phases)
        # the enforced action comes with an outcome that names the target
        hits = [a for a in lab.audit if a["phase"] == "result"
                and a.get("note") == "enforced"]
        self.assertTrue(hits and all(a.get("target") for a in hits))

    def test_dry_run_does_not_consume_history(self):
        """dry-run preview must not eat future enforcement."""
        lab = R.ResponseLab(seed=11)
        lab.run(upto=60)                    # dry-run by default
        lab.mode = "auto"
        lab.run(upto=95, from_tick=61)
        self.assertTrue(lab.firewall)      # exfil beacons re-fire R4

    def test_quiz_scoring(self):
        good = {"q_dryrun": "nothing-enforced",
                "q_fp_cause": "aggressive-without-allowlist",
                "q_pending": "queued",
                "q_rollback": "safe-removes-row",
                "q_scope": "designated-only"}
        self.assertEqual(R.score_response_answers(good)["score"], 100.0)
        bad = dict(good, q_dryrun="adds-row", q_scope="any")
        r = R.score_response_answers(bad)
        self.assertEqual(r["score"], 60.0)
        self.assertLess(R.score_response_answers({})["score"], 1.0)


class WebLabTests(unittest.TestCase):
    def _serve(self, factory, app):
        srv = factory("127.0.0.1", 0, app)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        self.addCleanup(srv.server_close)
        return srv.server_address[1]

    def _get(self, port, path, allow_error=False):
        try:
            return urllib.request.urlopen(
                f"http://127.0.0.1:{port}{path}", timeout=15).read().decode(
                "utf-8", "ignore")
        except Exception:
            if allow_error:
                return ""
            raise

    def _post(self, port, path, data=None):
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}{path}",
            data=urllib.parse.urlencode(data or {"_": "x"}).encode(),
            method="POST")
        return urllib.request.urlopen(req, timeout=60).read()

    def test_stealth_web(self):
        with tempfile.TemporaryDirectory() as td:
            d = os.path.join(td, "sc")
            H.generate_scenario(d, seed=10)
            scen = H.load_scenario(d)
            store = H.DevLabStore(":memory:")
            app = H.StealthApp(scen, store, "stok")
            port = self._serve(H.make_stealth_server, app)
            for p in ("/", "/procs", "/conns", "/files", "/auth",
                      "/services", "/compare", "/hunt", "/alerts",
                      "/exercises", "/quiz"):
                self.assertGreater(len(self._get(port, p)), 300, p)
            conns = self._get(port, "/conns")
            self.assertIn("«hidden from ps»", conns)
            self.assertNotIn("IMPLANT", conns)
            self.assertFalse(self._get(port, "/api/state",
                                       allow_error=True))
            self.assertIn("Ground truth", self._get(port, "/i/stok"))
            r = json.loads(self._post(port, "/api/advance?token=stok",
                                      {"tick": "100"}))
            self.assertEqual(r["tick"], 100)
            truth = scen["truth"]
            good = {"q_implant": truth["implant"]["name"],
                    "q_first_signal": "keepalive",
                    "q_concealment": "audit-gap", "q_flip": "day2 night",
                    "q_keep": H.IT_MONITOR}
            self.assertIn("100.0",
                          self._post(port, "/quiz", good).decode())
            trap = dict(good, q_implant=H.IT_MONITOR)
            self.assertIn("FALSE ACCUSATION",
                          self._post(port, "/quiz", trap).decode())
            r = json.loads(self._post(port, "/api/regenerate?token=stok"))
            self.assertEqual(r["seed"], 11)
            store.close()

    def test_response_web(self):
        store = R.DevLabStore(":memory:")
        app = R.ResponseWebApp(store, "rtok", seed=11)
        port = self._serve(R.make_response_server, app)
        for p in ("/", "/console", "/rules", "/blocks", "/audit",
                  "/exercises", "/quiz"):
            self.assertGreater(len(self._get(port, p)), 300, p)
        self.assertFalse(self._get(port, "/api/state", allow_error=True))
        # dry-run advance, then approve flow
        json.loads(self._post(port, "/api/advance?token=rtok",
                              {"upto": "60"}))
        st = json.loads(self._get(port, "/api/state?token=rtok"))
        self.assertEqual(st["metrics"]["enforced_total"], 0)
        json.loads(self._post(port, "/api/mode?token=rtok",
                              {"mode": "approval"}))
        json.loads(self._post(port, "/api/advance?token=rtok",
                              {"upto": "95"}))
        pend = json.loads(self._get(port,
                                    "/api/state?token=rtok"))["pending"]
        self.assertTrue(pend)
        ok = json.loads(self._post(port, "/api/approve?token=rtok",
                                   {"id": pend[0]}))
        self.assertTrue(ok["ok"])
        fw = json.loads(self._get(port, "/api/state?token=rtok"))[
            "firewall"]
        self.assertTrue(fw)
        ok = json.loads(self._post(port, "/rollback",
                                   {"mac": R.ATTACKER_MAC}))
        self.assertTrue(ok["ok"])
        self.assertEqual(json.loads(self._get(port,
                                    "/api/state?token=rtok"))["firewall"],
                         {})
        self.assertIn("pending approvals",
                      self._get(port, "/i/rtok").lower())
        good = {"q_dryrun": "nothing-enforced",
                "q_fp_cause": "aggressive-without-allowlist",
                "q_pending": "queued", "q_rollback": "safe-removes-row",
                "q_scope": "designated-only"}
        self.assertIn("100.0", self._post(port, "/quiz", good).decode())
        r = json.loads(self._post(port, "/api/regenerate?token=rtok"))
        self.assertEqual(r["seed"], 12)
        store.close()


class LabCLITests(unittest.TestCase):
    def test_stealth_cli(self):
        with tempfile.TemporaryDirectory() as td:
            d = os.path.join(td, "sl")
            r = _cli("stealth-lab", "make-scenario", d, "--seed", "10")
            self.assertEqual(r.returncode, 0, r.stderr)
            r = _cli("stealth-lab", "telemetry", d, "--kind", "procs",
                     "--day", "1")
            self.assertEqual(r.returncode, 0)
            self.assertIn("pkg-owner", r.stdout)
            r = _cli("stealth-lab", "hunt", d)
            self.assertEqual(r.returncode, 0)
            self.assertIn("covert implant", r.stdout)
            r = _cli("stealth-lab", "explain", d, "IMPLANT")
            self.assertEqual(r.returncode, 0)
            self.assertIn("concealment", r.stdout)
            r = _cli("stealth-lab", "compare", d)
            self.assertEqual(r.returncode, 0)
            self.assertIn("registered IT monitor", r.stdout)
            r = _cli("stealth-lab", "alerts", d)
            self.assertEqual(r.returncode, 0)
            self.assertIn("concealment", r.stdout)
            with open(os.path.join(d, "ground-truth.json")) as fh:
                truth = json.load(fh)
            ans = json.dumps({"q_implant": truth["implant"]["name"],
                              "q_first_signal": "name-mimic",
                              "q_concealment": "ps-vs-ss",
                              "q_flip": "day2 night",
                              "q_keep": "snmpd-corp"})
            r = _cli("stealth-lab", "score", d, "--answers", "-", inp=ans)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertIn("100.0", r.stdout)
            bad = json.dumps({"q_implant": "snmpd-corp"})
            r = _cli("stealth-lab", "score", d, "--answers", "-", inp=bad)
            self.assertEqual(r.returncode, 1)
            r = _cli("stealth-lab", "exercises")
            self.assertEqual(r.returncode, 0)
            self.assertIn("concealment", r.stdout.lower())
            r = _cli("stealth-lab", "hunt", os.path.join(td, "nope"))
            self.assertEqual(r.returncode, 2)

    def test_response_cli(self):
        r = _cli("response-lab", "cast")
        self.assertEqual(r.returncode, 0)
        self.assertIn("TEST-ATTACK-01", r.stdout)
        r = _cli("response-lab", "rules")
        self.assertEqual(r.returncode, 0)
        self.assertIn("R6", r.stdout)
        r = _cli("response-lab", "simulate", "--mode", "dry-run")
        self.assertEqual(r.returncode, 0)
        self.assertIn("enforced=0", r.stdout)
        r = _cli("response-lab", "simulate", "--mode", "auto")
        self.assertEqual(r.returncode, 0)
        self.assertIn("true+=1", r.stdout)
        self.assertIn("false+=0", r.stdout)
        r = _cli("response-lab", "simulate", "--mode", "auto",
                 "--enable-rule", "R6", "--clear-allowlist")
        self.assertEqual(r.returncode, 0)
        self.assertIn("false+=1", r.stdout)
        self.assertIn("friendly fire", r.stdout)
        ans = json.dumps({"q_dryrun": "nothing-enforced",
                          "q_fp_cause": "aggressive-without-allowlist",
                          "q_pending": "queued",
                          "q_rollback": "safe-removes-row",
                          "q_scope": "designated-only"})
        r = _cli("response-lab", "score", "--answers", "-", inp=ans)
        self.assertEqual(r.returncode, 0)
        self.assertIn("100.0", r.stdout)
        r = _cli("response-lab", "exercises")
        self.assertEqual(r.returncode, 0)
        self.assertIn("roll", r.stdout.lower())


if __name__ == "__main__":
    unittest.main(verbosity=2)
