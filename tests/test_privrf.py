#!/usr/bin/env python3
"""Feature 14 + 15 test battery: privlab (privacy/MAC-randomization) and
rflab (RF interference/resilience). All synthetic, all offline."""
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from wifiscanner import privlab as P    # noqa: E402
from wifiscanner import rflab as R    # noqa: E402


def _post(port, path, data=None):
    body = urllib.parse.urlencode(data or {}).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}",
                                 data=body, method="POST")
    return urllib.request.urlopen(req, timeout=40).read()


def _get(port, path):
    return urllib.request.urlopen(f"http://127.0.0.1:{port}{path}",
                                  timeout=40).read().decode("utf-8",
                                                            "ignore")


def _start(app_maker):
    srv = app_maker
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, port


class PrivDatasetTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.mkdtemp()
        P.generate_observations(self.td, seed=14, devices=10, days=6,
                                fresh=True)
        self.ds = P.load_dataset(self.td)

    def test_layout_permissions_determinism(self):
        for name in ("devices.json", "observations.json"):
            st = os.stat(os.path.join(self.td, name))
            self.assertEqual(st.st_mode & 0o777, 0o600)
        P.generate_observations(self.td, seed=14, devices=10, days=6,
                                fresh=True)
        ds2 = P.load_dataset(self.td)
        self.assertEqual(ds2["observations"][0],
                         self.ds["observations"][0])

    def test_guard_refuses_overwrite_without_fresh(self):
        with self.assertRaises(SystemExit):
            P.generate_observations(self.td, seed=14, devices=10,
                                    days=6, fresh=False)

    def test_all_lab_scope(self):
        for o in self.ds["observations"]:
            self.assertTrue(o["mac"].startswith(P.LAB_OUI),
                            o["mac"])
            self.assertTrue(o["device_id"].startswith("LAB-DEV-"))
            self.assertTrue(o["ap"].startswith("LAB-AP-"))

    def test_restricted_reference_ap_present(self):
        restr = [d for d in self.ds["devices"] if d.get("restricted")]
        self.assertEqual([d["device_id"] for d in restr], ["LAB-DEV-01"])
        self.assertEqual(restr[0]["label"], "LAB-REFERENCE-AP")


class PrivEngineTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.mkdtemp()
        P.generate_observations(self.td, seed=14, devices=10, days=6,
                                fresh=True)
        self.ds = P.load_dataset(self.td)

    def test_correlation_clusters_rotation(self):
        t = P.analyze_dataset(self.ds)
        self.assertGreaterEqual(len(t["clusters"]), 4, t)
        self.assertGreater(t["unique_macs"], len(self.ds["devices"]))

    def test_restricted_device_never_in_tracks(self):
        t = P.analyze_dataset(self.ds)
        restr_macs = {o["mac"] for o in self.ds["observations"]
                      if o["device_id"] == "LAB-DEV-01"}
        members = {m for c in t["clusters"] for m in c["members"]}
        self.assertFalse(members & restr_macs)

    def test_scope_refusal(self):
        with self.assertRaises(P.ScopeError):
            P.check_scope(self.ds, "LAB-DEV-01")
        self.assertTrue(P.check_scope(self.ds, "LAB-DEV-02"))

    def test_privacy_report_shows_scrub_effect(self):
        rpt = P.privacy_report(self.ds)
        leak = rpt["pnolist_leak"]
        self.assertGreater(leak["before_scrub"], 0)
        self.assertEqual(leak["after_scrub"], 0)

    def test_config_simulation_lowers_confidence(self):
        c1 = P.simulate_privacy_config(self.ds, "LAB-DEV-03", {})[
            "confidence"]
        c2 = P.simulate_privacy_config(self.ds, "LAB-DEV-03",
                                       {"scrub_pno": True,
                                        "ie_randomize": True,
                                        "irregular_timing": True})[
                                            "confidence"]
        self.assertLessEqual(c2, 0.10)
        self.assertEqual(c1, 0.9)

    def test_scoring_paths(self):
        good = {k: v[0] for k, v in P._PRIV_ANS.items()}
        self.assertEqual(P.score_privlab(good)[0], 100.0)
        bad = {k: "totally-wrong" for k in P._PRIV_ANS}
        self.assertLess(P.score_privlab(bad)[0], 60)
        part = dict(bad)
        part["q_rotates"] = P._PRIV_ANS["q_rotates"][0]
        self.assertGreater(P.score_privlab(part)[0],
                           P.score_privlab(bad)[0])


class RFEngineTests(unittest.TestCase):
    def test_baseline_is_healthy(self):
        s = R.InterferenceSession(15)
        s.stop()
        for ap, rows in s.series(30).items():
            summ = R._summarise(rows)
            self.assertLess(summ["loss"], 0.05)
            self.assertGreater(summ["snr_db"], 20)
            self.assertGreater(summ["throughput_kbps"], 20000)

    def test_interference_degrades_and_detector_sees_it(self):
        s = R.InterferenceSession(15)
        s.start("microwave", 75)
        det = R.detect_interference(s)
        self.assertIn(11, det["affected"])            # microwave band
        self.assertNotIn(1, det["affected"])          # no bleed to ch1
        self.assertEqual(det["guess"], "microwave")
        self.assertTrue(any(a["severity"] in ("critical", "warning")
                            for a in det["alerts"]))
        s.stop()

    def test_all_interferers_classified(self):
        want = {"microwave": "microwave", "bluetooth": "bluetooth",
                "cordless": "cordless", "chaos": "chaos"}
        for name, expect in want.items():
            s = R.InterferenceSession(15)
            s.start(name, 85)
            self.assertEqual(R.detect_interference(s)["guess"], expect,
                             name)

    def test_before_after_compare(self):
        s = R.InterferenceSession(15)
        rows = R.compare_runs(s, "microwave", 80)
        hit = next(r for r in rows if r["channel"] == 11)
        clean = next(r for r in rows if r["channel"] == 1)
        self.assertLess(hit["delta_pct_thru"], -10)
        self.assertEqual(clean["delta_pct_thru"], 0.0)

    def test_nonoverlap_resilience_lesson(self):
        """Moving the hit AP from ch11 to ch1 must fully recover it."""
        s = R.InterferenceSession(15)
        s.start("microwave", 85)
        res = R.resilience_score(s, "LAB-AP-3", 1)
        self.assertTrue(res["recovered"], res)
        self.assertEqual(res["score"], 100)
        s.stop()

    def test_instructor_controls_and_caps(self):
        s = R.InterferenceSession(15)
        s.start("cordless", 50, by="tester")
        capped = s.set_intensity(200, by="tester")
        self.assertTrue(capped)
        self.assertEqual(s.intensity, R.MAX_INTENSITY)
        s.stop(by="tester")
        self.assertFalse(s.running)
        s.reset(by="tester")
        actions = [l["action"] for l in s.log]
        self.assertEqual(actions, ["start", "intensity", "stop", "reset"])

    def test_channel_change_validated(self):
        s = R.InterferenceSession(15)
        with self.assertRaises(ValueError):
            s.set_channel("LAB-AP-1", 3)              # not a lab channel
        with self.assertRaises(ValueError):
            s.set_channel("REAL-AP-1", 1)             # not lab-owned
        old, new = s.set_channel("LAB-AP-1", 6)
        self.assertEqual((old, new), (6 - 5, 6))

    def test_scoring_paths(self):
        good = {k: v[0] for k, v in R._RF_ANS.items()}
        self.assertEqual(R.score_rflab(good)[0], 100.0)
        self.assertLess(R.score_rflab({k: "nope" for k in R._RF_ANS})[0],
                        60)


class WebLabsTests(unittest.TestCase):
    def test_privlab_web_flow(self):
        td = tempfile.mkdtemp()
        P.generate_observations(td, seed=14, devices=8, days=6,
                                fresh=True)
        ds = P.load_dataset(td)
        store = P.DevLabStore(":memory:")
        app = P.PrivLabApp(ds, store, "ptok")
        srv, port = _start(P.make_priv_server("127.0.0.1", 0, app))
        try:
            for p in ("/", "/tracks", "/privacy", "/compare", "/alerts",
                      "/exercises", "/quiz"):
                body = _get(port, p)
                self.assertGreater(len(body), 1000, p)
            dash = _get(port, "/i/ptok")
            self.assertIn("instructor console", dash)
            self.assertIn("LAB-REFERENCE-AP", dash)
            # state hidden without token
            with self.assertRaises(urllib.error.HTTPError) as cm:
                _get(port, "/api/state")
            self.assertEqual(cm.exception.code, 404)
            st = json.loads(_get(port, "/api/state?token=ptok"))
            self.assertTrue(st["ok"])
            self.assertEqual(st["devices"], 8)
            # scope refusal over the wire; alerts recorded
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/correlate",
                data=urllib.parse.urlencode(
                    {"target": "LAB-DEV-01"}).encode(),
                method="POST")
            with self.assertRaises(urllib.error.HTTPError) as cm:
                urllib.request.urlopen(req, timeout=20)
            self.assertEqual(cm.exception.code, 403)
            self.assertEqual(len(app.alerts), 1)
            # legal correlation works
            out = json.loads(_post(port, "/api/correlate",
                                   {"target": "*"}))
            self.assertGreater(out["unique_macs"], 8)
            self.assertIn("ran_correlation", app.completed)
            # what-if across the fence is also refused
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/simulate",
                data=urllib.parse.urlencode(
                    {"device": "LAB-DEV-01",
                     "scrub_pno": "on"}).encode(), method="POST")
            with self.assertRaises(urllib.error.HTTPError) as cm:
                urllib.request.urlopen(req, timeout=20)
            self.assertEqual(cm.exception.code, 403)
            # full-config what-if marks the exercise done
            r = json.loads(_post(port, "/api/simulate",
                                 {"device": "LAB-DEV-03",
                                  "scrub_pno": "on",
                                  "ie_randomize": "on",
                                  "irregular_timing": "on"}))
            self.assertLess(r["confidence"], 0.3)
            self.assertIn("config_lowered", app.completed)
            # quiz end-to-end
            good = {k: v[0] for k, v in P._PRIV_ANS.items()}
            self.assertIn("100.0", _post(port, "/quiz", good).decode())
            # instructor expand/reset/destroy over the wire
            _post(port, "/i/ptok/expand", {})
            self.assertEqual(len(app.ds["devices"]), 10)
            _post(port, "/i/ptok/reset", {})
            self.assertEqual(len(app.completed), 0)
            _post(port, "/i/ptok/destroy", {})
            self.assertEqual(len(app.ds["devices"]), 0)
            self.assertEqual(len(app.ds["observations"]), 0)
        finally:
            srv.shutdown()
            store.close()

    def test_rflab_web_flow(self):
        sess = R.InterferenceSession(15)
        store = R.DevLabStore(":memory:")
        app = R.RFLabApp(sess, store, "rtok")
        srv, port = _start(R.make_rf_server("127.0.0.1", 0, app))
        try:
            for p in ("/", "/compare", "/detect", "/incident",
                      "/exercises", "/quiz"):
                body = _get(port, p)
                self.assertGreater(len(body), 1500, p)
            dash = _get(port, "/i/rtok")
            self.assertIn("instructor console", dash)
            self.assertIn("microwave", dash)
            with self.assertRaises(urllib.error.HTTPError) as cm:
                _get(port, "/api/state")
            self.assertEqual(cm.exception.code, 404)
            st = json.loads(_get(port, "/api/state?token=rtok"))
            self.assertFalse(st["running"])
            # instructor: start with illegal intensity → capped + audited
            _post(port, "/i/rtok/start",
                  {"interferer": "microwave", "intensity": "500"})
            self.assertTrue(sess.running)
            self.assertEqual(sess.intensity, R.MAX_INTENSITY)
            self.assertTrue(any("capped" in l["detail"]
                                for l in sess.log))
            # detect over the wire, alerts raised
            det = json.loads(_post(port, "/api/detect", {}))
            self.assertEqual(det["guess"], "microwave")
            self.assertGreater(len(app.alerts), 0)
            self.assertTrue(any(a["kind"] == "suspected-interference"
                                for a in app.alerts))
            # rechannel exercise → recovery confirmed
            r = json.loads(_post(port, "/api/rechannel",
                                 {"ap": "LAB-AP-3", "channel": "1"}))
            self.assertTrue(r["recovered"], r)
            # incident report over the wire
            rpt = json.loads(_post(port, "/api/incident", {}))
            self.assertEqual(rpt["guess"], "microwave")
            # metrics API holds the five headline numbers
            m = json.loads(_get(port, "/api/metrics"))
            self.assertEqual(sorted(m.keys()),
                             ["LAB-AP-1", "LAB-AP-2", "LAB-AP-3"])
            sample = m["LAB-AP-1"][0]
            for k in ("util", "snr_db", "loss", "latency_ms",
                      "throughput_kbps"):
                self.assertIn(k, sample)
            # quiz + scoped completion flags
            good = {k: v[0] for k, v in R._RF_ANS.items()}
            self.assertIn("100.0", _post(port, "/quiz", good).decode())
            self.assertIn("x1", app.completed)
            self.assertIn("x3", app.completed)
            self.assertIn("x4", app.completed)
            self.assertIn("x5", app.completed)
            # stop + reset clear the stage
            _post(port, "/i/rtok/stop", {})
            self.assertFalse(sess.running)
            _post(port, "/i/rtok/reset", {})
            self.assertEqual(sess.intensity, 40)
            self.assertEqual(app.alerts, [])
        finally:
            srv.shutdown()
            store.close()


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class LabCLITests(unittest.TestCase):
    def _run(self, *argv):
        return subprocess.run(
            [sys.executable, os.path.join(ROOT, "main.py"),
             "--no-banner", "-q", *argv],
            capture_output=True, text=True, cwd=ROOT, timeout=300)

    def test_priv_lab_cli(self):
        with tempfile.TemporaryDirectory() as td:
            db = os.path.join(td, "priv")
            r = self._run("priv-lab", "make-dataset", db,
                          "--seed", "14", "--devices", "8", "--fresh")
            self.assertIn("lab dataset written", r.stdout)
            r = self._run("priv-lab", "inventory", "--db", db)
            self.assertIn("randomizers", r.stdout)
            r = self._run("priv-lab", "correlate", "--db", db)
            self.assertIn("clusters", r.stdout)
            # scoped refusal on the restricted reference AP
            r = self._run("priv-lab", "correlate", "--db", db,
                          "--target", "LAB-DEV-01")
            self.assertEqual(r.returncode, 1)
            self.assertIn("refused", r.stdout)
            r = self._run("priv-lab", "compare", "--db", db)
            self.assertIn("scrub", r.stdout)
            r = self._run("priv-lab", "exercises")
            self.assertIn("Break the randomization", r.stdout)
            # score: full-credit exit 0, bogus exit 1
            good = os.path.join(td, "good.json")
            with open(good, "w") as fh:
                json.dump({k: v[0] for k, v in P._PRIV_ANS.items()}, fh)
            r = self._run("priv-lab", "score", "--answers", good)
            self.assertEqual(r.returncode, 0)
            self.assertIn("100.0", r.stdout)
            bad = os.path.join(td, "bad.json")
            with open(bad, "w") as fh:
                json.dump({k: "nope" for k in P._PRIV_ANS}, fh)
            r = self._run("priv-lab", "score", "--answers", bad)
            self.assertEqual(r.returncode, 1)

    def test_rf_lab_cli(self):
        r = self._run("rf-lab", "baseline")
        self.assertIn("LAB-AP-1", r.stdout)
        r = self._run("rf-lab", "inject", "--interferer", "microwave",
                      "--intensity", "70")
        self.assertIn("detector sees", r.stdout)
        self.assertIn("ch11", r.stdout)
        r = self._run("rf-lab", "compare", "--interferer", "cordless",
                      "--intensity", "90")
        self.assertIn("Δgoodput", r.stdout)
        r = self._run("rf-lab", "investigate", "--interferer",
                      "bluetooth", "--intensity", "80")
        self.assertIn("bluetooth", r.stdout)
        r = self._run("rf-lab", "resilience", "--ap", "LAB-AP-3",
                      "--channel", "1", "--interferer", "microwave",
                      "--intensity", "85")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("recovered=True", r.stdout)
        r = self._run("rf-lab", "exercises")
        self.assertIn("Rechannel", r.stdout)
        with tempfile.TemporaryDirectory() as td:
            good = os.path.join(td, "g.json")
            with open(good, "w") as fh:
                json.dump({k: v[0] for k, v in R._RF_ANS.items()}, fh)
            r = self._run("rf-lab", "score", "--answers", good)
            self.assertEqual(r.returncode, 0)
            self.assertIn("100.0", r.stdout)


if __name__ == "__main__":
    unittest.main()
