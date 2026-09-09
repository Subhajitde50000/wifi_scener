"""Tests for the MAC-randomization deanonymization lab and the long-term
device-tracking lab (wifiscanner/devlab.py + `mac-lab`/`track-lab` CLI).

Run:  python3 -m pytest tests/test_devlab.py -q
or:   python3 tests/test_devlab.py
"""
import csv
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

from wifiscanner import devlab as D  # noqa: E402

MAIN = ROOT / "main.py"


def _cli(*argv, inp=None):
    return subprocess.run(
        [sys.executable, str(MAIN), "--no-banner", "-q", *argv],
        capture_output=True, text=True, timeout=600, input=inp,
        cwd=str(ROOT))


def _truth(ds):
    return {r["device"]: r for r in ds["truth"]}


class MacLabDatasetTests(unittest.TestCase):
    """Feature 8 dataset generation: deterministic, permissioned, parseable."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory(prefix="devlab-mac-")
        cls.dir = os.path.join(cls._tmp.name, "mac")
        D.generate_maclab_dataset(cls.dir, seed=8)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_dataset_layout_and_permissions(self):
        names = os.listdir(self.dir)
        self.assertIn("manifest.json", names)
        self.assertIn("ground-truth.csv", names)
        self.assertEqual(sorted(n for n in names if n.startswith("sensor-")),
                         ["sensor-corridor.pcap", "sensor-lab-a.pcap"])
        # instructor-only ground truth: 0600
        mode = os.stat(os.path.join(self.dir, "ground-truth.csv")).st_mode
        self.assertEqual(mode & 0o777, 0o600)
        # manifest lists sensors + frames
        with open(os.path.join(self.dir, "manifest.json")) as fh:
            man = json.load(fh)
        self.assertEqual(man["kind"], "maclab")
        self.assertGreater(man["frames"], 500)

    def test_deterministic_seed(self):
        with tempfile.TemporaryDirectory() as td:
            d2 = os.path.join(td, "m2")
            D.generate_maclab_dataset(d2, seed=8)
            a = D.load_dataset(self.dir)
            b = D.load_dataset(d2)
            self.assertEqual([o.mac for o in a["obs"]],
                             [o.mac for o in b["obs"]])
            self.assertEqual(a["truth"], b["truth"])

    def test_roundtrip_parse_and_fingerprint(self):
        ds = D.load_dataset(self.dir)
        self.assertGreater(len(ds["obs"]), 500)
        for o in ds["obs"][:50]:
            self.assertRegex(o.mac, r"^[0-9A-F:]{17}$")
            self.assertTrue(o.fp)  # IE fingerprint extracted per frame
            self.assertNotEqual(o.fp, ".|")

    def test_radiotap_rssi_roundtrip(self):
        from wifiscanner import wpalab
        page = self._get_first_frame_bytes()
        self.assertIsInstance(page, tuple)
        ts, body, rssi = page
        self.assertTrue(-100 <= rssi <= -20)
        f = wpalab.Frame80211(body)
        self.assertTrue(f.valid)
        self.assertEqual(f.ftype, 0)          # management frame
        self.assertEqual(f.subtype, 4)        # probe-request
        self.assertEqual(f.a1, b"\xff" * 6)   # broadcast destination

    def _get_first_frame_bytes(self):
        from wifiscanner import wpalab
        link, raws = wpalab.read_pcap(os.path.join(self.dir,
                                                   "sensor-lab-a.pcap"))
        self.assertEqual(link, 127)  # radiotap
        ts, raw = raws[0]
        body, rssi = D._rtap_parse(raw)
        return ts, body, rssi

    def test_engine_exits_and_shape(self):
        ds = D.load_dataset(self.dir)
        eng = D.CorrelationEngine(ds["obs"])
        self.assertGreaterEqual(len(eng.macs), 6)
        self.assertTrue(all(m in eng.by_mac for m in eng.macs))


class MacLabEngineTests(unittest.TestCase):
    """The pedagogical core: merge the rotator, reject the twins."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory(prefix="devlab-eng-")
        cls.dir = os.path.join(cls._tmp.name, "mac")
        D.generate_maclab_dataset(cls.dir, seed=8)
        cls.ds = D.load_dataset(cls.dir)
        cls.eng = D.CorrelationEngine(cls.ds["obs"])
        cls.gt = _truth(cls.ds)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_rotator_merges_into_one_cluster(self):
        rot = set(self.gt["Device-A"]["macs"].split(";"))
        clusters = self.eng.clusters()
        belongs = [c for c in clusters if rot & set(c["members"])]
        self.assertEqual(len(belongs), 1)
        self.assertEqual(set(belongs[0]["members"]), rot)

    def test_twins_are_rejected_with_simultaneity(self):
        t1 = self.gt["Device-B1"]["macs"]
        t2 = self.gt["Device-B2"]["macs"]
        ev = self.eng.evidence(t1, t2)
        self.assertEqual(ev["verdict"], "different")
        self.assertTrue(any("simultaneous" in name
                            for name, _, _ in ev["anti"]))
        self.assertIn("provably two devices", ev["anti"][0][2])

    def test_fingerprint_only_pairs_stay_possible(self):
        """Same-model coincidence must not reach 'likely'."""
        for ev in self.eng.matrix():
            if ev["verdict"] in ("likely", "high"):
                has_ssid = any(n == "ssid-set" for n, _, _ in ev["support"])
                has_handoff = any(n == "handoff" for n, _, _ in ev["support"])
                self.assertTrue(has_ssid or has_handoff,
                                f"{ev['pair']} climbed without behavioural "
                                f"evidence")
        self.assertTrue(any(ev["verdict"] == "possible"
                            for ev in self.eng.matrix()),
                        "the grey zone must exist for the lessons")

    def test_score_good_answer_100(self):
        rot = self.gt["Device-A"]["macs"].split(";")
        ans = [rot, [self.gt["Device-B1"]["macs"]],
               [self.gt["Device-B2"]["macs"]]]
        r = D.score_maclab(self.ds["truth"], ans)
        self.assertEqual(r["score"], 100.0)

    def test_score_twin_trap_hammered(self):
        rot = self.gt["Device-A"]["macs"].split(";")
        ans = [rot, [self.gt["Device-B1"]["macs"],
                     self.gt["Device-B2"]["macs"]]]
        r = D.score_maclab(self.ds["truth"], ans)
        self.assertLess(r["score"], 40)
        self.assertTrue(any("TWIN TRAP" in f for f in r["feedback"]))

    def test_score_empty_answer(self):
        r = D.score_maclab(self.ds["truth"], [])
        self.assertEqual(r["score"], 0.0)


class TrackLabTests(unittest.TestCase):
    """Feature 9: routines, edges, short-vs-long, quiz scoring."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory(prefix="devlab-track-")
        cls.dir = os.path.join(cls._tmp.name, "track")
        D.generate_tracklab_dataset(cls.dir, seed=9, days=14, fresh=True)
        cls.ds = D.load_dataset(cls.dir)
        cls.tr = D.Tracker(cls.ds["obs"])
        cls.gt = _truth(cls.ds)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_student_routine_recovered(self):
        mac = self.gt["Student-A"]["macs"]
        p = self.tr.pattern(mac)
        self.assertGreaterEqual(len(p["days_present"]), 8)
        self.assertIn(("lab-north", "canteen"), p["edges"])
        self.assertIn(("canteen", "lab-south"), p["edges"])
        self.assertGreaterEqual(p["edges"][("lab-north", "canteen")], 6)
        week = p["weekdays"]
        self.assertEqual(week[5] + week[6], 0)   # weekday-only student

    def test_decoy_scoped_to_corridor(self):
        decoy = self.gt["Decoy-A'"]["macs"]
        p = self.tr.pattern(decoy)
        sensors = {v[0] for v in p["visits"]}
        self.assertEqual(sensors, {"corridor"})
        tk = self.tr.trackability(decoy)
        self.assertIn("HIGH", tk["verdict"])  # it HAS a routine — that's
        # precisely why the trap bites inattentive students

    def test_visitor_is_untrackable_by_mac(self):
        table = self.tr.table()
        randomized = [t for t in table if t["randomized"]]
        multi = [t for t in randomized if t["days"] > 1]
        self.assertEqual(multi, [],
                         "any randomized MAC with >1 day breaks the lesson")
        self.assertGreater(len(randomized), 20)

    def test_short_vs_long_window_contrast(self):
        mac = self.gt["Student-A"]["macs"]
        short = D.Tracker(self.ds["obs"], since_s=2 * 86400)
        ps = short.pattern(mac)
        pf = self.tr.pattern(mac)
        self.assertLess(len(ps["days_present"]), len(pf["days_present"]))
        self.assertLess(ps["visit_count"], pf["visit_count"])

    def test_quiz_scoring_paths(self):
        truth = self.ds["truth"]
        good = {"q_identity": self.gt["Student-A"]["macs"],
                "q_untrackable": "Visitor-B",
                "q_edge": "lab-north>canteen",
                "q_short_window": "insufficient",
                "q_false_positive": self.gt["Decoy-A'"]["macs"]}
        r = D.score_tracklab(truth, good)
        self.assertEqual(r["score"], 100.0)
        conned = dict(good, q_identity=self.gt["Decoy-A'"]["macs"],
                      q_false_positive="")
        r2 = D.score_tracklab(truth, conned)
        self.assertLess(r2["score"], r["score"])
        self.assertTrue(any("FALSE POSITIVE" in f for f in r2["feedback"]))
        self.assertLess(D.score_tracklab(truth, {})["score"], 1.0)


class StoreTests(unittest.TestCase):
    def test_store_funnel_and_reset(self):
        st = D.DevLabStore(":memory:")
        st.event("mac", "page-view", "home", "127.0.0.1")
        st.attempt("mac", "cluster", "x,y", 42.5, "verdict", "127.0.0.1")
        f = st.funnel("mac")
        self.assertEqual(f["views"], 1)
        self.assertEqual(f["attempts"], 1)
        self.assertEqual(f["best_score"], 42.5)
        n = st.reset("mac")
        self.assertGreaterEqual(n, 2)
        self.assertEqual(st.funnel("mac")["attempts"], 0)
        st.close()

    def test_store_file_permissions(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "lab.sqlite")
            st = D.DevLabStore(path)
            st.close()
            mode = os.stat(path).st_mode
            self.assertEqual(mode & 0o777, 0o600)


class WebTests(unittest.TestCase):
    """Both portals end to end: student flow, scoring POSTs, gated
    instructor dashboard, dataset regeneration."""

    def _serve(self, app, factory):
        srv = factory("127.0.0.1", 0, app)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        self.addCleanup(srv.server_close)
        return srv.server_address[1]

    def _get(self, port, path, allow_error=False):
        try:
            return urllib.request.urlopen(
                f"http://127.0.0.1:{port}{path}", timeout=10).read().decode(
                "utf-8", "ignore")
        except Exception:
            if allow_error:
                return ""
            raise

    def _post(self, port, path, data):
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}{path}",
            data=urllib.parse.urlencode(data).encode())
        return urllib.request.urlopen(req, timeout=30).read().decode(
            "utf-8", "ignore")

    def test_maclab_web(self):
        with tempfile.TemporaryDirectory() as td:
            d = os.path.join(td, "m")
            D.generate_maclab_dataset(d, seed=8)
            store = D.DevLabStore(":memory:")
            app = D.MacLabApp(D.load_dataset(d), store, "tok")
            port = self._serve(app, D.make_maclab_server)
            home = self._get(port, "/")
            self.assertIn("MAC randomization", home)
            self.assertNotIn("Device-A", home)  # no ground truth leaked
            self.assertIn("Correlation evidence", self._get(port, "/matrix"))
            self.assertIn("clustering", self._get(port, "/quiz"))
            exc = self._get(port, "/exercises")
            self.assertIn("MAC-lab", exc)
            # student flow: correct answer -> 100
            truth = app.dataset["truth"]
            rot = truth[0]["macs"].split(";")
            t1, t2 = truth[1]["macs"], truth[2]["macs"]
            res = self._post(port, "/quiz", {"clusters":
                                             ",".join(rot) + "\n" + t1
                                             + "\n" + t2})
            self.assertIn("100.0", res)
            # trap
            res2 = self._post(port, "/quiz", {"clusters":
                                              ",".join(rot) + "\n" + t1
                                              + "," + t2})
            self.assertIn("TWIN TRAP", res2)
            # instructor gate
            self.assertFalse(self._get(port, "/api/state", allow_error=True))
            dash = self._get(port, "/i/tok")
            self.assertIn("Ground truth", dash)
            state = json.loads(self._get(port, "/api/state?token=tok"))
            self.assertEqual(state["funnel"]["attempts"], 2)
            # reset + regenerate
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/regenerate?token=tok",
                method="POST")
            info = json.loads(urllib.request.urlopen(req, timeout=60).read())
            self.assertEqual(info["seed"], 9)
            self.assertGreater(info["frames"], 0)
            store.close()

    def test_tracklab_web(self):
        with tempfile.TemporaryDirectory() as td:
            d = os.path.join(td, "t")
            D.generate_tracklab_dataset(d, seed=9, days=14, fresh=True)
            store = D.DevLabStore(":memory:")
            app = D.TrackLabApp(D.load_dataset(d), store, "tok2")
            port = self._serve(app, D.make_tracklab_server)
            home = self._get(port, "/")
            self.assertIn("tracking lab", home.lower())
            self.assertIn("retention",
                          self._get(port, "/compare?days=2").lower())
            self.assertIn("Persistent identifier",
                          self._get(port, "/privacy"))
            self.assertIn("Student-A", self._get(port, "/quiz"))
            gt = {r["device"]: r for r in app.truth}
            good = {"q_identity": gt["Student-A"]["macs"],
                    "q_untrackable": "Visitor-B",
                    "q_edge": "lab-north>canteen",
                    "q_short_window": "insufficient",
                    "q_false_positive": gt["Decoy-A'"]["macs"]}
            res = self._post(port, "/quiz", good)
            self.assertIn("100.0", res)
            trap = dict(good, q_identity=gt["Decoy-A'"]["macs"])
            res2 = self._post(port, "/quiz", trap)
            self.assertIn("FALSE POSITIVE", res2)
            self.assertFalse(self._get(port, "/api/state", allow_error=True))
            self.assertIn("Ground truth", self._get(port, "/i/tok2"))
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/api/regenerate?token=tok2",
                method="POST")
            info = json.loads(urllib.request.urlopen(req, timeout=90).read())
            self.assertEqual(info["seed"], 10)
            store.close()


class CLITests(unittest.TestCase):
    """Subprocess smoke over the main CLI for both labs."""

    def test_mac_lab_cli(self):
        with tempfile.TemporaryDirectory() as td:
            d = os.path.join(td, "ml")
            r = _cli("mac-lab", "make-dataset", d, "--seed", "8")
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("rotates", r.stdout)
            r = _cli("mac-lab", "inventory", d)
            self.assertEqual(r.returncode, 0)
            self.assertIn("randomiz", r.stdout)
            r = _cli("mac-lab", "correlate", d, "--limit", "5")
            self.assertEqual(r.returncode, 0)
            self.assertIn("engine clusters", r.stdout)
            # explain the rotator pair
            with open(os.path.join(d, "ground-truth.csv")) as _fh:
                rows = list(csv.DictReader(_fh))
            ro = rows[0]["macs"].split(";")
            r = _cli("mac-lab", "explain", d, ro[0], ro[1])
            self.assertEqual(r.returncode, 0)
            self.assertIn("HIGH", r.stdout)
            # explain the twins
            r = _cli("mac-lab", "explain", d, rows[1]["macs"],
                     rows[2]["macs"])
            self.assertEqual(r.returncode, 0)
            self.assertIn("DIFFERENT", r.stdout)
            # score both paths via stdin
            good = json.dumps([ro, [rows[1]["macs"]], [rows[2]["macs"]]])
            r = _cli("mac-lab", "score", d, "--submit", "-", inp=good)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertIn("100.0", r.stdout)
            bad = json.dumps([ro, [rows[1]["macs"], rows[2]["macs"]]])
            r = _cli("mac-lab", "score", d, "--submit", "-", inp=bad)
            self.assertEqual(r.returncode, 1)
            self.assertIn("TWIN TRAP", r.stdout)
            r = _cli("mac-lab", "exercises")
            self.assertEqual(r.returncode, 0)
            self.assertIn("randomization", r.stdout.lower())
            # no such dir
            r = _cli("mac-lab", "inventory", os.path.join(td, "nope"))
            self.assertEqual(r.returncode, 2)

    def test_track_lab_cli(self):
        with tempfile.TemporaryDirectory() as td:
            d = os.path.join(td, "tl")
            r = _cli("track-lab", "make-dataset", d, "--seed", "9")
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("Visitor-B", r.stdout)
            r = _cli("track-lab", "inventory", d)
            self.assertEqual(r.returncode, 0)
            with open(os.path.join(d, "ground-truth.csv")) as _fh:
                rows = list(csv.DictReader(_fh))
            stu = rows[0]["macs"]
            r = _cli("track-lab", "history", d, "--mac", stu)
            self.assertEqual(r.returncode, 0)
            self.assertIn("Visit timeline", r.stdout)
            r = _cli("track-lab", "patterns", d, "--mac", stu)
            self.assertEqual(r.returncode, 0)
            self.assertIn("lab-north → canteen", r.stdout)
            r = _cli("track-lab", "compare", d, "--since", "2d")
            self.assertEqual(r.returncode, 0)
            self.assertIn("retention", r.stdout.lower())
            ans = json.dumps({"q_identity": stu, "q_untrackable":
                              "Visitor-B", "q_edge": "lab-north>canteen",
                              "q_short_window": "insufficient",
                              "q_false_positive": rows[1]["macs"]})
            r = _cli("track-lab", "score", d, "--answers", "-", inp=ans)
            self.assertEqual(r.returncode, 0)
            self.assertIn("100.0", r.stdout)
            r = _cli("track-lab", "exercises")
            self.assertEqual(r.returncode, 0)
            self.assertIn("privacy", r.stdout.lower())
            r = _cli("track-lab", "patterns", d, "--mac", "AA:BB:CC:00:00:00")
            self.assertEqual(r.returncode, 0)  # unknown mac: prints nothing,
            # no crash

    def test_mac_lab_web_via_cli(self):
        with tempfile.TemporaryDirectory() as td:
            d = os.path.join(td, "ml")
            _cli("mac-lab", "make-dataset", d, "--seed", "8")
            proc = subprocess.Popen(
                [sys.executable, "-u", str(MAIN), "--no-banner", "-q",
                 "mac-lab", "web", d, "--port", "0", "--instructor-token",
                 "cto", "--duration", "25"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, cwd=str(ROOT))
            try:
                import time as _t
                deadline = _t.time() + 30
                out = ""
                while _t.time() < deadline and "Ctrl-C to stop" not in out:
                    line = proc.stdout.readline()
                    if not line:
                        break
                    out += line
                self.assertIn("student portal", out)
                self.assertIn("/i/cto", out)
            finally:
                proc.terminate()
                proc.wait(timeout=10)


if __name__ == "__main__":
    unittest.main(verbosity=2)
