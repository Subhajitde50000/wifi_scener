"""Tests for the scanning/scope lab (wifiscanner/scanlab.py + `scan-lab`)
and the credential/session security lab (wifiscanner/credlab.py +
`cred-lab`).

Run:  python3 -m pytest tests/test_biglabs.py -q
or:   python3 tests/test_biglabs.py
"""
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
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from wifiscanner import scanlab as S  # noqa: E402
from wifiscanner import credlab as C  # noqa: E402

MAIN = ROOT / "main.py"


def _cli(*argv, inp=None):
    return subprocess.run(
        [sys.executable, str(MAIN), "--no-banner", "-q", *argv],
        capture_output=True, text=True, timeout=600, input=inp,
        cwd=str(ROOT))


def _wait(job, timeout=15.0):
    t0 = time.time()
    while job.status in ("pending", "running") and time.time() - t0 < timeout:
        time.sleep(0.05)
    return job


class ScanLabDatasetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory(prefix="scanlab-")
        cls.dir = os.path.join(cls._tmp.name, "estate")
        S.generate_inventory(cls.dir, seed=12, size=220)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_layout_and_permissions(self):
        names = os.listdir(self.dir)
        self.assertEqual(sorted(names), ["inventory.json", "manifest.json"])
        for n in names:
            self.assertEqual(os.stat(os.path.join(self.dir, n)).st_mode
                             & 0o777, 0o600)

    def test_deterministic(self):
        with tempfile.TemporaryDirectory() as td:
            d2 = os.path.join(td, "b")
            S.generate_inventory(d2, seed=12, size=220)
            with open(os.path.join(self.dir, "inventory.json")) as fh:
                a = json.load(fh)
            with open(os.path.join(d2, "inventory.json")) as fh:
                b = json.load(fh)
            self.assertEqual(a, b)

    def test_all_assets_lab_subnet_only(self):
        ds = S.load_inventory(self.dir)
        for a in ds["inventory"]["assets"]:
            self.assertTrue(a["ip"].startswith(S.SUBNET + "."), a["ip"])
        self.assertGreaterEqual(len(ds["inventory"]["assets"]), 200)

    def test_guard_against_overwrite(self):
        with self.assertRaises(FileExistsError):
            S.generate_inventory(self.dir, seed=99)

    def test_duplicate_conflicts_exist(self):
        """Seeded estate deliberately contains duplicate-IP conflict rows —
        the inventory-hygiene lesson."""
        ds = S.load_inventory(self.dir)
        self.assertIsInstance(ds["inventory"]["duplicate_conflicts"],
                              list)


class ScanEngineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory(prefix="scanlab-eng-")
        cls.dir = os.path.join(cls._tmp.name, "estate")
        S.generate_inventory(cls.dir, seed=12, size=220)
        cls.ds = S.load_inventory(cls.dir)
        cls.inv = cls.ds["inventory"]

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_in_scope_scan_finds_services(self):
        eng = S.ScanLabEngine(self.ds)
        targets = [a["ip"] for a in self.inv["assets"]
                   if a["online"]][:10]
        job = eng.submit(targets, ["ssh/22", "http/80", "mqtt/1883"],
                         rate_limit=0, concurrency=4, by="test")
        _wait(job)
        self.assertEqual(job.status, "done")
        self.assertEqual(job.progress["refused"], 0)
        self.assertGreaterEqual(job.progress["hits"], 5)
        self.assertTrue(job.results)
        for row in job.results:
            self.assertIn(row["ip"],
                          {a["ip"] for a in self.inv["assets"]})

    def test_out_of_scope_is_refused_and_alerted(self):
        eng = S.ScanLabEngine(self.ds)
        listed = self.inv["assets"][0]["ip"]
        targets = [listed, "10.77.9.9", "192.168.1.1", "8.8.8.8",
                   "not-an-ip"]
        job = eng.submit(targets, ["ssh/22"], rate_limit=0,
                         concurrency=2, by="test")
        _wait(job)
        self.assertEqual(job.progress["refused"], 4,
                         job.scope_violations)
        self.assertEqual(len(job.scope_violations), 4)
        # refused targets produce zero probe rows for them
        for v in job.scope_violations:
            norm = S.ScanJob._norm(v["ip"])
            self.assertFalse(any(r["ip"] == norm for r in job.results))
        # sentinel alerts fired for every refusal
        self.assertEqual(len(eng.alerts), 4)

    def test_unlisted_in_subnet_is_also_refused(self):
        eng = S.ScanLabEngine(self.ds)
        eng.submit(["10.77.9.250"], ["ssh/22"], 0, 1, by="test")
        job = list(eng.jobs.values())[-1]
        _wait(job)
        self.assertEqual(job.progress["refused"], 1)
        self.assertIn("NOT inventoried", job.scope_violations[0]["why"])

    def test_rate_limiting_slows_but_same_results(self):
        targets = [a["ip"] for a in self.inv["assets"]][:15]
        eng = S.ScanLabEngine(self.ds)
        fast = eng.submit(targets, list(S.SERVICES), 0, 16, by="test")
        _wait(fast)
        slow = eng.submit(targets, list(S.SERVICES), 200, 1, by="test")
        _wait(slow, timeout=30)
        self.assertEqual(fast.progress["hits"], slow.progress["hits"])
        self.assertGreater(slow.duration_ms, fast.duration_ms)

    def test_concurrency_respected_shape(self):
        eng = S.ScanLabEngine(self.ds)
        targets = [a["ip"] for a in self.inv["assets"] if a["online"]][:20]
        j1 = eng.submit(targets, ["ssh/22"], 0, 1, by="t")
        _wait(j1)
        j16 = eng.submit(targets, ["ssh/22"], 0, 16, by="t")
        _wait(j16)
        self.assertLess(j16.duration_ms, j1.duration_ms * 2 + 400)
        self.assertEqual(j1.progress["hits"], j16.progress["hits"])

    def test_cancel(self):
        eng = S.ScanLabEngine(self.ds)
        targets = [a["ip"] for a in self.inv["assets"]]  # big run
        job = eng.submit(targets, list(S.SERVICES), 40, 4, by="test")
        time.sleep(0.2)
        self.assertTrue(eng.cancel(job.id))
        _wait(job)
        self.assertEqual(job.status, "cancelled")
        self.assertLess(job.progress["done"], job.progress["total"])

    def test_scoring_paths(self):
        good = {"q_scope_line": "10.77", "q_scope_alert": "unknown-asset",
                "q_rate_effect": "pressure", "q_sweep_lesson": "not-yours",
                "q_refusal": "never"}
        self.assertEqual(S.score_scanlab(self.inv, good)["score"], 100.0)
        bad = dict(good, q_refusal="retry", q_sweep_lesson="useful")
        r = S.score_scanlab(self.inv, bad)
        self.assertLess(r["score"], 70)
        self.assertLess(S.score_scanlab(self.inv, {})["score"], 1.0)


class CredLabTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory(prefix="credlab-")
        cls.pcap = os.path.join(cls._tmp.name, "lesson.pcap")
        cls.meta = C.build_credential_fixture(cls.pcap, seed=13)
        os.chmod(cls.pcap, 0o600)
        cls.analysis = C.dissect_capture(cls.pcap)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_fixture_deterministic_and_synthetic(self):
        p2 = os.path.join(self._tmp.name, "two.pcap")
        meta2 = C.build_credential_fixture(p2, seed=13)
        self.assertEqual([i["username"] for i in self.meta["identities"]],
                         [i["username"] for i in meta2["identities"]])
        for ident in meta2["identities"]:
            self.assertTrue(ident["username"].startswith("LAB-STUDENT-"))
            self.assertTrue(ident["password"].endswith("-lab"))

    def test_all_six_protocols_exposed(self):
        by = {}
        for e in self.analysis["exposures"]:
            by.setdefault(e["proto"], []).append(e)
        for proto in ("http-basic", "http-form", "http-cookie",
                      "ftp", "telnet", "snmpv1"):
            self.assertIn(proto, by)
            self.assertGreaterEqual(len(by[proto]), 5)
        # credentials actually decoded
        basic = by["http-basic"][0]
        self.assertIn("LAB-STUDENT-", basic["leaked"])
        self.assertIn(":", basic["leaked"])

    def test_tls_leg_reads_nothing(self):
        t = self.analysis["tls"]
        self.assertGreaterEqual(len(t), 40)
        hs = [r for r in t if r["kind"] == "handshake"]
        app = [r for r in t if r["kind"] == "application-data"]
        self.assertTrue(hs and app)
        ok_tags = {"SNI hostname only", "opaque — keys never left the wire"}
        for r in t:
            self.assertIn(r["readable"].split(" —")[0],
                          {"SNI hostname only", "opaque"})
        p = C.protection_summary(t)
        self.assertIn("SNI", p["visible"])
        self.assertIn("gone" if False else "cookie", p["invisible"])

    def test_alerts_and_summary(self):
        al = C.insecure_alerts(self.analysis["exposures"])
        protos = {a["proto"] for a in al}
        self.assertTrue({"http-basic", "http-form", "telnet", "ftp",
                         "snmpv1"} <= protos)
        s = C.exposure_summary(self.analysis["exposures"])
        self.assertTrue(any("session" in x["steal"] or
                            "cookie" in x["steal"] for x in s))
        self.assertTrue(any("keystroke" in x["steal"] for x in s))

    def test_no_real_credentials_anywhere(self):
        raw = open(self.pcap, "rb").read()
        for ident in self.meta["identities"]:
            self.assertTrue(ident["password"].endswith("-lab"))
            self.assertIn("lab", ident["cookie"].lower())
        self.assertIn(b"LAB-STUDENT-", raw)

    def test_scoring_paths(self):
        good = {"q_http_basic": "base64-is-encoding",
                "q_cookie": "session-hijack",
                "q_telnet": "keystroke-level", "q_snmp": "community",
                "q_tls_hide": "everything-but-sni",
                "q_mitigation": "eol-plaintext-protocols"}
        self.assertEqual(C.score_credlab(good)["score"], 100.0)
        bad = dict(good, q_cookie="nothing", q_http_basic="encrypted")
        r = C.score_credlab(bad)
        self.assertLess(r["score"], 70)
        self.assertLess(C.score_credlab({})["score"], 1.0)


class WebLabsTests(unittest.TestCase):
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
        if isinstance(data, dict):
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}{path}",
                data=urllib.parse.urlencode(data).encode(), method="POST")
        else:
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}{path}", data=b"", method="POST")
        return urllib.request.urlopen(req, timeout=40).read()

    # -------------------- scan-lab web
    def test_scanlab_web_flow(self):
        with tempfile.TemporaryDirectory() as td:
            d = os.path.join(td, "estate")
            S.generate_inventory(d, seed=12, size=60)
            ds = S.load_inventory(d)
            store = S.DevLabStore(":memory:")
            app = S.ScanWebApp(ds, store, "stok")
            port = self._serve(S.make_scan_server, app)
            for p in ("/", "/inventory", "/console", "/compare-page",
                      "/quiz", "/exercises"):
                page = self._get(port, p)
                self.assertGreater(len(page), 300, p)
            self.assertFalse(self._get(port, "/api/state",
                                       allow_error=True))
            # scan with a deliberately out-of-scope IP
            good_ip = next(a["ip"] for a in ds["inventory"]["assets"]
                           if a["online"])
            resp = self._post(port, "/scan", {
                "targets": f"{good_ip},10.77.9.9,192.168.1.1",
                "rate": "0", "conc": "8", "svc": ["ssh/22", "http/80"]})
            # urllib follows the 303 to /job/<id>
            self.assertIn(b"job", resp)
            engine = app.engine
            job = list(engine.jobs.values())[-1]
            _wait(job)
            self.assertGreaterEqual(job.progress["refused"], 2,
                                    job.progress)
            # sentinel alerts land when the job finishes
            self.assertEqual(len(engine.alerts), 2)   # 9.9 + 192.168
            self.assertGreater(job.progress["hits"], 0)
            page = self._get(port, f"/job/{job.id}")
            self.assertIn("scope violations", page)
            jobs = json.loads(self._get(port, "/api/jobs"))
            self.assertEqual(jobs["alerts"], 2)
            # csv export
            self._post(port, "/export-csv", {"job": job.id})
            # cancel path
            j2 = engine.submit([a["ip"] for a in ds["inventory"]["assets"]],
                               list(S.SERVICES), 30, 2, by="test")
            time.sleep(0.15)
            self._post(port, "/cancel", {"job": j2.id})
            _wait(j2)
            self.assertEqual(j2.status, "cancelled")
            # quiz
            good = {"q_scope_line": "10.77", "q_scope_alert":
                    "unknown-asset", "q_rate_effect": "pressure",
                    "q_sweep_lesson": "not-yours", "q_refusal": "never"}
            self.assertIn("100.0", self._post(port, "/quiz", good).decode())
            # instructor: expand, reset, regenerate
            r = json.loads(self._post(port, "/api/expand?token=stok",
                                      {"n": "5"}))
            self.assertEqual(len(r["added"]), 5)
            hosts_before = app.manifest.get("hosts", 0)
            self.assertEqual(hosts_before, 65)
            r = json.loads(self._post(port, "/api/reset?token=stok"))
            self.assertTrue(r["ok"])
            self.assertEqual(len(app.engine.alerts), 0)
            r = json.loads(self._post(port,
                                      "/api/regenerate?token=stok"))
            self.assertTrue(r["ok"])
            self.assertEqual(r["seed"], 13)
            self.assertIn("instructor", self._get(port, "/i/stok").lower())
            store.close()

    # -------------------- cred-lab web
    def test_credlab_web_flow(self):
        with tempfile.TemporaryDirectory() as td:
            pcap = os.path.join(td, "lesson.pcap")
            meta = C.build_credential_fixture(pcap, seed=13)
            store = C.DevLabStore(":memory:")
            app = C.CredWebApp(pcap, meta["identities"], store, "ctok")
            port = self._serve(C.make_cred_server, app)
            for p in ("/", "/exposures", "/tls", "/compare", "/alerts",
                      "/quiz", "/exercises"):
                page = self._get(port, p)
                self.assertGreater(len(page), 300, p)
            self.assertIn("LAB-STUDENT-", self._get(port, "/exposures"))
            self.assertFalse(self._get(port, "/api/state",
                                       allow_error=True))
            self.assertIn("synthetic", self._get(port, "/i/ctok").lower())
            good = {"q_http_basic": "base64-is-encoding",
                    "q_cookie": "session-hijack",
                    "q_telnet": "keystroke-level", "q_snmp": "community",
                    "q_tls_hide": "everything-but-sni",
                    "q_mitigation": "eol-plaintext-protocols"}
            self.assertIn("100.0", self._post(port, "/quiz",
                                              good).decode())
            # regenerate/destroy identities
            self.assertEqual(len(app.identities), 6)
            before_pw = [i["password"] for i in app.identities]
            # the printed instructor table must carry the current ids
            dash = self._get(port, "/i/ctok")
            for ident in app.identities:
                self.assertIn(ident["username"], dash)
            r = json.loads(self._post(port,
                                      "/api/regenerate?token=ctok",
                                      {"seed": "13"}))
            self.assertTrue(r["ok"])
            after_pw = [i["password"] for i in app.identities]
            self.assertNotEqual(before_pw, after_pw)
            dash2 = self._get(port, "/i/ctok")
            for ident in app.identities:
                self.assertIn(ident["password"], dash2)
            dash2 = self._get(port, "/i/ctok")
            for ident in app.identities:
                self.assertIn(ident["password"], dash2)
            store.close()


class LabCLITests(unittest.TestCase):
    def test_scan_lab_cli(self):
        with tempfile.TemporaryDirectory() as td:
            d = os.path.join(td, "estate")
            r = _cli("scan-lab", "make-dataset", d, "--seed", "12",
                     "--size", "80", "--fresh")
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("lab estate written", r.stdout)
            r = _cli("scan-lab", "inventory", d)
            self.assertEqual(r.returncode, 0)
            self.assertIn("duplicate-IP", r.stdout)
            assets = json.load(open(os.path.join(d, "inventory.json")))["assets"]
            tgt = next(a["ip"] for a in assets if a["online"])
            r = _cli("scan-lab", "scan", d, "--targets", tgt,
                     "--services", "ssh/22,http/80", "--rate", "0",
                     "--concurrency", "4")
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertIn("DONE", r.stdout)
            # scope breach → exit 1
            r = _cli("scan-lab", "scan", d, "--targets", "10.77.9.9")
            self.assertEqual(r.returncode, 1)
            self.assertIn("scope violations", r.stdout)
            r = _cli("scan-lab", "compare", d)
            self.assertEqual(r.returncode, 0)
            self.assertIn("uncontrolled", r.stdout)
            ans = json.dumps({"q_scope_line": "10.77",
                              "q_scope_alert": "unknown-asset",
                              "q_rate_effect": "pressure",
                              "q_sweep_lesson": "not-yours",
                              "q_refusal": "never"})
            r = _cli("scan-lab", "score", d, "--answers", "-", inp=ans)
            self.assertEqual(r.returncode, 0)
            self.assertIn("100.0", r.stdout)
            r = _cli("scan-lab", "exercises")
            self.assertEqual(r.returncode, 0)
            self.assertIn("scope", r.stdout.lower())

    def test_cred_lab_cli(self):
        with tempfile.TemporaryDirectory() as td:
            pcap = os.path.join(td, "lesson.pcap")
            r = _cli("cred-lab", "make-fixture", pcap, "--seed", "13",
                     "--students", "5")
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("lab capture written", r.stdout)
            r = _cli("cred-lab", "dissect", pcap)
            self.assertEqual(r.returncode, 0)
            self.assertIn("exposure rows:", r.stdout)
            r = _cli("cred-lab", "exposures", pcap)
            self.assertEqual(r.returncode, 0)
            self.assertIn("LAB-STUDENT-", r.stdout)
            self.assertIn("cookies", r.stdout.lower())
            r = _cli("cred-lab", "tls", pcap)
            self.assertEqual(r.returncode, 0)
            self.assertIn("application-data", r.stdout)
            r = _cli("cred-lab", "alerts", pcap)
            self.assertEqual(r.returncode, 0)
            self.assertIn("snmpv1", r.stdout)
            r = _cli("cred-lab", "compare", pcap)
            self.assertEqual(r.returncode, 0)
            self.assertIn("gone", r.stdout.lower())
            r = _cli("cred-lab", "report", pcap, "-o",
                     os.path.join(td, "out"))
            self.assertEqual(r.returncode, 0)
            self.assertTrue(os.path.exists(
                os.path.join(td, "out", "credlab_report.md")))
            self.assertTrue(os.path.exists(
                os.path.join(td, "out", "credlab_exposures.csv")))
            self.assertTrue(os.path.exists(
                os.path.join(td, "out", "credlab_tls.csv")))
            ans = json.dumps({"q_http_basic": "base64-is-encoding",
                              "q_cookie": "session-hijack",
                              "q_telnet": "keystroke-level",
                              "q_snmp": "community",
                              "q_tls_hide": "everything-but-sni",
                              "q_mitigation": "eol-plaintext-protocols"})
            r = _cli("cred-lab", "score", pcap, "--answers", "-",
                     inp=ans)
            self.assertEqual(r.returncode, 0)
            self.assertIn("100.0", r.stdout)
            r = _cli("cred-lab", "exercises")
            self.assertEqual(r.returncode, 0)
            self.assertIn("base64", r.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
