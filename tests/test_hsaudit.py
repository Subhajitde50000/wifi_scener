#!/usr/bin/env python3
"""Feature 3 test battery: handshake capture & password-auditing lab.
All synthetic, all offline: cryptographically-real lab handshakes,
lab-only wordlists, real PBKDF2 cost."""
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
from wifiscanner import hsaudit as H  # noqa: E402


def _get(port, path):
    return urllib.request.urlopen(f"http://127.0.0.1:{port}{path}",
                                  timeout=60).read().decode("utf-8",
                                                            "ignore")


def _post(port, path, data=None):
    body = urllib.parse.urlencode(data or {}).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}",
                                 data=body, method="POST")
    return urllib.request.urlopen(req, timeout=60).read()


class HsDatasetTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.mkdtemp()
        H.generate_dataset(self.td, seed=3, fresh=True)
        self.ds = H.load_dataset(self.td)

    def test_layout_and_permissions(self):
        for tier in H.DIFFICULTY_ORDER:
            spec = self.ds["manifest"]["tiers"][tier]
            for k in ("capture", "wordlist"):
                p = os.path.join(self.td, spec[k])
                self.assertTrue(os.path.exists(p), p)
        for fn in ("manifest.json", "creds.json"):
            st = os.stat(os.path.join(self.td, fn))
            self.assertEqual(st.st_mode & 0o777, 0o600, fn)

    def test_deterministic_per_seed(self):
        td2 = tempfile.mkdtemp()
        H.generate_dataset(td2, seed=3, fresh=True)
        a = H.load_wordlist(self.td, "medium")
        b = H.load_wordlist(td2, "medium")
        self.assertEqual(a, b)
        ca = H._creds_of(self.td)["expert"]["password"]
        cb = H._creds_of(td2)["expert"]["password"]
        self.assertEqual(ca, cb)

    def test_refuses_clobber_without_fresh(self):
        with self.assertRaises(SystemExit):
            H.generate_dataset(self.td, seed=9, fresh=False)

    def test_everything_is_lab_scoped(self):
        man = self.ds["manifest"]
        self.assertTrue(man["ap_mac"].startswith(H.LAB_OUI))
        for d in man["devices"]:
            self.assertTrue(d["mac"].startswith(H.LAB_OUI), d)
        self.assertEqual(man["ssid"], H.LAB_SSID)
        for tier in H.DIFFICULTY_ORDER:
            words = H.load_wordlist(self.td, tier)
            self.assertGreater(len(words), 10)
            self.assertTrue(all(8 <= len(w) <= 64 for w in words))
        creds = H._creds_of(self.td)
        # weak creds are IN their lists; expert is NOT (resists)
        for tier in ("easy", "medium"):
            self.assertIn(creds[tier]["password"],
                          H.load_wordlist(self.td, tier))
        self.assertNotIn(creds["expert"]["password"],
                         H.load_wordlist(self.td, "expert"))

    def test_capture_is_cryptographically_real(self):
        cap = os.path.join(self.td, "captures/easy.pcap")
        an = H.analyze_handshake(cap)
        self.assertTrue(an["captured"], an)
        self.assertEqual(an["eapol"], 4)
        b = an["bundles"][0]
        self.assertEqual(b["msgs"], [1, 2, 3, 4])
        self.assertTrue(b["anonce"] and b["snonce"] and b["mic"])
        self.assertIn("complete 4-way", an["verdict"])


class HsEngineTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.mkdtemp()
        H.generate_dataset(self.td, seed=3, fresh=True)

    def _cap(self, tier):
        return os.path.join(self.td, "captures", f"{tier}.pcap")

    def test_weak_password_falls_fast(self):
        res = H.audit(self._cap("easy"), H.load_wordlist(self.td, "easy"))
        self.assertTrue(res["found"])
        self.assertEqual(res["password"], "coffee-shop")
        self.assertLessEqual(res["attempts"], 5)
        self.assertGreater(res["rate"], 1.0)
        self.assertEqual(res["state"], "audited")

    def test_buried_weak_password_costs_more(self):
        res = H.audit(self._cap("medium"),
                      H.load_wordlist(self.td, "medium"))
        self.assertTrue(res["found"])
        self.assertGreater(res["attempts"], 50)
        self.assertGreater(res["elapsed_s"], 0.05)

    def test_strong_password_resists_expert_list(self):
        res = H.audit(self._cap("expert"),
                      H.load_wordlist(self.td, "expert"))
        self.assertFalse(res["found"])
        self.assertEqual(res["attempts"],
                         len(H.load_wordlist(self.td, "expert")))
        self.assertIn("resisted", res["note"])
        self.assertEqual(res["state"], "captured")   # audit didn't upgrade

    def test_audit_of_wrong_capture_terms_cleanly(self):
        # capture without handshake → no audit (captured=False state)
        import struct
        empty = os.path.join(self.td, "empty.pcap")
        H.wpalab.write_pcap(empty, [])
        res = H.audit(empty, ["whatever123"])
        self.assertFalse(res["ok"])
        self.assertFalse(res["found"])

    def test_authenticate_three_states(self):
        # authenticated only with the audited credential
        a = H.authenticate(self._cap("easy"), "coffee-shop")
        self.assertTrue(a["authenticated"], a)
        self.assertIn("decrypted", a["evidence"])
        b = H.authenticate(self._cap("easy"), "wrong-answer-1")
        self.assertFalse(b["authenticated"])
        self.assertEqual(b["state"], "mic-mismatch")

    def test_scoring(self):
        good = {k: v[0] for k, v in H._HS_ANS.items()}
        self.assertEqual(H.score_hslab(good)[0], 100.0)
        bad = {k: "nope" for k in H._HS_ANS}
        self.assertLess(H.score_hslab(bad)[0], 60)
        part = dict(bad)
        part["q_states"] = "capture"   # alias → half credit
        sc = H.score_hslab(part)[0]
        self.assertEqual(sc, 10.0)

    def test_three_states_report_shape(self):
        st = H.three_states(self.td, "easy")
        self.assertTrue(st["captured"])
        self.assertTrue(st["audited"])
        self.assertIsNone(st["authenticated"])   # only proven on demand
        self.assertIn("≠", st["moral"])


class HsWebTests(unittest.TestCase):
    def test_web_flow(self):
        td = tempfile.mkdtemp()
        H.generate_dataset(td, seed=3, fresh=True)
        ds = H.load_dataset(td)
        store = H.DevLabStore(":memory:")
        app = H.HsLabApp(ds, store, "htk")
        srv = H.make_hs_server("127.0.0.1", 0, app)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            for p in ("/", "/analysis", "/audit", "/compare", "/three",
                      "/exercises", "/quiz"):
                body = _get(port, p)
                self.assertGreater(len(body), 800, p)
            dash = _get(port, "/i/htk")
            self.assertIn("instructor console", dash)
            self.assertIn("coffee-shop", dash)      # instructor creds shown
            # state hidden without token, visible with it
            with self.assertRaises(urllib.error.HTTPError) as cm:
                _get(port, "/api/state")
            self.assertEqual(cm.exception.code, 404)
            st = json.loads(_get(port, "/api/state?token=htk"))
            self.assertTrue(st["ok"])
            self.assertEqual(sorted(st["tiers"]),
                             ["easy", "expert", "medium"])
            # audit the easy tier, state flips
            res = json.loads(_post(port, "/api/run/easy", {}))
            self.assertTrue(res["found"], res)
            self.assertEqual(res["password"], "coffee-shop")
            self.assertIn("weak_found", app.completed)
            # authenticate with it
            res2 = json.loads(_post(port, "/authenticate",
                                    {"tier": "easy"}))
            self.assertTrue(res2["authenticated"], res2)
            self.assertIn("decrypted_post_handshake", app.completed)
            # expert exhausts (the lesson)
            res3 = json.loads(_post(port, "/api/run/expert", {}))
            self.assertFalse(res3["found"])
            self.assertIn("exhausted_list", app.completed)
            # quiz
            good = {k: v[0] for k, v in H._HS_ANS.items()}
            self.assertIn("100.0", _post(port, "/quiz", good).decode())
            # instructor controls: regenerate shifts creds + captures
            old = H._creds_of(td)["expert"]["password"]
            _post(port, "/i/htk/regenerate", {})
            new = H._creds_of(td)["expert"]["password"]
            self.assertNotEqual(old, new)
            self.assertEqual(len(app.results), 0)
            # reset
            _post(port, "/i/htk/reset", {})
            self.assertEqual(app.completed, set())
            # destroy
            n = json.loads(_post(port, "/i/htk/destroy", {}))["bytes"]
            self.assertGreater(n, 100)
            self.assertFalse(os.path.exists(
                os.path.join(td, "manifest.json")))
        finally:
            srv.shutdown()
            store.close()


class HsCLITests(unittest.TestCase):
    def _run(self, *argv):
        return subprocess.run(
            [sys.executable, os.path.join(ROOT, "main.py"),
             "--no-banner", "-q", *argv],
            capture_output=True, text=True, cwd=ROOT, timeout=600)

    def test_handshake_lab_cli(self):
        with tempfile.TemporaryDirectory() as td:
            db = os.path.join(td, "hs")
            r = self._run("handshake-lab", "make-dataset", db,
                          "--seed", "3", "--fresh")
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("handshake dataset written", r.stdout)
            r = self._run("handshake-lab", "inventory", "--db", db)
            self.assertIn("LAB-CLI-01", r.stdout)
            r = self._run("handshake-lab", "analyze", "--db", db,
                          "--tier", "easy")
            self.assertEqual(r.returncode, 0, r.stdout)
            self.assertIn("captured=True", r.stdout)
            r = self._run("handshake-lab", "audit", "--db", db,
                          "--tier", "easy", "--quiet")
            self.assertEqual(r.returncode, 0, r.stdout)
            self.assertIn("found=True", r.stdout)
            r = self._run("handshake-lab", "audit", "--db", db,
                          "--tier", "expert", "--quiet")
            self.assertEqual(r.returncode, 1)
            self.assertIn("found=False", r.stdout)
            r = self._run("handshake-lab", "compare", "--db", db)
            self.assertIn("FOUND", r.stdout)
            self.assertIn("resisted", r.stdout)
            r = self._run("handshake-lab", "authenticate", "--db", db,
                          "--tier", "easy", "--password", "coffee-shop")
            self.assertEqual(r.returncode, 0, r.stdout)
            self.assertIn("authenticated", r.stdout)
            r = self._run("handshake-lab", "authenticate", "--db", db,
                          "--tier", "easy", "--password", "wrong-thing")
            self.assertEqual(r.returncode, 1)
            r = self._run("handshake-lab", "exercises")
            self.assertIn("Audit a weak password", r.stdout)
            good = os.path.join(td, "g.json")
            with open(good, "w") as fh:
                json.dump({k: v[0] for k, v in H._HS_ANS.items()}, fh)
            r = self._run("handshake-lab", "score", "--answers", good)
            self.assertEqual(r.returncode, 0)
            self.assertIn("100.0", r.stdout)


if __name__ == "__main__":
    unittest.main()
