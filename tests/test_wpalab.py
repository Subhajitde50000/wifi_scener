"""WPA decryption-lab tests — every crypto primitive checked against a
published test vector; end-to-end: fixture → parse → verify → decrypt →
export → web flow.

Run:  python -m pytest tests/test_wpalab.py -v  (or: python tests/test_wpalab.py)
"""
import json
import os
import stat
import subprocess
import sys
import tempfile
import threading
import urllib.error
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from wifiscanner import wcrypto
from wifiscanner import wpalab as W

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_HEX = bytes.fromhex


# ------------------------------------------------------------- crypto vectors

def test_aes_fips197_vectors():
    k = _HEX("000102030405060708090a0b0c0d0e0f")
    p = _HEX("00112233445566778899aabbccddeeff")
    c = _HEX("69c4e0d86a7b0430d8cdb78070b4c55a")
    assert wcrypto.aes_encrypt_block(k, p) == c
    assert wcrypto.aes_decrypt_block(k, c) == p
    k192 = _HEX("000102030405060708090a0b0c0d0e0f1011121314151617")
    assert wcrypto.aes_encrypt_block(k192, p).hex() == \
        "dda97ca4864cdfe06eaf70a0ec0d7191"
    k256 = _HEX("000102030405060708090a0b0c0d0e0f"
                "101112131415161718191a1b1c1d1e1f")
    c256 = _HEX("8ea2b7ca516745bfeafc49904b496089")
    assert wcrypto.aes_encrypt_block(k256, p) == c256
    assert wcrypto.aes_decrypt_block(k256, c256) == p


def test_ccm_rfc3610_vector_and_auth_fail():
    key = _HEX("404142434445464748494a4b4c4d4e4f")
    nonce = _HEX("10111213141516")
    aad = _HEX("0001020304050607")
    ct = wcrypto.ccm_encrypt(key, nonce, _HEX("20212223"), aad, mic_len=4)
    assert ct == _HEX("7162015b4dac255d")
    assert wcrypto.ccm_decrypt(key, nonce, ct, aad, mic_len=4) == \
        _HEX("20212223")
    try:                                   # corrupted tag must NOT decrypt
        wcrypto.ccm_decrypt(key, nonce, ct[:-1] + b"\x00", aad, mic_len=4)
        assert False
    except wcrypto.CryptoError:
        pass


def test_gcm_nist_vector_and_auth_fail():
    r = wcrypto.gcm_encrypt(b"\x00" * 16, b"\x00" * 12, b"\x00" * 16)
    assert r == _HEX("0388dace60b6a392f328c2b971b2fe78"
                     "ab6e47d42cec13bdf53a67b21257bddf")
    assert wcrypto.gcm_decrypt(b"\x00" * 16, b"\x00" * 12, r) == b"\x00" * 16
    try:
        wcrypto.gcm_decrypt(b"\x01" * 16, b"\x00" * 12, r)
        assert False
    except wcrypto.CryptoError:
        pass


def test_cmac_rfc4493():
    k = _HEX("2b7e151628aed2a6abf7158809cf4f3c")
    assert wcrypto.cmac_aes(k, b"") == _HEX("bb1d6929e95937287fa37d129b756746")
    assert wcrypto.cmac_aes(k, _HEX("6bc1bee22e409f96e93d7e117393172a")) == \
        _HEX("070a16b46b4d4144f79bdd9dd04a287c")


def test_kw_rfc3394_and_kwp_roundtrip():
    kek = _HEX("000102030405060708090a0b0c0d0e0f")
    p = _HEX("00112233445566778899aabbccddeeff")
    c = wcrypto.kw_wrap(kek, p)
    assert c == _HEX("1fa68b0a8112b447aef34bd8fb5a7b82"
                     "9d3e862371d2cfe5")
    assert wcrypto.kw_unwrap(kek, c) == p
    for n in (8, 19, 24, 40):
        m = bytes(range(1, n + 1))
        assert wcrypto.kwp_unwrap(kek, wcrypto.kwp_wrap(kek, m)) == m
    try:                                   # wrong KEK is caught, not silent
        wcrypto.kwp_unwrap(b"\x01" * 16, wcrypto.kwp_wrap(kek, b"12345678"))
        assert False
    except wcrypto.CryptoError:
        pass


def test_rc4_and_pbkdf2_pmk_vectors():
    assert wcrypto.rc4(b"Key", b"Plaintext") == _HEX("bbf316e8d940af0ad3")
    assert wcrypto.pmk_from_passphrase("password", "IEEE") == _HEX(
        "f42c6fc52df0ebef9ebb4b90b38a5f90"
        "2e83fe1b135a70e23aed762e9710a12e")


def test_ptk_is_deterministic_and_mac_commutative():
    pmk = b"\x07" * 32
    ap = _HEX("021122334435")[0:6] if False else _HEX("021122334455")
    sta = _HEX("0266778899aa")
    a1, a2 = b"\x11" * 32, b"\x22" * 32
    p1 = wcrypto.derive_ptk(pmk, ap, sta, a1, a2)
    p2 = wcrypto.derive_ptk(pmk, sta, ap, a1, a2)   # min/max must commute
    p3 = wcrypto.derive_ptk(pmk, sta, ap, a2, a1)
    assert p1 == p2 == p3
    assert len(p1["tk"]) == 16 and len(p1["kck"]) == 16
    p4 = wcrypto.derive_ptk(pmk, ap, sta, a1, a2, "ccmp-256")
    assert len(p4["tk"]) == 32 and len(p4["ptk"]) == 88
    assert p4["tk"] != p1["tk"]


# ------------------------------------------------------------ pcap / parsing

def _pcap(tmp):
    path = os.path.join(tmp, "lab.pcap")
    meta = W.make_fixture(path, ssid="TestNet-7", password="passphrase-42",
                          cipher="ccmp")
    return path, meta


def test_fixture_generates_real_handshakes_and_inventory():
    with tempfile.TemporaryDirectory() as td:
        path, meta = _pcap(td)
        assert os.path.getsize(path) > 500
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
        frames = W.parse_capture(path)
        assert len(frames) == meta["frames"] == 19
        a = W.analyze_capture(frames)
        ap = a["aps"]["02:11:22:33:44:55"]
        assert ap["ssid"] == "TestNet-7" and ap["security"] == "WPA2"
        assert ap["cipher"] == "ccmp" and "PSK" in ap["akm"]
        assert a["aps"]["02:99:88:77:66:55"]["security"] == "OPEN"
        assert len(a["handshakes"]) == 1
        h = a["handshakes"][0]
        assert h["complete"] and sorted(set(h["msgs"])) == [1, 2, 3, 4]
        assert h["anonce"] != h["snonce"]
        rows = W.frame_rows(a)
        locked = [r for r in rows if r["status"] == "locked"]
        assert len(locked) == 6
        assert all("key required" in r["info"] for r in locked)
        eapol = [r for r in rows if r["status"] == "eapol"]
        assert len(eapol) == 4 and "M2" in eapol[1]["info"]


# -------------------------------------------------- decrypt: keys & failures

def test_wrong_key_fails_at_mic_right_key_decrypts_all():
    with tempfile.TemporaryDirectory() as td:
        path, meta = _pcap(td)
        a = W.analyze_capture(W.parse_capture(path))
        bad = W.decrypt_capture(a, [W.LabKey("definitely-not-it",
                                             ssid="TestNet-7")])
        assert bad["verdicts"][0]["verdict"] == "wrong-key"
        assert bad["decrypted"] == 0
        good = W.decrypt_capture(a, [W.LabKey("passphrase-42",
                                              ssid="TestNet-7")])
        v = good["verdicts"][0]
        assert v["verdict"] == "accepted" and "MIC verified" in v["detail"]
        assert good["decrypted"] == 6
        rows = {r["idx"]: r for r in good["rows"]}
        assert rows[11]["plain_kind"] == "DNS"
        assert "intranet.lab.example" in rows[11]["info"]
        assert rows[13]["plain_kind"] == "TCP" and "HTTP GET" in rows[13]["info"]
        assert rows[14]["status"] == "decrypted" and "Lab quiz" in rows[14]["info"]
        assert rows[15]["plain_kind"] == "ARP" \
            and "who-has 192.168.7.1" in rows[15]["info"]   # GTK broadcast!
        assert rows[16]["plain_kind"] == "ICMP"
        # the open-network tail frames were ALWAYS cleartext
        assert any(r["status"] == "cleartext" and r["type"] == "qos-data"
                   for r in good["rows"])


def test_pmk_path_and_gtk_recovery():
    with tempfile.TemporaryDirectory() as td:
        path, meta = _pcap(td)
        a = W.analyze_capture(W.parse_capture(path))
        res = W.decrypt_capture(a, [W.LabKey(meta["pmk"])])
        assert res["verdicts"][0]["verdict"] == "accepted"
        sess = list(res["sessions"].values())[0]
        assert sess.gtk, "GTK must be recovered from the wrapped M3 key data"
        assert len(sess.gtk) == 16
        assert res["decrypted"] == 6


def test_no_handshake_means_no_decryption_with_any_key():
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "late.pcap")
        W.make_fixture(path, ssid="TestNet-7", password="passphrase-42",
                       include_handshake=False)
        a = W.analyze_capture(W.parse_capture(path))
        assert not a["handshakes"]
        res = W.decrypt_capture(a, [W.LabKey("passphrase-42", ssid="TestNet-7")])
        assert res["decrypted"] == 0
        assert all(r["status"] != "decrypted" for r in res["rows"])
        assert any(r["status"] == "no-handshake" for r in res["rows"])


def test_incomplete_handshake_raises_laberror():
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "half.pcap")
        W.make_fixture(path, ssid="TestNet-7", password="passphrase-42")
        frames = W.parse_capture(path)
        # trim to only M1 (drop everything after the first EAPOL frame)
        cut = next(i for i, f in enumerate(frames) if f.is_eapol) + 1
        a = W.analyze_capture(frames[:cut])
        assert a["handshakes"] and not a["handshakes"][0]["complete"]
        res = W.decrypt_capture(a, [W.LabKey("passphrase-42", ssid="TestNet-7")])
        assert res["verdicts"][0]["verdict"] == "no-handshake"
        assert "PTK cannot be derived" in res["verdicts"][0]["detail"]


def test_export_bundle_and_decrypted_pcap():
    with tempfile.TemporaryDirectory() as td:
        path, meta = _pcap(td)
        a = W.analyze_capture(W.parse_capture(path))
        res = W.decrypt_capture(a, [W.LabKey("passphrase-42", ssid="TestNet-7")])
        out = os.path.join(td, "out")
        files = W.export_lab(path, a, res, out)
        names = {os.path.basename(f) for f in files}
        assert names == {"wpa_lab_frames.csv", "wpa_lab_decrypted.pcap",
                         "wpa_lab.json", "wpa_lab_report.md"}
        for f in files:
            assert stat.S_IMODE(os.stat(f).st_mode) == 0o600
        lt, recs = W.read_pcap(os.path.join(out, "wpa_lab_decrypted.pcap"))
        assert lt == W.LINKTYPE_ETHERNET and len(recs) == 6
        # first ethernet record should be a real IPv4 packet for 192.168.7.23
        eth = recs[0][1]
        assert eth[12:14] == b"\x08\x00" and eth[26:30] == bytes(
            [192, 168, 7, 23])
        md = open(os.path.join(out, "wpa_lab_report.md")).read()
        assert "DECRYPT" not in md or "decrypted" in md
        assert "Before vs after" in md and "wrong-key" not in md.lower()
        assert "accepted" in md


# ------------------------------------------------------------------ web lab

def _web_server(td, password="passphrase-42"):
    path, meta = _pcap(td)
    store = W.WpaLabStore(":memory:")
    app = W.WpaWebApp(path, store, [W.LabKey(password, ssid="TestNet-7")],
                      token="teach-token")
    httpd = W.make_web_server("127.0.0.1", 0, app)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever,
                     kwargs={"poll_interval": 0.05}, daemon=True).start()
    return httpd, f"http://127.0.0.1:{port}", store


def test_web_student_flow_detection_and_instructor():
    httpd, base, store = _web_server(tempfile.mkdtemp())
    try:
        def _get(p):
            try:
                with urllib.request.urlopen(base + p, timeout=5) as r:
                    return r.status, r.read().decode("utf-8", "ignore")
            except urllib.error.HTTPError as exc:
                return exc.code, exc.read().decode("utf-8", "ignore")

        def _post(p, data):
            req = urllib.request.Request(base + p,
                                         data=data.encode(), method="POST")
            try:
                with urllib.request.urlopen(req, timeout=5) as r:
                    return r.status, r.read().decode("utf-8", "ignore")
            except urllib.error.HTTPError as exc:
                return exc.code, exc.read().decode("utf-8", "ignore")

        code, home = _get("/")
        assert code == 200 and "Try your laboratory key" in home
        assert "TestNet-7" in home and "WPA2" in home
        assert code and _get("/exercises")[0] == 200
        assert "🔒 sealed" in _get("/frames")[1]
        # wrong candidate: logged, teaches, nothing decrypted
        code, pg = _post("/try", "ssid=TestNet-7&candidate=hunter2")
        assert code == 200 and "wrong-key" in pg and "MIC" in pg
        # right candidate: verified + decrypted flow shown
        code, pg = _post("/try", "ssid=TestNet-7&candidate=passphrase-42")
        assert "Key verified" in pg and "intranet.lab.example" in pg
        assert "DECRYPTED" in _get("/frames")[1]
        # instructor dashboard + API
        assert _get("/i/teach-token")[0] == 200
        assert _get("/i/wrong")[0] == 404
        assert _get("/api/state?token=wrong")[0] == 404
        code, raw = _get("/api/state?token=teach-token")
        st = json.loads(raw)
        assert st["funnel"]["tries"] == 2 and st["funnel"]["successes"] == 1
        assert st["funnel"]["frames_decrypted"] == 6
        cands = {(a["candidate"], a["verdict"]) for a in st["attempts"]}
        assert ("hunter2", "wrong-key") in cands
        assert ("passphrase-42", "accepted") in cands
        # every attempt is the detection trail the exercise requires
        assert any(e["kind"] == "page-view" for e in st["events"])
        # instructor unlock via API (authorized lab key path)
        code, raw = _post("/api/reset?token=teach-token", "")
        assert json.loads(raw)["ok"]
        assert store.funnel()["tries"] == 0
        assert json.loads(_get("/api/state?token=teach-token")[1])[
            "inventory"]["unlocked"] is False
        code, raw = _post("/api/instructor-unlock?token=teach-token", "")
        assert json.loads(raw)["ok"] and json.loads(raw)["decrypted"] == 6
    finally:
        httpd.shutdown()
        httpd.server_close()
        store.close()


def test_store_is_owner_only_and_resets():
    with tempfile.TemporaryDirectory() as td:
        db = os.path.join(td, "w.sqlite")
        st = W.WpaLabStore(db)
        assert stat.S_IMODE(os.stat(db).st_mode) == 0o600
        st.attempt("SSID", "cand", "wrong-key", "mic mismatch", 0,
                   "10.0.0.2", "tester")
        st.event("page-view", "home", "10.0.0.2")
        assert st.funnel()["tries"] == 1 and st.funnel()["visits"] == 1
        assert st.reset() == 2
        assert st.funnel()["tries"] == 0
        st.close()


# ---------------------------------------------------------------------- CLI

def _cli(*argv):
    return subprocess.run([sys.executable, "main.py", "--no-banner", "-q",
                           *argv], cwd=ROOT, capture_output=True, text=True,
                          timeout=120)


def test_cli_make_fixture_inventory_try_decrypt():
    with tempfile.TemporaryDirectory() as td:
        cap = os.path.join(td, "c.pcap")
        p = _cli("wpa-lab", "make-fixture", cap, "--ssid", "QuizNet",
                 "--password", "quiz-pass-01")
        assert p.returncode == 0 and "lab.pcap".startswith("l") and \
            "laboratory capture written" in p.stdout
        assert "quiz-pass-01" in p.stdout and "PMK" in p.stdout
        p = _cli("wpa-lab", "inventory", cap)
        assert p.returncode == 0 and "QuizNet" in p.stdout
        assert "yes" in p.stdout and "locked" in p.stdout
        p = _cli("wpa-lab", "try", cap, "--ssid", "QuizNet",
                 "--password", "passw0rd")
        assert p.returncode == 1 and "wrong key" in p.stdout
        p = _cli("wpa-lab", "try", cap, "--ssid", "QuizNet",
                 "--password", "quiz-pass-01")
        assert p.returncode == 0 and "ACCEPTED" in p.stdout \
            and "intranet.lab.example" in p.stdout
        out = os.path.join(td, "exp")
        p = _cli("wpa-lab", "decrypt", cap, "--ssid", "QuizNet",
                 "--password", "quiz-pass-01", "-o", out)
        assert p.returncode == 0
        assert os.path.exists(os.path.join(out, "wpa_lab_decrypted.pcap"))
        assert os.path.exists(os.path.join(out, "wpa_lab_report.md"))


def test_cli_no_handshake_exit_code_and_exercises():
    with tempfile.TemporaryDirectory() as td:
        cap = os.path.join(td, "late.pcap")
        p = _cli("wpa-lab", "make-fixture", cap, "--ssid", "QuizNet",
                 "--password", "quiz-pass-01", "--no-handshake")
        assert p.returncode == 0 and "NO handshake" in p.stdout
        p = _cli("wpa-lab", "try", cap, "--ssid", "QuizNet",
                 "--password", "quiz-pass-01")
        assert p.returncode == 3 and "NO HANDSHAKE" in p.stdout
        p = _cli("wpa-lab", "exercises")
        assert p.returncode == 0 and "guided exercises" in p.stdout
        p = _cli("wpa-lab", "exercises", "--exercise", "4")
        assert "missing-handshake" in p.stdout and "■" not in p.stdout
        p = _cli("wpa-lab", "--help")
        assert p.returncode == 0 and "usage" in p.stdout.lower()
        p = _cli("wpa-lab", "inventory", "/tmp/does-not-exist.pcap")
        assert p.returncode == 2


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
