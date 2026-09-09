"""Tests for the captive-portal phishing awareness lab (`wifiscanner lab`).

Run:  python -m pytest tests/test_lab.py -v   (or: python tests/test_lab.py)
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

from wifiscanner.lab import (LAB_DOMAIN, LabApp, LabStore, export_lab,
                             make_server, new_token, self_test,
                             synthetic_roster)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ------------------------------------------------------------------- roster

def test_roster_is_synthetic_deterministic_and_bounded():
    r1, r2 = synthetic_roster(8, seed=0), synthetic_roster(8, seed=0)
    assert r1 == r2                                    # reproducible per seed
    assert len(r1) == 8
    accounts = {r["account"] for r in r1}
    assert len(accounts) == 8                          # unique
    assert all(a.endswith("@" + LAB_DOMAIN) for a in accounts)
    assert all(a.startswith("trainee") for a in accounts)
    assert all(r["secret"] and "-" in r["secret"] for r in r1)
    # a different seed produces different synthetic credentials
    assert synthetic_roster(8, seed=1)[0]["secret"] != r1[0]["secret"]
    # sane clamping
    assert len(synthetic_roster(0)) == 1 and len(synthetic_roster(500)) == 200
    # nothing points at a real service
    assert all("no real service" in r["note"] for r in r1)


# -------------------------------------------------------------------- store

def test_labstore_verdicts_funnel_and_reset():
    with tempfile.TemporaryDirectory() as td:
        db = os.path.join(td, "lab.sqlite")
        st = LabStore(db)
        assert st.ensure_roster(5) == 5
        assert st.ensure_roster(5) == 0                # idempotent
        assert stat.S_IMODE(os.stat(db).st_mode) == 0o600
        good = st.accounts()[0]
        st.record_event("portal-view", "ssid='X'", "10.0.0.5")
        st.record_event("portal-view", "ssid='X'", "10.0.0.5")
        a = st.record_attempt(good["account"], good["secret"],
                              ip="10.0.0.5", ua="test-agent")
        b = st.record_attempt(good["account"], "wrong-secret", ip="10.0.0.6")
        c = st.record_attempt("hacker@elsewhere", "whatever", ip="10.0.0.7")
        assert (a["verdict"], b["verdict"], c["verdict"]) == (
            "roster-match", "roster-account-wrong-secret", "off-roster")
        f = st.funnel()
        assert f["portal_views"] == 2 and f["unique_visitors"] == 1
        assert f["submissions"] == 3 and f["roster_matches"] == 1
        assert f["wrong_secret"] == 1 and f["off_roster"] == 1
        att = st.attempts()
        assert att[-1]["account"] == good["account"]   # oldest last (DESC)
        assert att[-1]["dwell_s"] is not None and att[-1]["dwell_s"] >= 0
        types = {e["kind"] for e in st.events()}
        assert {"roster-generated", "portal-view", "credential-submit"} <= types
        removed = st.reset()
        assert removed >= 5
        assert st.funnel()["submissions"] == 0 and st.events() == []
        assert len(st.accounts()) == 5                 # roster kept
        st.close()


def test_rotate_roster_fresh_credentials_and_wipe():
    st = LabStore(":memory:")
    st.ensure_roster(4)
    before = [(r["account"], r["secret"]) for r in st.accounts()]
    st.record_attempt(before[0][0], before[0][1])
    n = st.rotate_roster(4)
    assert n == 4
    after = [(r["account"], r["secret"]) for r in st.accounts()]
    assert [a for a, _ in before] == [a for a, _ in after]   # same names
    assert [s for _, s in before] != [s for _, s in after]   # new secrets
    assert st.funnel()["submissions"] == 0                   # wiped
    st.close()


# --------------------------------------------------- http end to end

def _serve(store, ssid="TestNet"):
    token = new_token()
    app = LabApp(store, ssid=ssid, token=token)
    httpd = make_server("127.0.0.1", 0, app)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever,
                     kwargs={"poll_interval": 0.05}, daemon=True).start()
    return httpd, f"http://127.0.0.1:{port}", token


def test_http_flow_student_path_and_instructor_api():
    st = LabStore(":memory:")
    st.ensure_roster(6)
    httpd, base, token = _serve(st, "Hotel-TestNet")
    try:
        def _get(path):
            try:
                with urllib.request.urlopen(base + path, timeout=5) as r:
                    return r.status, r.read().decode("utf-8", "ignore")
            except urllib.error.HTTPError as exc:
                return exc.code, exc.read().decode("utf-8", "ignore")

        code, portal = _get("/")
        assert code == 200 and "name='password'" in portal
        assert "Hotel-TestNet" in portal and "TRAINING SIMULATION" in portal
        # captive behaviour: unknown URL lands back on the portal
        code, body = _get("/totally/real/page.html")
        assert "name='password'" in body
        # student submits a roster credential
        acct = st.accounts()[1]
        data = f"account={acct['account']}&password={acct['secret']}".encode()
        req = urllib.request.Request(base + "/submit", data=data, method="POST")
        with urllib.request.urlopen(req, timeout=5) as r:
            reveal = r.read().decode("utf-8", "ignore")
        assert "training simulation" in reveal.lower()
        assert acct["account"] in reveal          # account acknowledged...
        assert acct["secret"] not in reveal       # ...secret never echoed
        # instructor API
        code, raw = _get("/api/state?token=" + token)
        assert code == 200
        state = json.loads(raw)
        assert state["funnel"]["submissions"] == 1
        assert state["funnel"]["roster_matches"] == 1
        assert state["attempts"][0]["secret"] == acct["secret"]  # captured
        assert state["attempts"][0]["ua"]
        # dashboard page renders with the token, invisible without it
        code, dash = _get("/i/" + token)
        assert code == 200 and "Instructor dashboard" in dash
        assert token in dash                       # JS polls with it
        assert _get("/i/wrong")[0] == 404
        assert _get("/api/state?token=wrong")[0] == 404
        # debrief pages exist for students
        for p in ("/indicators", "/compare", "/learn", "/legit"):
            assert _get(p)[0] == 200, p
        # dashboard reset
        req = urllib.request.Request(base + "/api/reset?token=" + token,
                                     data=b"", method="POST")
        with urllib.request.urlopen(req, timeout=5) as r:
            out = json.loads(r.read().decode())
        assert out["ok"] and st.funnel()["submissions"] == 0
    finally:
        httpd.shutdown()
        httpd.server_close()
        st.close()


def test_post_size_cap_and_empty_submit():
    st = LabStore(":memory:")
    st.ensure_roster(4)
    httpd, base, token = _serve(st)
    try:
        req = urllib.request.Request(base + "/submit", data=b"x" * 20000,
                                     method="POST")
        try:
            urllib.request.urlopen(req, timeout=5)
            assert False, "oversized POST must be refused"
        except urllib.error.HTTPError as exc:
            assert exc.code == 413
        # empty form is bounced back to the portal, not recorded
        req = urllib.request.Request(base + "/submit", data=b"", method="POST")
        with urllib.request.urlopen(req, timeout=5) as r:
            body = r.read().decode("utf-8", "ignore")
        assert "name='password'" in body
        assert st.funnel()["submissions"] == 0
    finally:
        httpd.shutdown()
        httpd.server_close()
        st.close()


# ------------------------------------------------------------------- export

def test_export_writes_owner_only_files():
    st = LabStore(":memory:")
    st.ensure_roster(3)
    st.record_attempt(st.accounts()[0]["account"], st.accounts()[0]["secret"],
                      ip="10.0.0.9", ua="pytest")
    with tempfile.TemporaryDirectory() as td:
        files = export_lab(st, td)
        names = {os.path.basename(f) for f in files}
        assert names == {"lab_accounts.csv", "lab_attempts.csv",
                         "lab_events.csv", "lab.json"}
        for f in files:
            assert stat.S_IMODE(os.stat(f).st_mode) == 0o600, f
            assert os.path.getsize(f) > 30, f
        data = json.load(open(os.path.join(td, "lab.json")))
        assert data["funnel"]["submissions"] == 1
        assert data["attempts"][0]["secret"]  # captured test value exported
        import csv as _csv
        with open(os.path.join(td, "lab_attempts.csv"),
                  encoding="utf-8-sig") as fh:
            rows = list(_csv.DictReader(fh))
        assert rows[0]["verdict"] == "roster-match"
    st.close()


# --------------------------------------------------------------- self-test

def test_self_test_passes():
    assert self_test(db_path=":memory:", accounts=4)


# ---------------------------------------------------------------------- CLI

def _cli(*argv, cwd=ROOT):
    return subprocess.run([sys.executable, "main.py", "--no-banner", "-q",
                           *argv], cwd=cwd, capture_output=True, text=True,
                          timeout=90)


def test_cli_lab_help_and_reset_guards():
    p = _cli("lab", "--help")
    assert p.returncode == 0 and "usage" in p.stdout.lower()
    assert "--rotate-roster" in p.stdout and "--instructor-token" in p.stdout
    # reset requires an existing db
    p = _cli("lab", "--db", "/tmp/definitely-not-here-lab.sqlite",
             "--reset", "--yes")
    assert p.returncode == 2
    with tempfile.TemporaryDirectory() as td:
        db = os.path.join(td, "l.sqlite")
        st = LabStore(db)
        st.ensure_roster(3)
        st.record_attempt("trainee01@lab.example", "x")
        st.close()
        # --yes is mandatory
        p = _cli("lab", "--db", db, "--reset")
        assert p.returncode == 2 and "--yes" in p.stderr
        p = _cli("lab", "--db", db, "--reset", "--yes", "-o", td)
        assert p.returncode == 0 and "deleted" in p.stdout
        assert os.path.exists(os.path.join(td, "lab_attempts.csv"))
        # rotate produces a fresh roster and prints it
        p = _cli("lab", "--db", db, "--rotate-roster", "--yes",
                 "--accounts", "5")
        assert p.returncode == 0 and "New synthetic roster" in p.stdout
        st = LabStore(db)
        assert len(st.accounts()) == 5
        st.close()


def test_cli_self_test_exit_zero():
    p = _cli("lab", "--self-test")
    assert p.returncode == 0, p.stdout + p.stderr
    assert "12/12" in p.stdout


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
