"""Captive-portal phishing AWARENESS lab — a local training simulation.

This module turns ``wifiscanner`` into a self-contained teaching rig for the
classic "evil captive portal" lesson — entirely on your own machine (or a
closed classroom LAN you control):

* It serves a realistic-looking fake Wi-Fi sign-in page (the "attack").
* It records every portal view and every training submission against a
  roster of SYNTHETIC accounts (``traineeNN@lab.example``) in an
  owner-only (0600) SQLite database (the "detection & logging").
* It gives the instructor a live dashboard with the attack flow, the
  captured TEST values, per-account status and an event timeline.
* After the reveal it offers debrief pages: how to spot the fake portal
  (indicators), a side-by-side legitimate-vs-phishing comparison, and an
  "attacker's view" briefing on what real harvesters go after.
* A dashboard button and ``wifiscanner lab --reset --yes`` wipe all
  submissions between exercises; ``--rotate-roster`` generates fresh
  synthetic credentials for the next class.

Scope rules baked into the code:

* There is no integration with any real authentication system. The only
  accounts that can ever "succeed" are the lab-generated synthetic ones;
  any other typed value is merely logged as an off-roster training
  attempt. Nothing here performs RF work, clones an AP, intercepts DNS or
  decrypts anything — the companion RF lessons live in ``ids`` /
  ``inject --mode ids-selftest`` and are cross-referenced from the
  debrief pages.
* The instructor dashboard lives behind a random per-run URL token printed
  to the instructor's console; the portal page never links to it.
* The server binds to localhost by default. ``--bind 0.0.0.0`` is accepted
  for presenting to a classroom LAN under the instructor's control.
"""
from __future__ import annotations

import csv
import hashlib
import html
import json
import os
import secrets as _secrets
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .privacy import ensure_secure_storage, secure_file
from .util import log

__all__ = ["LabStore", "LabApp", "make_server", "synthetic_roster",
           "export_lab", "self_test", "new_token", "LAB_DOMAIN"]

LAB_DOMAIN = "lab.example"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS lab_accounts(
  account TEXT PRIMARY KEY, secret TEXT NOT NULL, created REAL, note TEXT);
CREATE TABLE IF NOT EXISTS lab_attempts(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL, account TEXT, secret TEXT, verdict TEXT,
  roster_match INT, ip TEXT, ua TEXT);
CREATE TABLE IF NOT EXISTS lab_events(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL, kind TEXT, detail TEXT, ip TEXT);
CREATE INDEX IF NOT EXISTS idx_lab_att_ts ON lab_attempts(ts);
CREATE INDEX IF NOT EXISTS idx_lab_evt_ts ON lab_events(ts);
"""

# Word pool for readable, obviously synthetic training passphrases
# ("trainee07@lab.example / mesa-river-83!" style).
_WORDS = ("amber basalt cedar comet delta ember fjord gale harbor iris "
          "juniper kelp laguna mesa north onyx prairie quartz river "
          "solstice tundra willow beryl coral drift echo flint grove "
          "hazel inlet jasper krill lumen").split()
_SYMBOLS = "!#$%"


def synthetic_roster(n: int = 10, seed: int = 0) -> list:
    """Generate ``n`` synthetic training accounts (deterministic per seed).

    Usernames live under the reserved ``lab.example`` domain (RFC 2606);
    passwords are random-shaped word-word-number-symbol strings. They look
    realistic on paper but belong to no real person, service or system.
    """
    n = max(1, min(int(n), 200))
    out = []
    for i in range(n):
        d = hashlib.sha256(f"wifi-lab-roster:{seed}:{i}".encode()).digest()
        secret = "{}-{}-{}{}".format(
            _WORDS[d[0] % len(_WORDS)], _WORDS[d[1] % len(_WORDS)],
            10 + d[2] % 90, _SYMBOLS[d[3] % len(_SYMBOLS)])
        out.append({"account": f"trainee{i + 1:02d}@{LAB_DOMAIN}",
                    "secret": secret,
                    "note": "synthetic training account — no real service"})
    return out


def new_token() -> str:
    """Per-run instructor-dashboard URL token."""
    return _secrets.token_urlsafe(9)


def _t(value, limit: int = 200) -> str:
    """Truncate untrusted input before it hits storage/screens."""
    s = "" if value is None else str(value)
    return s if len(s) <= limit else s[:limit] + "…"


def _fmt(ts: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)) if ts else "-"


class LabStore:
    """Owner-only SQLite store for the lab's roster, attempts and events.

    Mirrors the main history store's discipline: 0600 from birth, WAL
    journalling, thread-safe writes (the HTTP server is threaded), and an
    explicit reset. ``path=':memory:'`` is supported for tests/self-tests.
    """

    def __init__(self, path: str):
        self.path = path or "lab.sqlite"
        self.memory = self.path == ":memory:"
        self.lock = threading.RLock()
        if not self.memory:
            os.makedirs(os.path.dirname(os.path.abspath(self.path)) or ".",
                        exist_ok=True)
        self.db = sqlite3.connect(self.path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        with self.lock:
            if not self.memory:
                self.db.executescript("PRAGMA journal_mode=WAL; "
                                      "PRAGMA synchronous=NORMAL;")
            self.db.executescript(_SCHEMA)
            self.db.commit()
        if not self.memory:
            ensure_secure_storage(self.path, fix=True)
            for suffix in ("-wal", "-shm"):
                if os.path.exists(self.path + suffix):
                    ensure_secure_storage(self.path + suffix, fix=True)

    def close(self) -> None:
        with self.lock:
            self.db.commit()
            self.db.close()

    # -------------------------------------------------------------- roster

    @property
    def roster_seed(self) -> int:
        """Roster generation seed, stored in ``PRAGMA user_version``."""
        try:
            with self.lock:
                v = self.db.execute("PRAGMA user_version").fetchone()[0]
        except sqlite3.OperationalError:
            v = 0
        return int(v or 0)

    def _set_roster_seed(self, seed: int) -> None:
        with self.lock:
            self.db.execute(f"PRAGMA user_version={int(seed)}")
            self.db.commit()

    def ensure_roster(self, n: int = 10) -> int:
        """Create the synthetic roster on first use; returns rows created."""
        with self.lock:
            have = self.db.execute(
                "SELECT COUNT(*) c FROM lab_accounts").fetchone()["c"]
        if have:
            return 0
        rows = synthetic_roster(n, seed=self.roster_seed)
        with self.lock:
            self.db.executemany(
                "INSERT INTO lab_accounts VALUES(?,?,?,?)",
                [(r["account"], r["secret"], time.time(), r["note"])
                 for r in rows])
            self.db.commit()
        self.record_event("roster-generated",
                          f"{len(rows)} synthetic accounts created")
        return len(rows)

    def accounts(self) -> list:
        """Roster joined with per-account attempt statistics."""
        with self.lock:
            rows = self.db.execute(
                "SELECT a.account, a.secret, a.created, a.note, "
                "(SELECT COUNT(*) FROM lab_attempts t WHERE t.account=a.account) "
                "  AS attempts, "
                "(SELECT COUNT(*) FROM lab_attempts t WHERE t.account=a.account "
                "  AND t.verdict='roster-match') AS matched "
                "FROM lab_accounts a ORDER BY a.account").fetchall()
        return [dict(r) for r in rows]

    def lookup_secret(self, account: str) -> str:
        with self.lock:
            row = self.db.execute(
                "SELECT secret FROM lab_accounts WHERE account=?",
                (account,)).fetchone()
        return row["secret"] if row else ""

    def rotate_roster(self, n: int = 10) -> int:
        """Fresh synthetic credentials for the next exercise round.

        Deletes the old roster and all submissions (old matches would be
        meaningless), bumps the seed and regenerates. Returns the size of
        the new roster.
        """
        with self.lock:
            self.db.execute("DELETE FROM lab_accounts")
            self.db.execute("DELETE FROM lab_attempts")
            self.db.execute("DELETE FROM lab_events")
            self.db.commit()
        self._set_roster_seed(self.roster_seed + 1)
        return self.ensure_roster(n)

    # ----------------------------------------------------------- recording

    def record_event(self, kind: str, detail: str = "", ip: str = "") -> None:
        with self.lock:
            self.db.execute("INSERT INTO lab_events VALUES(NULL,?,?,?,?)",
                            (time.time(), _t(kind, 40), _t(detail, 400),
                             _t(ip, 45)))
            self.db.commit()

    def record_attempt(self, account: str, secret: str, ip: str = "",
                       ua: str = "") -> dict:
        """Store a training submission and classify it against the roster.

        Verdicts:
          * ``roster-match``               — valid synthetic account+secret
          * ``roster-account-wrong-secret``— real roster account, wrong secret
          * ``off-roster``                 — anything else typed in
        The typed value itself is kept (these ARE the captured test values
        the lesson is about) and the DB stays owner-only.
        """
        account, secret = _t(account, 120), _t(secret, 120)
        expected = self.lookup_secret(account)
        if expected and secret == expected:
            verdict, match = "roster-match", 1
        elif expected:
            verdict, match = "roster-account-wrong-secret", 0
        else:
            verdict, match = "off-roster", 0
        with self.lock:
            cur = self.db.execute(
                "INSERT INTO lab_attempts VALUES(NULL,?,?,?,?,?,?,?)",
                (time.time(), account, secret, verdict, match,
                 _t(ip, 45), _t(ua, 200)))
            self.db.commit()
            row_id = cur.lastrowid
        self.record_event(
            "credential-submit",
            f"attempt #{row_id}: account={account or '<blank>'!r} "
            f"verdict={verdict}")
        return {"id": row_id, "verdict": verdict, "roster_match": match,
                "account": account}

    # ------------------------------------------------------------ querying

    def attempts(self, limit: int = 1000) -> list:
        with self.lock:
            rows = [dict(r) for r in self.db.execute(
                "SELECT id, ts, account, secret, verdict, roster_match, ip, ua "
                "FROM lab_attempts ORDER BY ts DESC LIMIT ?",
                (limit,)).fetchall()]
        # Dwell time: seconds from this client's first portal view to the
        # submission — a classic "how fast did they fall for it" metric.
        first_view = {}
        with self.lock:
            for r in self.db.execute(
                    "SELECT ip, MIN(ts) t FROM lab_events "
                    "WHERE kind='portal-view' GROUP BY ip").fetchall():
                first_view[r["ip"]] = r["t"]
        for r in rows:
            r["time"] = _fmt(r["ts"])
            base = first_view.get(r["ip"])
            r["dwell_s"] = round(r["ts"] - base, 1) \
                if base and r["ts"] >= base else None
        return rows

    def events(self, limit: int = 500) -> list:
        with self.lock:
            rows = [dict(r) for r in self.db.execute(
                "SELECT id, ts, kind, detail, ip FROM lab_events "
                "ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()]
        for r in rows:
            r["time"] = _fmt(r["ts"])
        return rows

    def funnel(self) -> dict:
        """Attack-flow counters for the dashboard."""
        with self.lock:
            def _one(q, *a):
                return self.db.execute(q, a).fetchone()[0]
            views = _one("SELECT COUNT(*) FROM lab_events "
                         "WHERE kind='portal-view'")
            visitors = _one("SELECT COUNT(DISTINCT ip) FROM lab_events "
                            "WHERE kind='portal-view'")
            submissions = _one("SELECT COUNT(*) FROM lab_attempts")
            matches = _one("SELECT COUNT(*) FROM lab_attempts "
                           "WHERE verdict='roster-match'")
            wrong = _one("SELECT COUNT(*) FROM lab_attempts "
                         "WHERE verdict='roster-account-wrong-secret'")
            off = _one("SELECT COUNT(*) FROM lab_attempts "
                       "WHERE verdict='off-roster'")
            first_view = _one("SELECT MIN(ts) FROM lab_events "
                              "WHERE kind='portal-view'") or 0.0
            first_sub = _one("SELECT MIN(ts) FROM lab_attempts") or 0.0
        secs = round(first_sub - first_view, 1) \
            if first_view and first_sub and first_sub >= first_view else None
        return {"portal_views": views, "unique_visitors": visitors,
                "submissions": submissions, "roster_matches": matches,
                "wrong_secret": wrong, "off_roster": off,
                "first_view": _fmt(first_view), "first_submission": _fmt(first_sub),
                "view_to_submit_s": secs}

    # -------------------------------------------------------------- reset

    def reset(self) -> int:
        """Wipe all submissions and events (roster kept). Returns rows cut."""
        total = 0
        with self.lock:
            for table in ("lab_attempts", "lab_events"):
                cur = self.db.execute(f"DELETE FROM {table}")
                total += cur.rowcount or 0
            self.db.commit()
        log.warning("lab reset: %d training row(s) deleted", total)
        return total

    def stats_file(self) -> dict:
        return {"path": self.path, "memory": self.memory,
                "accounts": len(self.accounts()),
                "attempts": self.funnel()["submissions"],
                "events": len(self.events(100000))}


# ------------------------------------------------------------- web assets

_CSS = """
:root{--bg:#0f172a;--card:#1e293b;--ink:#e2e8f0;--mut:#94a3b8;--acc:#38bdf8;
--ok:#34d399;--warn:#fbbf24;--bad:#f87171;--line:#334155}
*{box-sizing:border-box}body{margin:0;font:15px/1.55 -apple-system,Segoe UI,
Roboto,Helvetica,Arial,sans-serif;background:var(--bg);color:var(--ink)}
a{color:var(--acc)}.wrap{max-width:980px;margin:0 auto;padding:24px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;
padding:20px;margin:14px 0}
h1{font-size:22px;margin:6px 0}h2{font-size:17px;margin:18px 0 8px}
.small{color:var(--mut);font-size:12.5px}
.chip{display:inline-block;padding:2px 10px;border-radius:999px;font-size:12px;
border:1px solid var(--line);background:#0b1220}
table{width:100%;border-collapse:collapse;font-size:13.5px;margin-top:8px}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);
vertical-align:top}
th{color:var(--mut);font-weight:600;font-size:12px;text-transform:uppercase;
letter-spacing:.04em}
.matched{color:var(--ok);font-weight:600}.miss{color:var(--warn)}
.bad{color:var(--bad)}.ok{color:var(--ok)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
gap:10px;margin:12px 0}
.stat{background:#0b1220;border:1px solid var(--line);border-radius:10px;
padding:12px}.stat b{display:block;font-size:24px}
.btn{display:inline-block;background:var(--acc);color:#082f49;border:0;
border-radius:8px;padding:10px 16px;font-weight:600;cursor:pointer;
text-decoration:none;font-size:14px}
.btn.danger{background:var(--bad);color:#450a0a}
.btn.ghost{background:transparent;color:var(--acc);border:1px solid var(--acc)}
input[type=text],input[type=password]{width:100%;padding:11px 12px;margin:6px 0
14px;border-radius:8px;border:1px solid var(--line);background:#0b1220;
color:var(--ink);font-size:15px}
label{font-size:13px;color:var(--mut)}
.simbadge{position:fixed;left:10px;bottom:10px;background:#111827;
border:1px dashed var(--warn);color:var(--warn);padding:4px 10px;
border-radius:6px;font-size:11px;opacity:.85;z-index:9}
.addrbar{background:#0b1220;border:1px solid var(--line);border-radius:8px;
padding:8px 12px;font-family:ui-monospace,monospace;font-size:13px;
margin:8px 0}
.lock{color:var(--ok)}.nolock{color:var(--bad)}
.tell{border-left:4px solid var(--warn);padding:10px 14px;background:#0b1220;
border-radius:0 8px 8px 0;margin:10px 0}
ul.tight li{margin:5px 0}
"""

_SIM_BADGE = "<div class='simbadge'>TRAINING SIMULATION — wifiscanner lab</div>"


def _page(title: str, body: str) -> bytes:
    doc = ("<!doctype html><html lang='en'><head><meta charset='utf-8'>"
           "<meta name='viewport' content='width=device-width,initial-scale=1'>"
           f"<title>{html.escape(title)}</title>"
           f"<style>{_CSS}</style></head><body>{body}</body></html>")
    return doc.encode("utf-8")


def _login_form(ssid: str, action: str, *, watermark: bool) -> str:
    badge = _SIM_BADGE if watermark else ""
    return f"""
<div class='wrap' style='max-width:430px'>
 <div class='card' style='text-align:center;margin-top:40px'>
  <div style='font-size:34px'>📶</div>
  <h1>Wi-Fi Sign In</h1>
  <div class='chip'>network: {html.escape(ssid)}</div>
  <p class='small'>Welcome! Sign in with your {html.escape(ssid)} guest
  account to get online. Premium 5G-speed access for registered guests.</p>
  <form method='POST' action='{action}' autocomplete='off'>
    <input type='text' name='account' placeholder='Username or email'
           aria-label='username'>
    <input type='password' name='password' placeholder='Password'
           aria-label='password'>
    <label style='display:block;text-align:left'>
      <input type='checkbox' name='terms' value='yes'> I accept the
      <a href='#' onclick='return false'>acceptable-use terms</a></label>
    <button class='btn' style='width:100%;margin-top:12px'>Connect</button>
  </form>
  <p class='small'>Need help? Contact the front desk ·
    reference #CP-7042</p>
 </div>
</div>{badge}"""


def portal_page(ssid: str, host: str) -> bytes:
    body = (_login_form(ssid, "/submit", watermark=True) +
            "\n<!-- lab-marker:no-tls  (this page travelled in cleartext) -->"
            "\n<!-- lab-marker:ip-host (host is "
            f"{html.escape(host)}, not the operator's real domain) -->")
    return _page(f"{ssid} — Sign in", body)


def legit_page(ssid: str) -> bytes:
    """Stand-in for the operator's REAL portal, for the comparison page."""
    addr = ("<div class='addrbar'><span class='lock'>🔒</span> "
            f"https://portal.{LAB_DOMAIN.replace('lab', 'campusnet')}"
            "/welcome — valid certificate, official domain</div>")
    body = ("<div class='wrap'>" + addr +
            "<div class='card' style='border-color:var(--ok)'>" +
            "<h1>✅ This stand-in represents the LEGITIMATE portal</h1>"
            "<p>In a real lesson this box is your reference for what the "
            "genuine sign-in experience looks like: an HTTPS page on the "
            "operator's real domain, reached by asking staff, never by "
            "following whatever pops up after joining a strange network.</p>"
            "<ul class='tight'>"
            "<li>Address bar shows the official domain with a valid 🔒 "
            "certificate</li><li>Branding, terms and support links match the "
            "venue's printed material</li><li>It never appears uninvited "
            "seconds after you joined a network</li></ul>"
            f"{_login_form(ssid, '#', watermark=False)}"
            "</div><p><a href='/compare'>← back to the comparison</a></p>"
            "</div>")
    return _page("Legitimate portal (reference)", body)


def reveal_page(attempt: dict, ssid: str) -> bytes:
    """Shown right after a training submission: instant awareness moment.

    Deliberately echoes the account name but NEVER the typed secret back.
    """
    acct = html.escape(attempt.get("account") or "(blank)")
    body = f"""
<div class='wrap' style='max-width:640px'>
 <div class='card' style='border-color:var(--bad)'>
  <h1>⚠️ This was a training simulation</h1>
  <p>The page you just used was a <b>fake captive portal</b> run by your
  instructor. Had this been a real phishing attack, the credentials you
  typed for <b>{acct}</b> would now be in an attacker's database — together
  with your IP address, browser fingerprint and exact timestamp.</p>
  <p class='ok'>Your training submission was recorded as attempt
  #{attempt.get('id')} ({html.escape(attempt.get('verdict', '?'))}).
  No real system was contacted; nothing you typed can leave this machine.</p>
  <h2>Do the two-minute debrief</h2>
  <ul class='tight'>
   <li><a href='/indicators'>🚩 How to spot this fake portal</a></li>
   <li><a href='/compare'>🔍 Legitimate vs phishing portal, side by side</a></li>
   <li><a href='/learn'>🎯 What a real attacker would do next</a></li>
   <li><a href='/'>↺ Try the portal again (see if you catch the tells)</a></li>
  </ul>
 </div>
 <p class='small'>wifiscanner lab · synthetic credentials only ·
 instructor can wipe this session's data at any time.</p>
</div>{_SIM_BADGE}"""
    return _page("Training debrief", body)


def indicators_page(ssid: str, host: str) -> bytes:
    tells = [
        ("No HTTPS padlock",
         "This page arrived over plain HTTP — everything you type crosses "
         "the network in cleartext. A genuine portal of any size runs HTTPS. "
         "View source and find <code>lab-marker:no-tls</code>."),
        ("Wrong address",
         f"The address bar shows <code>http://{html.escape(host)}</code> — a "
         "bare host/IP, not the operator's registered domain. Attackers "
         "can't use the real domain; look for misspellings and odd TLDs. "
         "Marker: <code>lab-marker:ip-host</code>."),
        ("Uninvited appearance",
         "It appeared the instant you joined the network. Real portals greet "
         "you when you open a browser and try to browse — a login box that "
         "ambushes you at association time is suspicious."),
        ("Generic, interchangeable branding",
         "No verifiable company imprint, broken 'terms' link, stock icons. "
         "Attack kits use templates that must work for every venue."),
        ("Over-asking",
         "It wants an account + password for 'free' Wi-Fi. Ask: does the "
         "venue need this? Hotel portals usually want a room number + name, "
         "and many honest networks just need one button."),
        ("Pressure & polish mismatch",
         "'Premium 5G-speed' promises, urgency, but a support reference "
         "that goes nowhere (#CP-7042 doesn't map to anything real)."),
        ("No way to verify",
         "Nothing on the page lets you confirm it out-of-band. The fix is "
         "always the same: ask staff, use the venue's official app, or "
         "type the known URL yourself."),
    ]
    lis = "".join(f"<div class='tell'><b>{html.escape(t)}</b><br/>{d}</div>"
                  for t, d in tells)
    body = f"""
<div class='wrap'>
 <h1>🚩 Seven tells that expose this portal</h1>
 <p class='small'>Network shown: <b>{html.escape(ssid)}</b> · trainer host:
 <code>{html.escape(host)}</code>. Two markers are hidden in the page
 source as an exercise — open <code>view-source:</code> on the portal and
 find them.</p>
 <div class='card'>{lis}</div>
 <div class='card'>
  <h2>How the trap arrives over the air</h2>
  <p>A real credential-harvesting portal is usually the last hop of an RF
  attack: a <b>deauthentication burst</b> knocks you off the genuine AP, an
  <b>evil twin</b> beacons the same name at stronger power, and its
  <b>captive DNS</b> answers every lookup with the fake portal. Every one of
  those hops is visible to the passive side of this tool:</p>
  <ul class='tight'>
   <li><code>wifiscanner ids</code> — deauth-flood, forced-reauth and
       handshake-harvest signatures</li>
   <li><code>wifiscanner ids --db known.sqlite --learn</code> — warden
       baseline, then unknown-BSSID alerts</li>
   <li><code>wifiscanner scan -o out</code> — same-SSID / open-clone rows in
       <code>*_rogue_alerts.csv</code></li>
   <li><code>wifiscanner inject --mode ids-selftest</code> — prove your
       detector actually fires, offline</li>
  </ul>
 </div>
 <p><a class='btn ghost' href='/compare'>Continue: comparison →</a></p>
</div>{_SIM_BADGE}"""
    return _page("How to spot the fake portal", body)


def compare_page(ssid: str, host: str) -> bytes:
    rows = [
        ("Address bar",
         f"https://portal.campusnet.example — 🔒 official domain",
         f"http://{html.escape(host)} — bare host/IP, no padlock"),
        ("Transport", "TLS, valid certificate chain", "Plain HTTP — typed "
         "credentials would cross the air in cleartext"),
        ("How you arrive", "You ask staff / official app and type the URL",
         "It pops up uninvited right after joining the network"),
        ("Branding", "Matches the venue's printed material; working terms and "
         "imprint", "Template look, dead 'terms' link, invented reference "
         "numbers"),
        ("Data requested", "Only what the venue needs (e.g. room + surname)",
         "Full account + password, 'to verify your identity'"),
        ("Verification path", "Staff / official app can confirm it",
         "None — the page cannot be validated out-of-band"),
    ]
    body_rows = "".join(
        f"<tr><th>{html.escape(a)}</th><td class='ok'>{b}</td>"
        f"<td class='bad'>{c}</td></tr>" for a, b, c in rows)
    body = f"""
<div class='wrap'>
 <h1>🔍 Legitimate vs phishing portal</h1>
 <p class='small'>Open both and compare: <a href='/legit'>legitimate
 reference</a> vs <a href='/'>simulated phishing portal</a>
 (network: <b>{html.escape(ssid)}</b>).</p>
 <div class='grid'>
  <div class='card'><h2>✅ Genuine (reference)</h2>
   <div class='addrbar'><span class='lock'>🔒</span>
    https://portal.campusnet.example/welcome</div>
   <p class='small'>Reached because YOU navigated there; verifiable by
   staff; HTTPS on the real domain.</p></div>
  <div class='card'><h2>🎣 This lab's fake</h2>
   <div class='addrbar'><span class='nolock'>⚠️</span>
    http://{html.escape(host)}/</div>
   <p class='small'>Ambushes you after association; unverifiable; plain HTTP
   on a bare host; over-asks for credentials.</p></div>
 </div>
 <div class='card'>
  <table><tr><th>Signal</th><th>Legitimate portal</th>
   <th>Phishing portal</th></tr>{body_rows}</table>
 </div>
 <p><a class='btn ghost' href='/learn'>Continue: attacker's view →</a></p>
</div>{_SIM_BADGE}"""
    return _page("Legitimate vs phishing", body)


def learn_page(ssid: str) -> bytes:
    loot = [
        ("The typed password, verbatim",
         "the portal sees the secret in cleartext before any hashing would "
         "ever matter — that is the whole point of the fake page"),
        ("Account / email enumeration",
         "whether each typed username 'exists' (wrong-password vs unknown "
         "account tells differ)"),
        ("Client IP address", "where the victim is, right now"),
        ("Browser / OS fingerprint", "the User-Agent header, for tailoring "
         "follow-up attacks"),
        ("Timestamps & behaviour",
         "when people join, how fast they comply, who reuses credentials"),
    ]
    chain = ("📶 deauth kick → 🎭 evil-twin beacon → 🧭 captive DNS → "
             "🎣 fake portal → 🗝️ captured credentials → 🔁 instant reuse "
             "on the victim's email / VPN / cloud accounts")
    body = f"""
<div class='wrap'>
 <h1>🎯 The attacker's view</h1>
 <div class='card'><h2>The kill chain this lab skips the RF part of</h2>
  <p style='font-size:16px'>{chain}</p>
  <p class='small'>Steps 1–3 are over-the-air techniques demonstrated
  separately (and detectably) by this project's IDS side:
  <code>ids</code>, <code>scan</code> rogue rows and
  <code>inject --mode ids-selftest</code>. This lab covers step 4–5 in a
  closed, synthetic form.</p></div>
 <div class='card'><h2>What one submission hands the attacker</h2>
  <table><tr><th>Harvested</th><th>Why it matters</th></tr>
  {"".join(f"<tr><th>{html.escape(a)}</th><td>{html.escape(b)}</td></tr>"
           for a, b in loot)}</table>
  <p>The single biggest payoff is usually <b>password reuse</b>: one captive
  portal password tried against the account's email, corporate VPN and cloud
  logins. That is why a single careless connect can become a breach.</p></div>
 <div class='card'><h2>The defender's checklist</h2>
  <ul class='tight'>
   <li>Type known portal URLs yourself; never trust a pop-up login that
       appears at association time</li>
   <li>Refuse credential boxes on plain HTTP; no padlock, no password</li>
   <li>Disable auto-join for open networks; forget networks you no longer
       use</li>
   <li>Prefer WPA3/PMF networks — PMF blocks the deauth kick that starts the
       chain (<code>wifiscanner audit</code> shows the setting)</li>
   <li>Run <code>wifiscanner ids --learn</code> on your home/office airspace
       so a hostile twin is a baseline alert, not a surprise</li>
   <li>Use unique passwords (manager) so one captured value dies with the
       site it belongs to</li>
  </ul></div>
 <p class='small'>Lab network name: <b>{html.escape(ssid)}</b>. This briefing
 teaches <i>concepts only</i>; no usable attack tooling is described.</p>
 <p><a class='btn ghost' href='/'>Back to the portal</a></p>
</div>{_SIM_BADGE}"""
    return _page("Attacker's view — debrief", body)


_DASH_JS = """
const TOKEN = "__TOKEN__";
function td(t, parent, cls){ const e=document.createElement('td');
  e.textContent = (t === null || t === undefined) ? '-' : String(t);
  if(cls) e.className = cls; parent.appendChild(e); return e; }
function render(d){
  const f = d.funnel;
  document.getElementById('s_views').textContent = f.portal_views;
  document.getElementById('s_vis').textContent = f.unique_visitors;
  document.getElementById('s_subs').textContent = f.submissions;
  document.getElementById('s_match').textContent = f.roster_matches;
  document.getElementById('s_fast').textContent =
    (f.view_to_submit_s === null) ? '–' : f.view_to_submit_s + 's';
  const at = document.getElementById('attempts');
  at.innerHTML = '';
  d.attempts.forEach(a => {
    const tr = document.createElement('tr');
    td('#'+a.id, tr); td(a.time, tr); td(a.account || '(blank)', tr);
    td(a.secret || '(blank)', tr);
    td(a.verdict, tr, a.roster_match ? 'matched' : 'miss');
    td(a.dwell_s === null ? '–' : a.dwell_s + 's', tr);
    td(a.ip, tr); td(a.ua, tr);
    at.appendChild(tr);
  });
  const ac = document.getElementById('roster');
  ac.innerHTML = '';
  d.accounts.forEach(r => {
    const tr = document.createElement('tr');
    td(r.account, tr); td(r.secret, tr);
    td(r.matched > 0 ? 'CAPTURED' : '—',
       tr, r.matched > 0 ? 'matched' : '');
    td(r.attempts, tr);
    ac.appendChild(tr);
  });
  const ev = document.getElementById('events');
  ev.innerHTML = '';
  d.events.forEach(e => {
    const tr = document.createElement('tr');
    td('#'+e.id, tr); td(e.time, tr); td(e.kind, tr);
    td(e.detail, tr); td(e.ip, tr);
    ev.appendChild(tr);
  });
  document.getElementById('stamp').textContent =
    'updated ' + new Date().toLocaleTimeString();
}
async function tick(){ try { const r = await fetch('/api/state?token='+TOKEN);
  if (r.ok) render(await r.json()); } catch(e) {} }
async function doReset(){
  if (!confirm('Wipe ALL captured submissions and events? ' +
               'The synthetic roster is kept.')) return;
  await fetch('/api/reset?token='+TOKEN, {method:'POST'});
  await tick();
}
document.getElementById('resetBtn').addEventListener('click', doReset);
tick(); setInterval(tick, 3000);
"""


def dashboard_page(ssid: str, host: str, token: str,
                   started: float) -> bytes:
    js = _DASH_JS.replace("__TOKEN__", token)
    body = f"""
<div class='wrap'>
 <h1>🎓 Instructor dashboard — captive-portal lab</h1>
 <p class='small'>network under test: <b>{html.escape(ssid)}</b> · portal:
 <code>http://{html.escape(host)}/</code> · session started
 {html.escape(_fmt(started))} · <span id='stamp'>loading…</span></p>
 <div class='grid'>
  <div class='stat'>portal views<b id='s_views'>0</b></div>
  <div class='stat'>unique clients<b id='s_vis'>0</b></div>
  <div class='stat'>credential submissions<b id='s_subs'>0</b></div>
  <div class='stat'>roster accounts captured<b id='s_match'>0</b></div>
  <div class='stat'>fastest view→submit<b id='s_fast'>–</b></div>
 </div>
 <div class='card'>
  <h2>Attack flow — captured TEST values</h2>
  <p class='small'>Every row is a student submission on the fake portal.
  Values are the synthetic training credentials (or whatever else was typed) —
  this is exactly what a real attacker's log contains.</p>
  <table><tr><th>#</th><th>Time</th><th>Account (as typed)</th>
   <th>Secret (as typed)</th><th>Verdict</th><th>View→submit</th>
   <th>Client IP</th><th>User-Agent</th></tr>
   <tbody id='attempts'></tbody></table>
 </div>
 <div class='card'>
  <h2>Synthetic roster status</h2>
  <table><tr><th>Training account</th><th>Training secret</th>
   <th>Status</th><th>Attempts</th></tr><tbody id='roster'></tbody></table>
 </div>
 <div class='card'>
  <h2>Event log (detection trail)</h2>
  <table><tr><th>#</th><th>Time</th><th>Kind</th><th>Detail</th>
   <th>Client IP</th></tr><tbody id='events'></tbody></table>
 </div>
 <div class='card'>
  <h2>Exercise controls</h2>
  <button class='btn danger' id='resetBtn'>🧹 Reset — wipe submissions &
  events</button>
  <a class='btn ghost' href='/indicators'>student debrief pages</a>
  <p class='small'>CLI equivalent: <code>wifiscanner lab --reset
  --yes</code> (roster kept) · <code>wifiscanner lab --reset --yes
  --rotate-roster</code> (fresh synthetic credentials for the next class).
  The roster and log live in an owner-only (0600) SQLite file.</p>
 </div>
</div>
<script>{js}</script>"""
    return _page("Instructor dashboard", body)


# --------------------------------------------------------------- HTTP glue

class LabApp:
    """Shared state handed to every request handler."""

    def __init__(self, store: LabStore, ssid: str, token: str):
        self.store = store
        self.ssid = ssid or "CampusNet-Guest"
        self.token = token
        self.started = time.time()


class _Handler(BaseHTTPRequestHandler):
    server_version = "wifiscanner-lab"
    protocol_version = "HTTP/1.1"
    _MAX_POST = 16384

    # -- plumbing -------------------------------------------------------
    def log_message(self, fmt, *args):       # quiet, but keep a debug trail
        log.debug("lab http: " + fmt, *[str(a)[:80] for a in args])

    def _send(self, body: bytes, status: int = 200,
              ctype: str = "text/html; charset=utf-8") -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, obj, status: int = 200) -> None:
        self._send(json.dumps(obj, indent=1).encode(), status,
                   "application/json; charset=utf-8")

    def _redirect(self, location: str) -> None:
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    @property
    def app(self) -> LabApp:
        return self.server.app

    def _client(self) -> str:
        fwd = self.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        return _t(fwd or self.client_address[0], 45)

    def _ua(self) -> str:
        return _t(self.headers.get("User-Agent", ""), 200)

    def _host(self) -> str:
        return _t(self.headers.get("Host", "127.0.0.1"), 80)

    def _instructor_ok(self, u) -> bool:
        token = parse_qs(u.query).get("token", [""])[0]
        return bool(token) and _secrets.compare_digest(token, self.app.token)

    # -- routes ---------------------------------------------------------
    def do_GET(self):
        u = urlparse(self.path)
        path = u.path.rstrip("/") or "/"
        app = self.app
        if path == "/health":
            return self._json({"ok": True, "lab": True})
        if path in ("/", "/index.html"):
            ip = self._client()
            app.store.record_event("portal-view", f"ssid={app.ssid!r}", ip)
            log.info("lab: portal viewed by %s", ip)
            return self._send(portal_page(app.ssid, self._host()))
        if path == "/legit":
            return self._send(legit_page(app.ssid))
        if path == "/indicators":
            return self._send(indicators_page(app.ssid, self._host()))
        if path == "/compare":
            return self._send(compare_page(app.ssid, self._host()))
        if path == "/learn":
            return self._send(learn_page(app.ssid))
        if path == "/favicon.ico":
            return self._send(b"", 204, "image/x-icon")
        if path == "/api/state":
            if not self._instructor_ok(u):
                return self._json({"error": "not found"}, 404)
            return self._json(self._state())
        if path == "/i/" + app.token:
            return self._send(dashboard_page(app.ssid, self._host(),
                                             app.token, app.started))
        if path.startswith("/i/"):
            # any other instructor path: stay invisible, pretend no dashboard
            return self._json({"error": "not found"}, 404)
        # everything else behaves like a captive DNS / walled garden:
        # bounce unknown URLs back to the portal, exactly as the real
        # attack does.
        return self._redirect("/")

    def do_HEAD(self):
        return self.do_GET() if False else self._send(b"", 200)

    def do_POST(self):
        u = urlparse(self.path)
        path = u.path.rstrip("/") or "/"
        app = self.app
        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
        except ValueError:
            length = 0
        if length > self._MAX_POST:
            return self._json({"error": "payload too large"}, 413)
        raw = self.rfile.read(length) if length else b""
        form = {k: v[0] for k, v in
                parse_qs(raw.decode("utf-8", "ignore"),
                         keep_blank_values=True, max_num_fields=50).items()}

        if path == "/submit":
            ip, ua = self._client(), self._ua()
            account = form.get("account", "")
            secret = form.get("password", "")
            if not account and not secret:
                return self._redirect("/")
            attempt = app.store.record_attempt(account, secret, ip, ua)
            log.info("lab capture #%s: account=%r verdict=%s from %s",
                     attempt["id"], attempt["account"], attempt["verdict"],
                     ip)
            return self._send(reveal_page(attempt, app.ssid))

        if path == "/api/reset":
            token = (parse_qs(u.query).get("token", [""])[0]
                     or form.get("token", ""))
            if not token or not _secrets.compare_digest(token, app.token):
                return self._json({"error": "not found"}, 404)
            removed = app.store.reset()
            log.warning("lab reset via dashboard (%d rows removed)", removed)
            return self._json({"ok": True, "removed": removed})

        return self._json({"error": "not found"}, 404)

    # -- state ----------------------------------------------------------
    def _state(self) -> dict:
        app = self.app
        return {"ssid": app.ssid, "started": _fmt(app.started),
                "funnel": app.store.funnel(),
                "attempts": app.store.attempts(500),
                "events": app.store.events(300),
                "accounts": app.store.accounts()}


class LabServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, app: LabApp):
        self.app = app
        super().__init__(address, _Handler)


def make_server(bind: str, port: int, app: LabApp) -> LabServer:
    return LabServer((bind, int(port)), app)


# ---------------------------------------------------------------- export

def export_lab(store: LabStore, outdir: str, prefix: str = "lab") -> list:
    """Write the exercise record to CSV + JSON (owner-only files)."""
    os.makedirs(outdir, exist_ok=True)
    files = []

    def _csv(name, fieldnames, rows):
        path = os.path.join(outdir, f"{prefix}_{name}.csv")
        with open(path, "w", newline="", encoding="utf-8-sig") as fh:
            w = csv.DictWriter(fh, fieldnames=fieldnames,
                               extrasaction="ignore")
            w.writeheader()
            w.writerows(rows)
        secure_file(path)
        files.append(path)
        return path

    _csv("accounts",
         ["account", "secret", "created", "attempts", "matched", "note"],
         [dict(r, created=_fmt(r["created"])) for r in store.accounts()])
    _csv("attempts",
         ["id", "ts", "time", "account", "secret", "verdict",
          "roster_match", "dwell_s", "ip", "ua"],
         store.attempts(100000))
    _csv("events", ["id", "ts", "time", "kind", "detail", "ip"],
         store.events(100000))
    path = os.path.join(outdir, f"{prefix}.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"generated": _fmt(time.time()),
                   "funnel": store.funnel(),
                   "accounts": store.accounts(),
                   "attempts": store.attempts(100000),
                   "events": store.events(100000)}, fh, indent=1)
    secure_file(path)
    files.append(path)
    return files


# ------------------------------------------------------------- self-test

def self_test(db_path: str = ":memory:", accounts: int = 6) -> bool:
    """Prove the whole lab end-to-end without leaving anything running.

    Spins the real HTTP server on an ephemeral loopback port, walks the
    student path (view portal → submit synthetic credential → reveal),
    checks the instructor API, the stealth of the dashboard, and the reset.
    Prints PASS/FAIL rows; returns True when every check passed.
    """
    import urllib.request
    import urllib.error

    checks = []

    def check(name, ok, detail=""):
        checks.append((name, bool(ok), detail))
        print(f"  {'PASS' if ok else 'FAIL'}  {name}"
              + (f" — {detail}" if detail else ""))

    store = LabStore(db_path)
    created = store.ensure_roster(accounts)
    check("roster generated", created == accounts, f"{created} accounts")
    token = new_token()
    app = LabApp(store, ssid="SelfTest-Net", token=token)
    httpd = make_server("127.0.0.1", 0, app)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever,
                              kwargs={"poll_interval": 0.1}, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{port}"
    opener = urllib.request.build_opener(
        urllib.request.HTTPRedirectHandler())

    def _get(path, allow_error=False):
        try:
            with urllib.request.urlopen(base + path, timeout=5) as r:
                return r.status, r.read().decode("utf-8", "ignore")
        except urllib.error.HTTPError as exc:
            if allow_error:
                return exc.code, exc.read().decode("utf-8", "ignore")
            raise

    try:
        st, body = _get("/")
        check("portal serves a login form", st == 200 and
              "name='password'" in body and "SelfTest-Net" in body)
        check("unknown URL is captive-redirected",
              _get("/some/evil/lookup")[1].find("name='password'") >= 0)
        acct = store.accounts()[0]
        data = (f"account={acct['account']}&password={acct['secret']}"
                ).encode()
        req = urllib.request.Request(base + "/submit", data=data,
                                     method="POST")
        with urllib.request.urlopen(req, timeout=5) as r:
            reveal = r.read().decode("utf-8", "ignore")
        check("training submission returns the debrief page",
              "training simulation" in reveal.lower())
        check("submitted secret is never echoed back",
              acct["secret"] not in reveal)
        req = urllib.request.Request(
            base + "/submit", data=b"account=nobody&password=whatever",
            method="POST")
        urllib.request.urlopen(req, timeout=5).read()
        st, state = _get(f"/api/state?token={token}")
        state = json.loads(state)
        fun = state["funnel"]
        check("funnel: views + submissions counted",
              fun["portal_views"] >= 1 and fun["submissions"] == 2,
              str(fun))
        verdicts = {a["verdict"] for a in state["attempts"]}
        check("verdicts distinguish roster-match from off-roster",
              verdicts == {"roster-match", "off-roster"}, str(verdicts))
        check("events log records the capture for detection",
              any(e["kind"] == "credential-submit" for e in state["events"]))
        st, _ = _get("/i/definitely-wrong-token", allow_error=True)
        check("dashboard is invisible without the instructor token",
              st == 302 or st == 404, f"HTTP {st}")
        st, _ = _get("/api/state?token=definitely-wrong", allow_error=True)
        check("API rejects a bad token", st == 404)
        st, body = _get(f"/api/state?token={token}")
        req = urllib.request.Request(
            base + f"/api/reset?token={token}", data=b"", method="POST")
        with urllib.request.urlopen(req, timeout=5) as r:
            reset = json.loads(r.read().decode())
        check("reset endpoint clears submissions and events",
              reset.get("ok") and store.funnel()["submissions"] == 0)
        check("roster survives a reset",
              len(store.accounts()) == accounts)
    finally:
        httpd.shutdown()
        httpd.server_close()
        store.close()
    ok = all(c[1] for c in checks)
    print(f"\nlab self-test: {sum(c[1] for c in checks)}/{len(checks)} "
          f"checks passed")
    return ok
