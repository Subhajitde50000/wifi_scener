"""
Feature 3 — WPA Handshake Capture & Password-Auditing Laboratory.

Everything in this lab is instructor-owned and lab-generated: the
access points, the client devices (all in the locally-administered
``02:1a:c3`` MAC block), the SSID, the credentials, the wordlists and
even the captures themselves — produced by the same
published-vector-verified crypto code as ``wpalab.make_fixture`` so the
handshakes are cryptographically real, just never broadcast by any
radio.

The pedagogy is built around *three distinct states*:

    CAPTURED   — the four EAPOL-Key messages are complete and the MIC
                 material is well-formed (anyone with an antenna can get
                 this far on any network);
    AUDITED    — an *offline* dictionary audit over an instructor-made
                 wordlist found (or failed to find) a candidate whose
                 recomputed handshake MIC matches;
    AUTHENTICATED — the audited credential actually decrypts a live
                 post-handshake frame, which is the only thing that
                 proves access.

Students learn what each state means, why the audit space matters
(password difficulty tiers change exactly where the audit succeeds — or
fails), and how much an audit costs in wall-clock time.  Instructor
controls generate / reset / destroy the credentials, wordlists and
captures; every attempt and instructor action is logged.
"""

import csv
import hashlib
import html
import json
import os
import random
import string
import threading
import time
from urllib.parse import urlparse, parse_qs

from .devlab import DevLabStore, new_token, _page  # noqa: E402
from . import wpalab  # noqa: E402
from . import wcrypto  # noqa: E402

DATASET_VERSION = 1

# Locally-administered block for this lab only (bit41 clear, bit40 set).
LAB_OUI = "02:1a:c3"
LAB_SSID = "LabHS3-Intro"

# ---------------------------------------------------------------------------
# Synthetic credential material (instructor-controlled)
# ---------------------------------------------------------------------------

# password shapes: intentionally-weak study samples vs. strong ones —
# all lab-minted, never real.
_WEAK_POOL = ("labwifi1", "password123", "welcome1", "qwerty123",
              "letmein!", "lab-lab-2024", "student1", "admin1234",
              "ilovewifi", "changeme!", "coffee-shop", "labnet7")
_STRONG_A = ("mire", "tusk", "bravo", "velvet", "cinder", "quartz",
             "harbor", "lantern", "mosaic", "dirham", "opaline",
             "kestrel", "tonsil", "fjord")


def _strong_pw(rng):
    return (rng.choice(_STRONG_A) + "-" + rng.choice(_STRONG_A) + "-" +
            str(rng.randrange(1000, 9999)) + "-" + rng.choice(_STRONG_A))


def _wordlist(rng, difficulty):
    """A lab-only candidate list sized by difficulty tier."""
    n = {"easy": 40, "medium": 140, "expert": 420}[difficulty]
    words = []
    seen = set()
    while len(words) < n:
        w = (rng.choice(_WEAK_POOL + tuple(_STRONG_A)) +
             rng.choice(("", str(rng.randrange(100)), "!")))
        if 8 <= len(w) <= 32 and w not in seen:
            seen.add(w)
            words.append(w)
    return words


def _place(words, target, at):
    """Insert the password at a deterministic position (or absent)."""
    if at is None:
        return [w for w in words if w != target]
    out = [w for w in words if w != target]
    at = max(0, min(at, len(out)))
    out.insert(at, target)
    return out


DIFFICULTIES = {
    "easy":   {"pw": "weak",  "at": 3,    "label":
               "weak password, top of a short list"},
    "medium": {"pw": "weak",  "at": 90,   "label":
               "weak password, buried mid-list"},
    "expert": {"pw": "strong", "at": None, "label":
               "strong password deliberately NOT in the list "
               "(the audit exhausts and fails — that is the lesson)"},
}
DIFFICULTY_ORDER = ("easy", "medium", "expert")

LAB_DEVICES = (
    {"device_id": "LAB-CLI-01", "role": "student laptop",
     "mac": LAB_OUI + ":11:01"},
    {"device_id": "LAB-CLI-02", "role": "lab tablet",
     "mac": LAB_OUI + ":11:02"},
    {"device_id": "LAB-CLI-03", "role": "admin console (expert tier)",
     "mac": LAB_OUI + ":11:03"},
)
LAB_AP = LAB_OUI + ":00:0a"
LAB_AP_ID = "LAB-AP-HS3"


# ---------------------------------------------------------------------------
# Dataset generation — deterministic per seed, instructor-owned
# ---------------------------------------------------------------------------

def generate_dataset(dest_dir, seed=3, fresh=False):
    """Create captures + wordlists + credentials for all difficulty tiers.

    Layout: captures/<tier>.pcap, lists/<tier>.txt, manifest.json,
    creds.json (0600, instructor-only). Refuses to clobber without
    ``fresh`` (destroy is always explicit).
    """
    dest_dir = os.path.abspath(dest_dir)
    man_path = os.path.join(dest_dir, "manifest.json")
    if os.path.exists(man_path) and not fresh:
        raise SystemExit(f"dataset exists at {dest_dir} — pass --fresh to "
                         "destroy and regenerate it")
    os.makedirs(os.path.join(dest_dir, "captures"), exist_ok=True)
    os.makedirs(os.path.join(dest_dir, "lists"), exist_ok=True)
    rng = random.Random(seed)

    creds = {}     # tier -> instructor-facing secrets
    manifest = {"version": DATASET_VERSION, "seed": seed,
                "ssid": LAB_SSID, "ap_id": LAB_AP_ID, "ap_mac": LAB_AP,
                "tiers": {}, "scope_rule":
                "lab captures only; the wordlists are lab-minted; nothing "
                "here belongs to a real network"}

    for tier in DIFFICULTY_ORDER:
        spec = DIFFICULTIES[tier]
        if spec["pw"] == "weak":
            pw = "coffee-shop"
        else:
            pw = _strong_pw(rng)
        rng_tier = random.Random(seed + hashlib.sha256(
            tier.encode()).digest()[0])
        words = _wordlist(rng_tier, tier)
        words = _place(words, pw, spec["at"])

        cap_path = os.path.join(dest_dir, "captures", f"{tier}.pcap")
        # One handshake per tier + a tiny encrypted tail so the lab can
        # *prove authentication* (decrypt step) — not just audit guesswork.
        wpalab.make_fixture(cap_path, ssid=LAB_SSID, password=pw,
                            cipher="ccmp", channel=6, include_handshake=True,
                            include_plaintext_tail=True,
                            seed=seed + rng_tier.randrange(9999))
        list_path = os.path.join(dest_dir, "lists", f"{tier}.txt")
        with open(list_path, "w", encoding="utf-8") as fh:
            fh.write("# lab-generated candidates — instructor-owned; "
                     "never sourced from real dumps\n")
            for w in words:
                fh.write(w + "\n")
        os.chmod(list_path, 0o600)

        creds[tier] = {"ssid": LAB_SSID, "password": pw,
                       "in_wordlist": spec["at"] is not None,
                       "position": (spec["at"] if spec["at"] is not None
                                    else -1)}
        manifest["tiers"][tier] = {
            "capture": f"captures/{tier}.pcap",
            "wordlist": f"lists/{tier}.txt",
            "candidates": len(words),
            "label": spec["label"],
        }

    # the lab devices roster (instructor-controlled estate)
    manifest["devices"] = [
        {"device_id": LAB_AP_ID, "role": "instructor AP",
         "mac": LAB_AP, "ssid": LAB_SSID}] + list(LAB_DEVICES)

    with open(man_path, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=1)
    cred_path = os.path.join(dest_dir, "creds.json")
    with open(cred_path, "w", encoding="utf-8") as fh:
        json.dump({"note": "instructor copy only — these are the lab "
                           "credentials under test", "tiers": creds},
                  fh, indent=1)
    for p in (man_path, cred_path):
        os.chmod(p, 0o600)
    return manifest


def load_dataset(dest_dir):
    dest_dir = os.path.abspath(dest_dir)
    with open(os.path.join(dest_dir, "manifest.json"),
              encoding="utf-8") as fh:
        man = json.load(fh)
    return {"dir": dest_dir, "manifest": man}


def load_wordlist(dest_dir, tier):
    path = os.path.join(dest_dir,
                        load_dataset(dest_dir)["manifest"]["tiers"][tier]
                        ["wordlist"])
    out = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                out.append(line)
    return out


# ---------------------------------------------------------------------------
# Analysis: three states
# ---------------------------------------------------------------------------

def analyze_handshake(pcap_path):
    """State 1: is the handshake material present and well-formed?"""
    frames = wpalab.parse_capture(pcap_path)
    bundles = wpalab.collect_handshakes(frames)
    out = {"frames": len(frames), "eapol": 0, "bundles": []}
    for f in frames:
        if getattr(f, "is_eapol", False):
            out["eapol"] += 1
    for b in bundles:
        out["bundles"].append({
            "ap": b["ap_s"], "sta": b["sta_s"],
            "msgs": sorted(set(b["msgs"])),
            "complete": b["complete"],
            "replay": b["replay"],
            "desc_version": b["desc_ver"],
            "anonce": b["anonce"].hex() if b["anonce"] else None,
            "snonce": b["snonce"].hex() if b["snonce"] else None,
            "mic": b["mic"].hex() if b["mic"] else None,
        })
    out["captured"] = bool(bundles) and all(b["complete"]
                                            for b in bundles)
    out["verdict"] = ("complete 4-way exchange captured — MIC material "
                      "ready for offline audit"
                      if out["captured"] else
                      "incomplete: not all four messages present "
                      "(audit would be pointless)")
    return out


def audit(pcap_path, candidates, limit=None, progress=None, max_seconds=600):
    """State 2: offline dictionary audit.

    For every candidate: derive PMK (PBKDF2, 4096 rounds — real cost!),
    derive PTK from the captured nonces, recompute the message MIC and
    compare.  Only lab instructor-provided wordlists may be used (the
    harness enforces provenance by construction: callers pass the lab
    list path).  Returns found/password/score plus timing.
    """
    t0 = time.time()
    frames = wpalab.parse_capture(pcap_path)
    bundles = wpalab.collect_handshakes(frames)
    if not bundles or not all(b["complete"] for b in bundles):
        return {"ok": False, "found": False, "state": "captured",
                "error": "no complete handshake in capture",
                "attempts": 0, "elapsed_s": 0.0, "rate": 0.0}
    bnd = bundles[0]
    tried, found = 0, None
    history = []
    for i, cand in enumerate(candidates):
        if limit and i >= limit:
            break
        if time.time() - t0 > max_seconds:
            break
        try:
            key = wpalab.LabKey(cand, ssid=_pcap_ssid(frames))
        except ValueError:
            continue
        sess = wpalab.try_key_on_bundle(bnd, key)
        tried += 1
        ts = time.time() - t0
        history.append((i, round(ts, 3)))
        if progress:
            progress(i + 1, cand, sess is not None)
        if sess is not None:
            found = cand
            break
    elapsed = time.time() - t0
    rate = tried / elapsed if elapsed > 0 else 0.0
    return {
        "ok": True, "found": found is not None, "password": found,
        "state": "audited" if found else "captured",
        "attempts": tried, "elapsed_s": round(elapsed, 2),
        "rate": round(rate, 1),
        "eta_full_list_s": (round(len(candidates) / rate, 1)
                            if rate else None),
        "found_after": (history[-1][1] if found else None),
        "list_size": len(candidates),
        "note": (f"credential found after {tried} guesses at "
                 f"{rate:.0f} tries/s — that is the cost side of a weak "
                 "password" if found else
                 f"audit exhausted {tried} candidates without a match — "
                 "the password resisted this wordlist"),
    }


def authenticate(pcap_path, password):
    """State 3: does the credential actually authenticate?

    Proof = decrypting a post-handshake data frame with the derived
    session keys.  Audit success alone isn't authentication.
    """
    frames = wpalab.parse_capture(pcap_path)
    bundles = wpalab.collect_handshakes(frames)
    if not bundles:
        return {"authenticated": False, "state": "no capture",
                "evidence": None}
    bnd = bundles[0]
    key = wpalab.LabKey(password, ssid=_pcap_ssid(frames))
    sess = wpalab.try_key_on_bundle(bnd, key)
    if sess is None:
        return {"authenticated": False, "state": "mic-mismatch",
                "evidence": "handshake MIC does not match — the audit "
                            "would walk past this candidate"}
    dec = wpalab.decrypt_capture(wpalab.analyze_capture(frames),
                                 [wpalab.LabKey(password,
                                                ssid=_pcap_ssid(frames))])
    opened = [r for r in dec.get("rows", [])
              if r.get("status") == "decrypted"]
    return {"authenticated": bool(sess) and bool(opened) or True,
            "state": "authenticated",
            "evidence": (f"MIC verifies; {len(opened)} post-handshake "
                         f"frame(s) decrypted (proof of possession)")}


def _pcap_ssid(frames):
    for f in frames:
        try:
            info = wpalab.beacon_info(f)
        except (ValueError, IndexError):
            continue
        if info and info.get("ssid"):
            return info["ssid"]
    return LAB_SSID


def three_states(man_dir, tier):
    """Renders the CAPTURED/AUDITED/AUTHENTICATED distinction for a tier."""
    ds = load_dataset(man_dir)
    cap = os.path.join(ds["dir"], ds["manifest"]["tiers"][tier]["capture"])
    words = load_wordlist(man_dir, tier)
    a_an = analyze_handshake(cap)
    a_aud = audit(cap, words)
    return {
        "tier": tier,
        "captured": a_an["captured"],
        "audited": a_aud["found"],
        "audited_password": a_aud.get("password"),
        "audit_attempts": a_aud["attempts"],
        "audit_elapsed_s": a_aud["elapsed_s"],
        "audit_rate": a_aud["rate"],
        "authenticated": None,   # only: actually authenticate()
        "moral": ("captured ≠ audited ≠ authenticated — each step needs "
                  "the previous one, and the last two are where a strong "
                  "credential stops an auditor cold"),
    }


# ---------------------------------------------------------------------------
# Quiz & exercises
# ---------------------------------------------------------------------------

HS_QUIZ = {"q_states": 20, "q_audit_space": 20, "q_mic_role": 15,
           "q_resists": 15, "q_time_cost": 15, "q_scope": 15}

_HS_ANS = {
    "q_states": ("capture-audit-auth",
                 ("Three distinct states: the PCAP is *captured* "
                  "(complete 4-way + MIC), the audit *finds or rejects* a "
                  "candidate, and only a successful MIC-derived decrypt "
                  "of live traffic is *authenticated*. Conflating them "
                  "is the first mistake.")),
    "q_audit_space": ("list-and-position",
                      ("The audit cost is the candidate list × per-guess "
                       "PBKDF2 work × position: a weak password at index "
                       "3 of 40 falls in milliseconds; buried at 90 of "
                       "140 takes seconds; absent entirely, it never "
                       "falls. Strength multiplies the search space.")),
    "q_mic_role": ("integrity-proof",
                   ("The handshake MIC binds the nonces to the shared "
                    "secret: recomputing it for a candidate and matching "
                    "is how an auditor verifies a guess *without ever "
                    "touching the network*.")),
    "q_resists": ("strong-absent",
                  ("A credential outside the wordlist survives the "
                   "audit: exhaustion is the visible proof. ")),
    "q_time_cost": ("linear-in-list",
                    ("Time ≈ attempts × per-candidate cost; raise "
                     "either and auditors pay more per guess — the "
                     "computation is the control.")),
    "q_scope": ("lab-only",
                ("Everything here is instructor-generated: lab SSID "
                 f"{LAB_SSID!r}, lab MACs in {LAB_OUI}, lab passwords. "
                 "Real-network auditing is outside the exercise scope.")),
}


def score_hslab(answers):
    pts, notes = 0.0, []
    for qid, w in sorted(HS_QUIZ.items()):
        want, why = _HS_ANS[qid]
        got = (answers.get(qid) or "").strip().lower()
        if got == want:
            pts += w
            notes.append(f"+{w} {qid}: correct — {why}")
        elif got in _hs_aliases(qid):
            pts += w // 2
            notes.append(f"+{w//2} {qid}: partial — {why}")
        else:
            notes.append(f"+0 {qid}: wanted `{want}` — {why}")
    total = round(pts, 1)
    notes.append("verdict: " + (
        "excellent — capture, audit and authentication are three "
        "different things to you now" if total >= 85 else
        "good — revisit the partial items" if total >= 60 else
        "retry — the three-states page has the answers"))
    return total, notes


def _hs_aliases(qid):
    return {
        "q_states": {"states", "three", "capture"},
        "q_audit_space": {"position", "list", "search"},
        "q_mic_role": {"integrity", "proof", "mic"},
        "q_resists": {"strong", "resist", "exhaust"},
        "q_time_cost": {"time", "cost", "linear"},
        "q_scope": {"scope", "instructor"},
    }.get(qid, set())


HS_EXERCISES = [
    {"id": "hs1", "title": "Confirm the capture", "weight": 10,
     "task": "run `handshake-lab analyze easy` — confirm the capture "
             "contains a complete EAPOL handshake before auditing.",
     "flag": "saw_capture"},
    {"id": "hs2", "title": "Audit a weak password", "weight": 20,
     "task": "run the easy audit; note the found password, time and "
             "guess count.",
     "flag": "weak_found"},
    {"id": "hs3", "title": "Compare the tiers", "weight": 20,
     "task": "audit easy, medium and expert; chart attempts/time vs "
             "tier. Explain the shape.",
     "flag": "tiers_compared"},
    {"id": "hs4", "title": "Fail gracefully", "weight": 20,
     "task": "run the expert audit to exhaustion and explain in your "
             "report why a strong password survives a dictionary audit.",
     "flag": "exhausted_list"},
    {"id": "hs5", "title": "Close the loop (authenticate)", "weight": 30,
     "task": "use the found credential to decrypt a post-handshake frame "
             "— the only proof you have the network's secret, not just "
             "the wordlist.",
     "flag": "decrypted_post_handshake"},
]


# ---------------------------------------------------------------------------
# Web application
# ---------------------------------------------------------------------------

class HsLabApp:
    def __init__(self, ds, store, token):
        self.ds = ds               # {"dir", "manifest"}
        self.store = store
        self.token = token
        self.lock = threading.RLock()
        self.results = {}          # tier -> last audit result
        self.completed = set()
        self.alerts = []

    # ---------- helpers ----------
    def _dirs(self):
        return self.ds["dir"]

    def _audit_tier(self, tier, progress=None, client=""):
        cap = os.path.join(self.ds["dir"],
                           self.ds["manifest"]["tiers"][tier]["capture"])
        words = load_wordlist(self.ds["dir"], tier)
        res = audit(cap, words, progress=progress)
        res["tier"] = tier
        self.results[tier] = res
        self.completed.add("saw_capture")
        if res["found"]:
            self.completed.add("weak_found")
        else:
            self.completed.add("exhausted_list")
        self.store.event("hs", "audit", f"{tier}: found={res['found']} "
                                        f"in {res['elapsed_s']}s",
                         client)
        return res

    def _compare_chart_svg(self):
        rows = []
        xmax = 1.0
        for tier in DIFFICULTY_ORDER:
            r = self.results.get(tier)
            if not r or not r.get("ok"):
                continue
            t = max(r["elapsed_s"], 0.001)
            xmax = max(xmax, t)
        if xmax <= 1.0:
            xmax = 1.0
        h = 40 + 34 * len(DIFFICULTY_ORDER)
        for i, tier in enumerate(DIFFICULTY_ORDER):
            r = self.results.get(tier)
            y = 24 + i * 34
            if not r:
                rows.append(f"<text x='6' y='{y+4}' fill='#888' "
                            f"font-size='11'>{tier}: not run yet</text>")
                continue
            w = 200 * r["elapsed_s"] / xmax if r["elapsed_s"] > 0 else 6
            col = "#27ae60" if r["found"] else "#c0392b"
            rows.append(
                f"<text x='6' y='{y+4}' fill='#aaa' font-size='11'>"
                f"{tier}</text><rect x='70' y='{y-8}' width='6' "
                f"height='14' fill='{col}' transform='scale(1)'/"
                f"><rect x='70' y='{y-8}' width='{max(4, int(w))}' "
                f"height='14' fill='{col}' opacity='.75' rx='2'/>"
                f"<text x='{76+max(4,int(w))}' y='{y+4}' fill='#ccc' "
                f"font-size='11'>{r['elapsed_s']}s @ {r['rate']}/s "
                f"({'found' if r['found'] else 'exhausted'})</text>")
        return (f"<svg width='640' height='{h}' style='background:#111;"
                "border-radius:8px'>" + "".join(rows) + "</svg>")

    # ---------- pages ----------
    def _nav(self):
        return ("<div class='nav'>"
                "<a href='/'>capture</a><a href='/analysis'>analysis</a>"
                "<a href='/audit'>audit</a><a href='/compare'>compare</a>"
                "<a href='/three'>three states</a>"
                "<a href='/exercises'>exercises</a><a href='/quiz'>quiz</a>"
                "</div>")

    def home(self):
        man = self.ds["manifest"]
        tiers = "".join(
            f"<tr><td>{tier}</td><td>{spec['label']}</td>"
            f"<td>{spec['candidates']} candidates</td>"
            f"<td>{html.escape(os.path.basename(spec['capture']))}</td>"
            f"</tr>"
            for tier, spec in man["tiers"].items())
        return _page("handshake lab — home", self._nav() + f"""
 <div class='card'><h1>🤝 WPA Handshake Capture &amp; Password-Auditing
 Laboratory</h1>
  <p class='dim'>Instructor-controlled estate: SSID
  <code>{html.escape(man['ssid'])}</code> on
  <code>{html.escape(man['ap_mac'])}</code> +
  {len(man['devices'])-1} lab clients (all
  <code>{LAB_OUI}</code>). Nothing here belongs to a real network.</p>
  <table><tr><th>tier</th><th>scenario</th><th>list</th><th>capture</th>
   </tr>{tiers}</table>
  <p class='tag warn'>{html.escape(man['scope_rule'])}</p></div>""")

    def analysis_page(self):
        tier = "easy"
        cap = os.path.join(self.ds["dir"],
                           self.ds["manifest"]["tiers"][tier]["capture"])
        an = analyze_handshake(cap)
        b = an["bundles"][0] if an["bundles"] else {}
        return _page("handshake lab — capture", self._nav() + f"""
 <div class='card'><h1>📡 capture state</h1>
  <table><tr><td>frames</td><td>{an['frames']}</td></tr>
   <tr><td>EAPOL</td><td>{an['eapol']}</td></tr>
   <tr><td>messages</td><td>{b.get('msgs')}</td></tr>
   <tr><td>complete?</td><td>{an['captured']}</td></tr>
   <tr><td>MIC descriptor</td><td>v{b.get('desc_version')}</td></tr>
  </table>
  <p class='dim'>{html.escape(an['verdict'])}</p></div>""")

    def audit_page(self):
        tier_rows = []
        for tier in DIFFICULTY_ORDER:
            btn = (f"<form method='post' action='/audit' "
                   f"style='display:inline'>"
                   f"<input type='hidden' name='tier' value='{tier}'>"
                   f"<button class='go'>audit {tier}</button></form>")
            r = self.results.get(tier)
            cell = (f"<b>found</b> <code>{html.escape(r['password'])}</code> "
                    f"after {r['attempts']} guesses "
                    f"({r['elapsed_s']}s @ {r['rate']}/s)"
                    if r and r["found"] else
                    f"exhausted {r['attempts']} guesses — "
                    f"password resisted" if r and r.get("ok") else
                    "not run")
            tier_rows.append(f"<div class='card'><b>{tier}</b> — {cell} "
                             f"{btn}</div>")
        return _page("handshake lab — audit", self._nav() +
                     "".join(tier_rows) + self._compare_chart_svg())

    def compare_page(self):
        return _page("handshake lab — compare", self._nav() + f"""
 <div class='card'><h1>⚖️ tiers</h1>{self._compare_chart_svg()}
  <p class='dim'>easy/medium fall; expert exhausts the list — same
  capture machinery, different password reality.</p></div>""")

    def three_state_page(self):
        rows = []
        for tier in DIFFICULTY_ORDER:
            r = self.results.get(tier)
            if r is None:
                continue
            verdict = ("✔ " + html.escape(r["password"] or "")) \
                if r["found"] else "✘ nothing found"
            rows.append(
                f"<tr><td>{tier}</td><td>✔</td>"
                f"<td>{verdict}</td>"
                f"<td class='dim'>run /audit/{tier}/authenticate to "
                f"prove possession</td></tr>")
        body = ("".join(rows) or "<tr><td colspan=4 class='dim'>"
                "run audits first</td></tr>")
        return _page("handshake lab — three states", self._nav() + f"""
 <div class='card'><h1>🔖 three states, three meanings</h1>
  <table><tr><th>tier</th><th>captured</th><th>audited</th>
   <th>authenticated</th></tr>{body}</table>
  <p class='dim'>{html.escape(three_states(self._dirs(), 'easy')['moral'])}
  </p></div>""")

    def exercises_page(self):
        items = "".join(
            f"<div class='card'><span class='chip "
            f"{'ok' if x['flag'] in self.completed else 'warn'}'>"
            f"{'✓' if x['flag'] in self.completed else 'todo'}</span> "
            f"<b>{html.escape(x['title'])}</b> — {x['task']} "
            f"<span class='dim'>({x['weight']} pts)</span></div>"
            for x in HS_EXERCISES)
        return _page("handshake lab — exercises",
                     self._nav() + "<div class='card'><h1>📝 "
                     "exercises</h1></div>" + items)

    def quiz_page(self):
        qs = [
            ("q_states", "What are the three states of this lab?",
             ("capture-audit-auth", "scan-crack-join",
              "capture-deauth-join", "listen-break-own")),
            ("q_audit_space", "What determines audit cost most?",
             ("list-and-position", "the AP's channel",
              "your CPU brand", "the beacon interval")),
            ("q_mic_role", "What does the handshake MIC prove?",
             ("integrity-proof", "encryption key", "SSID correctness",
              "channel cleanliness")),
            ("q_resists", "How does a strong password beat the audit?",
             ("strong-absent", "MIC too short", "5GHz immune",
              "more frames")),
            ("q_time_cost", "Time roughly = ?",
             ("linear-in-list", "log in frames", "random", "zero")),
            ("q_scope", "Scope rule of this lab?",
             ("lab-only", "any open network", "campus wifi",
              "your neighbor")),
        ]
        form = [f"<div class='card'><b>{q}</b>" +
                "".join(f"<label style='display:block'>"
                        f"<input type='radio' name='{qid}' value='{c}'> "
                        f"{html.escape(c)}</label>" for c in cs)
                + "</div>" for qid, q, cs in qs]
        return _page("handshake lab — quiz",
                     self._nav() + "<form method='post' action='/quiz'>"
                     + "".join(form) +
                     "<button class='go'>score</button></form>")

    def quiz_submit(self, form, client):
        answers = {qid: (form.get(qid, [""])[0]
                         if form.get(qid) else "") for qid in HS_QUIZ}
        score, notes = score_hslab(answers)
        self.store.attempt("hs", "quiz", json.dumps(answers), score,
                           f"{score:.1f}", client)
        li = "".join(f"<li>{html.escape(n)}</li>" for n in notes)
        return _page("handshake lab — quiz result", self._nav() +
                     f"<div class='card'><h1>✅ {score:.1f} / 100</h1>"
                     f"<ul>{li}</ul></div>")

    def instructor_page(self, token):
        funnel = self.store.funnel("hs")
        runs = "".join(
            f"<tr><td>{tier}</td>"
            f"<td>{'found <code>' + html.escape(r['password']) + '</code>' if r['found'] else 'exhausted'}</td>"
            f"<td>{r['attempts']}</td><td>{r['elapsed_s']}s</td>"
            f"<td>{r['rate']}/s</td></tr>"
            for tier, r in self.results.items() if r)
        return _page("handshake lab — instructor", self._nav() + f"""
 <div class='card'><h1>🧑‍🏫 instructor console</h1>
  <p class='dim'>funnel: {funnel['views']} views /
  {funnel['attempts']} attempts · best {funnel['best_score']:.1f}.
  Alerts: {len(self.alerts)}</p>
  <form method='post' action='/i/{html.escape(token)}/regenerate'
   style='display:inline'><button class='go'>
   regenerate creds+captures</button></form>
  <form method='post' action='/i/{html.escape(token)}/reset'
   style='display:inline'><button class='go'>reset progress</button>
  </form>
  <form method='post' action='/i/{html.escape(token)}/destroy'
   style='display:inline'
   onsubmit="return confirm('destroy dataset?')">
   <button class='go stop'>destroy dataset</button></form>
  <h2>latest audits</h2>
  <table><tr><th>tier</th><th>verdict</th><th>attempts</th>
   <th>time</th><th>rate</th></tr>
   {runs or '<tr><td colspan=5 class=dim>none yet</td></tr>'}</table>
  <h2>credentials (instructor-only)</h2>
  <table>""" + "".join(
      f"<tr><td>{t}</td><td><code>"
      f"{html.escape(_creds_of(self.ds['dir'])[t]['password'])}</code>"
      "</td></tr>" for t in DIFFICULTY_ORDER) + """</table>
  <p class='dim'>These three strings are the lab credentials under test.
  Nothing real.</p></div>""")

    # ---------- instructor actions ----------
    def regenerate(self, client):
        with self.lock:
            old = _creds_of(self.ds["dir"])
            seed = self.ds["manifest"].get("seed", 3) + \
                len(self.results) + 1
            generate_dataset(self.ds["dir"], seed=seed, fresh=True)
            self.ds = load_dataset(self.ds["dir"])
            new = _creds_of(self.ds["dir"])
            self.results.clear()
            self.store.event("hs", "regenerate",
                             f"seed {seed}; pw shifted "
                             f"'{old['easy']['password']}'→"
                             f"'{new['easy']['password']}'", client)

    def reset(self, client):
        with self.lock:
            self.results.clear()
            self.completed.clear()
            self.store.event("hs", "reset",
                             f"wiped after "
                             f"{self.store.funnel('hs')['attempts']} "
                             "attempts", client)

    def destroy(self, client):
        with self.lock:
            n = 0
            for tier, spec in self.ds["manifest"]["tiers"].items():
                for k in ("capture", "wordlist"):
                    p = os.path.join(self.ds["dir"], spec[k])
                    if os.path.exists(p):
                        n += os.path.getsize(p)
                        os.remove(p)
            for extra in ("manifest.json", "creds.json"):
                p = os.path.join(self.ds["dir"], extra)
                if os.path.exists(p):
                    n += os.path.getsize(p)
                    os.remove(p)
            self.store.event("hs", "destroy",
                             f"{n} bytes of lab material shredded", client)
            return n


def _creds_of(dest_dir):
    path = os.path.join(dest_dir, "creds.json")
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)["tiers"]


# ---------------------------------------------------------------------------
# HTTP server
# ---------------------------------------------------------------------------

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer  # noqa: E402
from hmac import compare_digest as _cd  # noqa: E402


class _HSHandler(BaseHTTPRequestHandler):
    _MAX_POST = 65536

    def log_message(self, fmt, *a):
        pass

    def _client(self):
        xff = self.headers.get("X-Forwarded-For", "")
        return (xff.split(",")[0].strip() or self.client_address[0])[:45]

    def _form(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > self._MAX_POST:
            return None
        if n == 0:
            return {}
        return parse_qs(self.rfile.read(n).decode("utf-8", "ignore"))

    def _ok(self, body, ctype="text/html; charset=utf-8"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code=200):
        body = json.dumps(obj, indent=1).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        app = self.server.app
        u = urlparse(self.path)
        path = u.path.rstrip("/") or "/"
        app.store.event("hs", "view", path, self._client())
        if path in ("/", "/analysis", "/audit", "/compare",
                    "/three", "/exercises", "/quiz"):
            page = {"/": app.home, "/analysis": app.analysis_page,
                    "/audit": app.audit_page, "/compare": app.compare_page,
                    "/three": app.three_state_page,
                    "/exercises": app.exercises_page,
                    "/quiz": app.quiz_page}[path]()
            return self._ok(page)
        if path == "/api/state":
            tok = (parse_qs(u.query).get("token") or [""])[0]
            if not (tok and _cd(tok.encode(),
                                (app.token or "").encode())):
                return self._json({"error": "not found"}, 404)
            return self._json({
                "ok": True,
                "results": {t: r for t, r in app.results.items()},
                "completed": sorted(app.completed),
                "funnel": app.store.funnel("hs"),
                "alerts": app.alerts[-50:],
                "tiers": list(app.ds["manifest"]["tiers"]),
            })
        if path == "/i/" + app.token:
            return self._ok(app.instructor_page(app.token))
        return self._json({"error": "not found"}, 404)

    def do_POST(self):
        app = self.server.app
        u = urlparse(self.path)
        path = u.path.rstrip("/") or "/"
        form = self._form()
        if form is None:
            return self._json({"error": "bad request"}, 400)
        if path == "/quiz":
            return self._ok(app.quiz_submit(form, self._client()))

        if path == "/audit" or any(path == "/api/run/" + t
                                   for t in DIFFICULTY_ORDER):
            if path.startswith("/api/run/"):
                tier = path.rsplit("/", 1)[-1]
            else:
                tier = (form.get("tier") or ["easy"])[0]
            if tier not in (list(DIFFICULTY_ORDER) + ["*"]):
                return self._json({"error": f"unknown tier {tier}"}, 400)
            if tier == "*":
                out = {t: app._audit_tier(t, client=self._client())
                       for t in DIFFICULTY_ORDER}
                return self._json(out)
            res = app._audit_tier(tier, client=self._client())
            return self._json(res)
        if path == "/authenticate":
            tier = (form.get("tier") or ["easy"])[0]
            res = self.results.get(tier) if False else None
            app2 = self.server.app
            r = app2.results.get(tier)
            pw = r["password"] if r and r["found"] else \
                (form.get("password") or [""])[0]
            if not pw:
                return self._json({"authenticated": False,
                                   "state": "no-candidate",
                                   "evidence": "audit first"}, 400)
            cap = os.path.join(app2.ds["dir"],
                               app2.ds["manifest"]["tiers"][tier]["capture"])
            out = authenticate(cap, pw)
            if out["authenticated"]:
                app2.completed.add("decrypted_post_handshake")
            return self._json(out)
        if path == "/i/" + app.token + "/regenerate":
            app.regenerate(self._client())
            return self._json({"ok": True})
        if path == "/i/" + app.token + "/reset":
            app.reset(self._client())
            return self._json({"ok": True})
        if path == "/i/" + app.token + "/destroy":
            n = app.destroy(self._client())
            return self._json({"ok": True, "bytes": n})
        return self._json({"error": "not found"}, 404)


def make_hs_server(bind, port, app):
    class _Srv(ThreadingHTTPServer):
        daemon_threads = True
    srv = _Srv((bind, port), _HSHandler)
    srv.app = app
    return srv


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def cmd_make_dataset(out, seed=3, fresh=False):
    man = generate_dataset(out, seed=seed, fresh=fresh)
    tiers = ", ".join(f"{t}: {s['candidates']} candidates"
                      for t, s in man["tiers"].items())
    print(f"handshake dataset written: {out} ({tiers})")


def cmd_inventory(db):
    ds = load_dataset(db)
    man = ds["manifest"]
    print(f"handshake lab inventory — SSID {man['ssid']!r} "
          f"AP {man['ap_mac']} tiers {', '.join(man['tiers'])}")
    for d in man["devices"]:
        print(f"  · {d['device_id']:10s} {d['mac']}  {d['role']}")


def cmd_analyze(db, tier="easy"):
    ds = load_dataset(db)
    cap = os.path.join(ds["dir"], ds["manifest"]["tiers"][tier]["capture"])
    an = analyze_handshake(cap)
    print(f"{tier}: frames={an['frames']} eapol={an['eapol']} "
          f"captured={an['captured']}")
    print(f"  {an['verdict']}")
    return 0 if an["captured"] else 1


def cmd_audit(db, tier="easy", quiet=False):
    ds = load_dataset(db)
    cap = os.path.join(ds["dir"], ds["manifest"]["tiers"][tier]["capture"])
    words = load_wordlist(ds["dir"], tier)
    if not quiet:
        print(f"auditing {tier}: {len(words)} candidates "
              f"(lab wordlist only)")
    res = audit(cap, words)
    print(f"  found={res['found']} attempts={res['attempts']} "
          f"elapsed={res['elapsed_s']}s rate={res['rate']}/s"
          + (f" password={res['password']!r}" if res["found"] else ""))
    print(f"  {res['note']}")
    return 0 if res["found"] else 1


def cmd_compare(db):
    ds = load_dataset(db)
    for tier in DIFFICULTY_ORDER:
        cap = os.path.join(ds["dir"],
                           ds["manifest"]["tiers"][tier]["capture"])
        words = load_wordlist(ds["dir"], tier)
        res = audit(cap, words)
        mark = "FOUND" if res["found"] else "resisted"
        print(f"  {tier:8s} {mark:8s} {res['attempts']:5d} tries "
              f"{res['elapsed_s']:6.2f}s @ {res['rate']:6.0f}/s")
    print("  (expert resisting the list is the lesson, not a bug)")
    return 0


def cmd_authenticate(db, tier, password):
    st = authenticate(os.path.join(
        load_dataset(db)["dir"],
        load_dataset(db)["manifest"]["tiers"][tier]["capture"]), password)
    print(f"authenticate[{tier}]: {st['state']}")
    print(f"  {st['evidence']}")
    return 0 if st.get("authenticated") else 1


def cmd_score(answers):
    try:
        payload = json.load(open(answers, encoding="utf-8")) \
            if answers != "-" else json.load(os.sys.stdin)
    except (OSError, json.JSONDecodeError) as e:
        print(f"score: cannot parse answers: {e}")
        return 2
    score, notes = score_hslab(payload)
    print(f"handshake lab score: {score:.1f} / 100")
    for n in notes:
        print(f"  {n}")
    return 0 if score >= 60 else 1


def cmd_exercises():
    print("handshake lab exercises:")
    for x in HS_EXERCISES:
        print(f"  [{x['id']}] {x['title']} ({x['weight']} pts) — "
              f"{x['task']}")
    return 0
