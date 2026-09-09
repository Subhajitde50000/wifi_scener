# -*- coding: utf-8 -*-
"""autoresp — the automatic (offensive) response laboratory (feature 11).

An offline, scenario-driven lab teaching IDS-driven *automated response*:
simulated detections are evaluated by rule-based policies; depending on the
MODE a response is dry-run-logged, queued for instructor approval, or
*simulated-enforced* on a lab "firewall" state table — with a full audit
trail through every phase: detect → decide → respond → result → rollback.

Nothing touches the network: the "firewall" is a dict in this module;
blocking a device flips a row; rollback flips it back. The real-life
dangers taught here — over-blocking legitimate machines, acting on false
positives, acting without auditability — are what the seeded scenarios
generate and the quizzes score.

Cast of the lab network (all designated lab test devices):

  * TEST-ATTACK-01 — the designated attacker: deauth flood, port sweep,
    auth brute-force, then low-and-slow exfil beacons.
  * IT-SCAN-01 — the organisation's AUTHENTICATED scanner: periodic sweeps
    that must be allowlisted; without the allowlist they trigger port-scan
    rules (the false-positive lesson, deterministic).
  * NEIGHBOR-77 — occasional single probes sitting below thresholds:
    teaches threshold tuning rather than "block everything".

Modes: dry-run | approval | auto | manual. All scoped to the designated
device registry — policies refuse, loudly, to act outside it.
"""

import html
import json
import os
import sys
import threading
import time
from collections import defaultdict

from .devlab import DevLabStore, new_token, _page  # noqa: E402
from .privacy import ensure_secure_storage, secure_file  # noqa: E402

ATTACKER = "TEST-ATTACK-01"
ATTACKER_MAC = "02:00:DE:AD:BE:01"
ITSCAN = "IT-SCAN-01"
ITSCAN_MAC = "02:00:1A:1B:1C:1D"
NEIGHBOR = "NEIGHBOR-77"
NEIGHBOR_MAC = "02:00:77:77:77:77"

DESIGNATED = {ATTACKER: ATTACKER_MAC, ITSCAN: ITSCAN_MAC,
              NEIGHBOR: NEIGHBOR_MAC}

MODES = ("dry-run", "approval", "auto", "manual")


# ------------------------------------------------------------------ events

def build_event_stream(seed=11, n_ticks=96):
    """Deterministic event stream: (tick, kind, src, detail, weight).

    Kinds: deauth (mgmt storm), portscan, authfail, beacon, probe.
    weight = magnitude of that single event in the counter.
    """
    rnd = __import__("random").Random(seed)
    ev = []

    def add(t, kind, src, detail, w=1):
        if 0 <= t < n_ticks:
            ev.append((t, kind, src, detail, w))

    # phase 1 (ticks 8-17): deauth flood from attacker, intense
    for t in range(8, 18):
        for _ in range(rnd.randint(6, 10)):
            add(t, "deauth", ATTACKER,
                "deauth frame at victim client (broadcast=false)")
    # phase 2 (ticks 20-25): port sweep burst (loud)
    for t in range(20, 26):
        for i in range(5):
            add(t, "portscan", ATTACKER,
                "SYN burst to closed ports " + ",".join(str(8 * t + j)
                                                        for j in range(3)))
    # IT scanner: periodic sweep DAYS (4 quick sweeps per window, 2/day) —
    # authorised, but identical behavior shape to the attacker's sweep
    for t in range(4, n_ticks, 12):
        for i in range(4):
            add(t, "portscan", ITSCAN, "authorised scheduled sweep (range "
                "admin plan §3.2)")
    # NEIGHBOR: one probe now and then — below every threshold
    for t in range(6, n_ticks, 13):
        add(t, "probe", NEIGHBOR, "single probe burst (1 frame)")
    # phase 3 (ticks 34-43): auth brute force
    for t in range(34, 44):
        for _ in range(rnd.randint(4, 7)):
            add(t, "authfail", ATTACKER,
                "login denied: bad password for 'admin'")
    # phase 4 (ticks 50..): low-and-slow exfil beacons
    for t in range(50, n_ticks):
        if t % 2 == 0:
            add(t, "beacon", ATTACKER,
                f"outbound keepalive {t} (every {2} ticks, 40-60 bytes)")
    ev.sort(key=lambda e: e[0])
    return ev


# ------------------------------------------------------------------- rules

def default_rules():
    """The stock rulebook. action ∈ log|alert|block|contain."""
    return [
        dict(rid="R1", kind="deauth", window=6, threshold=8, severity="high",
             action="block", why="deauth-flood rate (>8/6 ticks) — a DoS "
             "kick in progress"),
        dict(rid="R2", kind="portscan", window=12, threshold=6,
             severity="medium", action="alert", why="sustained port "
             "sweep (>=6 sweeps/12 ticks)"),
        dict(rid="R3", kind="authfail", window=8, threshold=12,
             severity="high", action="block", why="auth brute-force "
             "(>12 failures/8 ticks)"),
        dict(rid="R4", kind="beacon", window=20, threshold=8,
             severity="medium", action="alert", why="low-and-slow beacon "
             "cadence (>=8/20 ticks)"),
        dict(rid="R5", kind="probe", window=12, threshold=8,
             severity="low", action="log", why="probe chatter "
             "(=record, never block: too generic)"),
        dict(rid="R6", kind="portscan", window=6, threshold=4,
             severity="high", action="block",
             why="AGGRESSIVE sweep blocking (>=4/6 ticks) — shipped "
             "DISABLED: enable it in the UI and watch your own IT "
             "scanner get blocked unless it is allowlisted — the "
             "false-positive lesson"),
    ]


ACTIONS_FOR = {"log": "log-only", "alert": "alert", "block": "block-mac",
               "contain": "contain-host"}


# ---------------------------------------------------------------- simulation

class ResponseLab:
    """The whole lab brain: event stream → detections → decisions →
    (mode-dependent) enforcement → audit trail."""

    def __init__(self, seed: int = 11, n_ticks: int = 96):
        self.seed = seed
        self.n_ticks = n_ticks
        self.lock = threading.RLock()
        self.reset_all()

    # ------------- lifecycle
    def reset_all(self):
        self.rules = default_rules()
        self.allowlist = {ITSCAN_MAC}      # sane default — students may clear
        self.mode = "dry-run"
        self.firewall = {}                 # mac -> dict(action, rule, tick)
        self.contained = set()
        self.audit = []                    # entries {t, phase, ...}
        self.pending = []                  # approval queue entries
        self._windows = defaultdict(list)  # (kind,src) -> [ticks]
        self._fired = set()                # (rule, src) — legacy mirror
        self._last_fire = {}               # (rule, src) -> tick of last fire
        self._dry_tick_seen = set()        # dry-run within-tick dedupe
        self.enabled_rules = {r["rid"] for r in self.rules
                              if r["rid"] != "R6"}   # R6 ships disabled
        self._log("log", note="scenario loaded and lab state reset")

    # ------------- audit
    def _log(self, phase, **kw):
        with self.lock:
            entry = dict(t=len(self.audit), phase=phase, **kw)
            self.audit.append(entry)
            return entry

    # ------------- phase 1: detection
    def detections_at(self, tick):
        """Fire rules against events seen so far at this tick."""
        out = []
        for rule in self.rules:
            if rule["rid"] not in self.enabled_rules:
                continue
            win = rule["window"]
            buckets = defaultdict(int)
            for (k, src), ticks in list(self._windows.items()):
                if k != rule["kind"]:
                    continue
                recent = [t for t in ticks if tick - win < t <= tick]
                if len(recent) >= rule["threshold"]:
                    tag = (rule["rid"], src)
                    # Sliding-window dedupe: once the flood falls out of the
                    # window it may re-fire — that's exactly what a real IDS
                    # does when an attacker comes back, and it's what makes
                    # the dry-run → auto mode switch teach re-checkable
                    # history instead of swallowing past attacks forever.
                    if (tick - self._last_fire.get(tag, -10 ** 9)) > win:
                        pass
                    elif self.mode == "dry-run":
                        # dry-run never consumes fires; dedupe repeats
                        # *within its own tick* only.
                        tkey = (tag, tick)
                        if tkey in self._dry_tick_seen:
                            continue
                        self._dry_tick_seen.add(tkey)
                    else:
                        continue
                    if self.mode != "dry-run":
                        self._last_fire[tag] = tick
                        self._fired.add(tag)
                    out.append(dict(rule=rule["rid"], src=src,
                                    magnitude=len(recent),
                                    severity=rule["severity"],
                                    why=rule["why"], action=rule["action"],
                                    tick=tick))
        return out

    # ------------- phase 2: decision policy
    def decide(self, det):
        """Every detection produces a decision row. Scope is enforced
        HERE: only designated lab devices may ever be acted on."""
        mac = DESIGNATED.get(det["src"])
        if mac is None:
            return dict(det, decision="out-of-scope",
                        reason=(f"{det['src']} is NOT a designated lab test "
                                f"device — the lab refuses to act on it"),
                        action=None, mac=None)
        open_pending = [p for p in self.pending
                        if p["mac"] == mac and not p.get("closed")]
        if open_pending:
            return dict(det, decision="already-queued", mac=mac,
                        reason=(f"{mac} already has pending action "
                                f"#{open_pending[0]['pending_id']} — no "
                                f"duplicates in the approval queue"),
                        action=None)
        if mac in self.allowlist:
            return dict(det, decision="allowlisted-drop", mac=mac,
                        reason=(f"{mac} is in the allowlist — rule "
                                f"{det['rule']} fires but the policy "
                                f"documents it as authorised noise"),
                        action=None)
        if ALREADY := self.firewall.get(mac):
            return dict(det, decision="already-acted", mac=mac,
                        reason=f"{mac} is already under "
                        f"'{ALREADY['action']}' since tick "
                        f"{ALREADY['tick']} (cooldown/idempotence)",
                        action=None)
        if det["action"] == "log":
            return dict(det, decision="log-only", mac=mac,
                        reason=f"rule {det['rule']} is record-only — "
                               f"no enforcement ever for that kind",
                        action=None)
        return dict(det, decision="act", mac=mac,
                    reason=(f"rule {det['rule']} → {det['action']} applied "
                            f"to designated lab device {mac}"),
                    action=det["action"])

    # ------------- phase 3: response (mode-dependent)
    def apply(self, dec, dry_run=None):
        """Returns the resulting audit-phase result string.

        dry_run overrides the lab's live mode — the what-if sandbox runs
        with dry_run=True so it is, by hard construction, incapable of
        changing the shared state regardless of its rules/allowlist.
        """
        action = dec["action"]
        if dec["decision"] != "act":
            self._log("decision", ref=dec)
            if dec["decision"] == "log-only":
                self._log("result", note="recorded", ref=dec)
            return dec["decision"]
        if self.mode == "manual":
            self._log("decision", ref=dec, note="manual mode — awaiting "
                      "operator; nothing executed")
            self._log("result", note="manual-pending", ref=dec)
            return "manual-pending"
        if self.mode == "dry-run" or dry_run is True:
            self._log("decision", ref=dec, note="dry-run: what WOULD happen")
            self._log("response", action=action, mac=dec["mac"],
                      rule=dec["rule"], executed=False)
            self._log("result", note="would-block",
                      target=dec["mac"], rule=dec["rule"],
                      sandbox=bool(dry_run))
            return "dry-run"
        if self.mode == "approval":
            pend = dict(dec, pending_id=len(self.pending))
            self.pending.append(pend)
            self._log("decision", ref=dec,
                      note=f"queued for instructor approval "
                           f"(pending #{pend['pending_id']})")
            self._log("result", note="queued")
            return "queued"
        # auto: execute immediately (simulated)
        self._enforce(dec["mac"], action, dec["rule"])
        self._log("decision", ref=dec, note="auto mode")
        self._log("response", action=action, mac=dec["mac"],
                  rule=dec["rule"], executed=True, mode="auto")
        self._log("result", note="enforced", target=dec["mac"],
                  outcome=(f"{dec['mac']} now {action}ed; traffic from it "
                           f"is dropped by the lab firewall table"),
                  rollbackable=True)
        return "enforced"

    def _enforce(self, mac, action, rule):
        with self.lock:
            self.firewall[mac] = dict(action=action, rule=rule,
                                      tick=self._now_tick,
                                      since=time.time())
            if action == "contain":
                self.contained.add(mac)

    # ------------- approval
    def approve(self, pending_id, by="instructor"):
        with self.lock:
            for p in self.pending:
                if p["pending_id"] == pending_id and not p.get("closed"):
                    p["closed"] = "approved"
                    self._enforce(p["mac"], p["action"], p["rule"])
                    self._log("response", action=p["action"], mac=p["mac"],
                              rule=p["rule"], executed=True,
                              mode="approval", by=by)
                    self._log("result", note="enforced-after-approval",
                              target=p["mac"], by=by)
                    return True
        return False

    def deny(self, pending_id, by="instructor"):
        with self.lock:
            for p in self.pending:
                if p["pending_id"] == pending_id and not p.get("closed"):
                    p["closed"] = "denied"
                    self._log("result", note="denied-by-instructor",
                              target=p["mac"], by=by)
                    self._log("response", action=None, mac=p["mac"],
                              rule=p["rule"], executed=False,
                              mode="approval", by=by)
                    return True
        return False

    # ------------- rollback
    def rollback(self, mac):
        with self.lock:
            row = self.firewall.pop(mac, None)
            self.contained.discard(mac)
            if row:
                self._log("rollback", mac=mac, former=row,
                          note="containment rolled back — lab firewall row "
                               "removed")
                return True
            self._log("rollback", mac=mac, note="nothing to roll back")
            return False

    # ------------- driver
    _now_tick = 0

    def run(self, upto=None, from_tick=None):
        """Advance the simulation: feed events, detect, decide, respond."""
        evs = build_event_stream(self.seed, self.n_ticks)
        upto = self.n_ticks - 1 if upto is None else upto
        start = 0 if from_tick is None else from_tick
        self._log("log", note=f"simulation slice ticks {start}…{upto} "
                              f"(mode={self.mode})")
        for tick in range(start, upto + 1):
            self._now_tick = tick
            for (t, kind, src, detail, w) in [e for e in evs if e[0] == tick]:
                self._windows[(kind, src)].append(t)
                self._log("detect", kind=kind, src=src, detail=detail)
            for det in self.detections_at(tick):
                dec = self.decide(det)
                self.apply(dec)
        return self.audit

    # ------------- metrics
    def metrics(self):
        blocks = [a for a in self.audit if a["phase"] == "result"
                  and a.get("note") in ("enforced",
                                        "enforced-after-approval")]
        fp = [b for b in blocks if b.get("target") == ITSCAN_MAC]
        real = [b for b in blocks if b.get("target") == ATTACKER_MAC]
        sne = [b for b in blocks if b.get("target") == NEIGHBOR_MAC]
        return dict(enforced_total=len(blocks), true_positives=len(real),
                    false_positives=len(fp), blocked_neighbor=len(sne),
                    audit_entries=len(self.audit))


# ------------------------------------------------------------------ scoring

RESP_QUIZ = {
    "q_dryrun": 20, "q_fp_cause": 20, "q_pending": 20,
    "q_rollback": 20, "q_scope": 20,
}


def score_response_answers(answers):
    fb = []
    pts = 0.0
    # Q1 dry-run semantics
    a = answers.get("q_dryrun", "")
    if a == "nothing-enforced":
        pts += RESP_QUIZ["q_dryrun"]
        fb.append("✅ Q1: correct — dry-run records decide/respond-WOULD "
                  "without touching the lab firewall table")
    else:
        fb.append("❌ Q1: dry-run never writes state — the 'would-block' "
                  "rows are the whole point")
    # Q2 FP cause
    a = answers.get("q_fp_cause", "")
    if a == "aggressive-without-allowlist":
        pts += RESP_QUIZ["q_fp_cause"]
        fb.append("✅ Q2: correct — R6 + empty allowlist = friendly fire "
                  "on IT-SCAN-01; tiny policy gap, big blast radius")
    else:
        fb.append("❌ Q2: the controlled FP comes from an aggressive rule "
                  "meeting a missing allowlist")
    # Q3 approval behaviour
    a = answers.get("q_pending", "")
    if a == "queued":
        pts += RESP_QUIZ["q_pending"]
        fb.append("✅ Q3: correct — approval mode queues, enforcement waits "
                  "for the instructor click")
    else:
        fb.append("❌ Q3: in approval mode the action lands in the pending "
                  "queue; the firewall row appears only after approve")
    # Q4 rollback semantics
    a = answers.get("q_rollback", "")
    if a == "safe-removes-row":
        pts += RESP_QUIZ["q_rollback"]
        fb.append("✅ Q4: correct — rollback is the first-class undo of a "
                  "containment/block row, safe by construction")
    else:
        fb.append("❌ Q4: rollback simply removes the enforcement row — "
                  "safe, auditable, and the reason 'auto' is allowed at all")
    # Q5 scope
    a = answers.get("q_scope", "")
    if a == "designated-only":
        pts += RESP_QUIZ["q_scope"]
        fb.append("✅ Q5: correct — policies act ONLY on registered lab "
                  "test devices; anything else is refused at decision time")
    else:
        fb.append("❌ Q5: scope is enforced in decide(): non-designated "
                  "src → 'out-of-scope', always")
    total = sum(RESP_QUIZ.values())
    return dict(score=round(100.0 * pts / total, 1),
                points=round(pts, 1), possible=total, feedback=fb,
                answers=answers)


def response_exercises() -> str:
    items = [
        ("1. Watch the dry-run", "`response-lab simulate --mode dry-run` — "
         "which rules fire, in which order, on which designated device? "
         "What changes in the firewall table? (spoilers: nothing — say why)"),
        ("2. Skim the audit", "Each enforced action must create exactly the "
         "chain detect→decide→response→result. Find one rule firing that "
         "never becomes a response. Why is that legal? (hint: R2 and R5)"),
        ("3. Enable the aggressive policy", "Run with the IT scanner NOT "
         "allowlisted but R6 enabled (`simulate --enable-rule R6 "
         "--clear-allowlist --mode auto`). Who got blocked first? Whose "
         "action is that — the IDS's or YOURS?"),
        ("4. The blame-conversation", "Same run WITH the allowlist — the "
         "attacker still gets blocked, your scanner lives. Which table row "
         "is the whole lesson?"),
        ("5. Approval choreography", "Run `--mode approval`: enforcement "
         "IDLES until the instructor clicks. What does 'already-queued' "
         "prevent from happening?"),
        ("6. The rollback drill", "In the web lab: enforce, then roll the "
         "block back. Compare the audit trail to a hypothetical product "
         "that has unblock but no rollback log — what would be missing?"),
        ("7. Quiz", "`response-lab score --answers ans.json`. Which answer "
         "was hardest — the mode semantics, the FP mechanics, or the "
         "scope rule?"),
    ]
    return ("Response-lab — guided exercises\n\n" + "\n\n".join(
        f"■ {t}\n{b}" for t, b in items) + "\n")


# ================================================================== web app

class ResponseWebApp:
    """Student portal + instructor console for the response lab."""

    CAST = [(ATTACKER, ATTACKER_MAC, "designated attacker (halt after lab)"),
            (ITSCAN, ITSCAN_MAC, "registered IT scanner (allowlist it)"),
            (NEIGHBOR, NEIGHBOR_MAC, "ambient neighbour node (never acts)")]

    def __init__(self, store: DevLabStore, token: str, seed: int = 11,
                 n_ticks: int = 96):
        self.store = store
        self.token = token
        self.seed = seed
        self.n_ticks = n_ticks
        self.lab = ResponseLab(seed=seed, n_ticks=n_ticks)
        self.lock = self.lab.lock
        self.last_tick = -1

    # ---------------- engine ops (instructor-initiated)
    def run_to(self, upto):
        with self.lock:
            frm = max(0, self.last_tick + 1)
            upto = max(frm, min(self.lab.n_ticks - 1, int(upto)))
            self.lab.run(upto=upto, from_tick=frm)
            self.last_tick = upto
            return upto

    def reset_lab(self):
        with self.lock:
            self.lab.reset_all()
            self.last_tick = -1

    def regenerate(self):
        with self.lock:
            self.seed += 1
            self.lab = ResponseLab(seed=self.seed, n_ticks=self.n_ticks)
            self.reset_lab()
            return self.seed

    # ---------------- pages
    def _nav(self):
        return ("<nav><a class='btn ghost' href='/'>🏠 brief</a>"
                "<a class='btn ghost' href='/console'>🖥 console</a>"
                "<a class='btn ghost' href='/rules'>📜 rules</a>"
                "<a class='btn ghost' href='/blocks'>🧱 firewall</a>"
                "<a class='btn ghost' href='/audit'>🧾 audit</a>"
                "<a class='btn ghost' href='/quiz'>✅ quiz</a>"
                "<a class='btn ghost' href='/exercises'>🧭 exercises</a>"
                "</nav>")

    def _modechip(self):
        return ("<span class='chip info'>mode: <b>" +
                html.escape(self.lab.mode) + "</b></span>")

    def home(self):
        m = self.lab.metrics()
        fw_rows = "".join(
            f"<tr><td><code>{mac}</code></td><td>"
            f"{html.escape(v['action'])}</td><td>{html.escape(v['rule'])}"
            f"</td><td>tick {v['tick']}</td></tr>"
            for mac, v in self.lab.firewall.items()) or \
            "<tr><td colspan=4>no enforcement yet</td></tr>"
        cast = "".join(f"<tr><td>{html.escape(n)}</td>"
                       f"<td><code>{html.escape(mac)}</code></td>"
                       f"<td>{html.escape(d)}</td></tr>"
                       for n, mac, d in self.CAST)
        body = self._nav() + f"""
 <div class='hero'><h1>⚙️ Automatic (offensive) response laboratory</h1>
  <p>The lab IDS watches designated test devices on a simulated network.
  Detections flow through rule-based policies; the <b>mode</b> decides who
  gets hurt — nobody, pending-approved persons, or the firewall table
  directly. Your job: make the automatic response defend the lab without
  ever friendly-firing its scanner, and understand <i>why</i>.</p>
  <p class='small'>Isolated simulation — the firewall below is a table in
  this process. No traffic is sent, filtered or dropped anywhere real.</p>
 </div>
 <div class='card'><h2>Cast (all designated lab test devices)</h2>
  <table><tr><th>device</th><th>MAC</th><th>role</th></tr>{cast}</table></div>
 <div class='grid'>
 <div class='card'><h2>State {self._modechip()}
   <span class='chip'>tick {self.last_tick}/{self.lab.n_ticks - 1}</span></h2>
  <p>enforced: {m['enforced_total']} · true+: {m['true_positives']} ·
     <span class='chip {'bad' if m['false_positives'] else 'ok'}>
     false+ {m['false_positives']}</span> · neighbour blocked:
     {m['blocked_neighbor']}</p>
  <p>pending approvals: {len([p for p in self.lab.pending
     if not p.get('closed')])} · audit entries: {m['audit_entries']}</p></div>
 <div class='card'><h2>🧱 lab firewall table</h2>
  <table><tr><th>MAC</th><th>action</th><th>rule</th><th>since</th></tr>
  {fw_rows}</table></div>
 </div>
 <div class='card'><h2>How the pipeline reads</h2>
  <pre>detect → decide → respond → result
  phase 1   events land in sliding windows per (kind, src)
  phase 2   rules match rate+window; allowlist &amp; scope &amp; cooldown applied
  phase 3   mode decides: dry-run logs / approval queues / auto executes
  phase 4   the audit says what actually happened — and rollback if you undo
  </pre></div>"""
        return _page("automatic response lab", body)

    def console(self):
        last = [a for a in self.lab.audit[-160:]][::-1]
        tr = "".join(
            f"<tr><td>{a['t']}</td><td><span class='chip "
            f"{ {'detect':'info','decision':'warn','response':'bad','result':'ok','rollback':'info','log':''} .get(a['phase'],'') }'>"
            f"{html.escape(a['phase'])}</span></td><td class='mono'>"
            f"{html.escape(_describe_audit(a))}</td></tr>" for a in last)
        body = self._nav() + f"""
 <div class='card'><h2>🖥 live console {self._modechip()}
  <span class='chip'>tick {self.last_tick}/{self.lab.n_ticks - 1}</span></h2>
  <p class='small'>The instructor advances time; this table simply renders
  the audit tail. Newest first.</p>
  <table><tr><th>#</th><th>phase</th><th>what</th></tr>{tr}</table></div>"""
        return _page("console", body)

    def rules_page(self):
        tr = "".join(
            f"<tr><td><code>{r['rid']}</code></td><td>{r['kind']}</td>"
            f"<td>{r['threshold']}/{r['window']}</td>"
            f"<td><span class='chip {'bad' if r['action'] in ('block','contain') else 'info'}'>{r['action']}</span></td>"
            f"<td>{'✅ on' if r['rid'] in self.lab.enabled_rules else '⏸ off'}</td>"
            f"<td>{html.escape(r['why'])}</td></tr>"
            for r in self.lab.rules)
        al = ", ".join(f"<code>{m}</code>" for m in
                       sorted(self.lab.allowlist)) or "<i>empty</i>"
        body = self._nav() + f"""
 <div class='card'><h2>📜 rulebook</h2>
  <table><tr><th>id</th><th>kind</th><th>rate</th><th>action</th>
   <th>enabled</th><th>why</th></tr>{tr}</table>
  <p>Allowlist: {al}</p>
  <p class='small'>Toggles are instructor-side (dashboard). R6 ships
  disabled ON PURPOSE — it's the exercise.</p></div>"""
        return _page("rules", body)

    def blocks_page(self):
        fw = self.lab.firewall
        tr = "".join(
            f"<tr><td><code>{mac}</code></td><td>{html.escape(v['action'])}"
            f"</td><td>{html.escape(v['rule'])}</td><td>tick {v['tick']}</td>"
            f"<td><form method='post' action='/rollback' "
            f"style='display:inline'><input type='hidden' name='mac' "
            f"value='{html.escape(mac)}'><button class='btn warn'>↩ rollback"
            f"</button></form></td></tr>" for mac, v in fw.items()) \
            or "<tr><td colspan=5>empty — nothing is currently contained</td></tr>"
        pend = [p for p in self.lab.pending if not p.get("closed")]
        ptr = "".join(f"<tr><td>#{p['pending_id']}</td><td>{p['rule']}</td>"
                      f"<td><code>{p['mac']}</code></td>"
                      f"<td>{p['action']}</td><td>{html.escape(p['reason'])}"
                      f"</td></tr>" for p in pend) \
             or "<tr><td colspan=5>no pending actions</td></tr>"
        body = self._nav() + f"""
 <div class='card'><h2>🧱 lab firewall (Simulated Enforcement)</h2>
  <table><tr><th>MAC</th><th>action</th><th>rule</th><th>since</th>
   <th>undo</th></tr>{tr}</table>
  <p class='small'>Rolling back is a first-class operation: it removes the
  row and writes an audit entry. Try it in manual mode after an
  automatic block.</p></div>
 <div class='card'><h2>⏳ approval queue</h2>
  <table><tr><th>#</th><th>rule</th><th>target</th><th>action</th>
   <th>reason</th></tr>{ptr}</table>
  <p class='small'>Approvals happen on the instructor dashboard
  (/i/&lt;token&gt;).</p></div>"""
        return _page("firewall", body)

    def audit_page(self):
        tr = "".join(
            f"<tr><td>{a['t']}</td><td>{html.escape(a['phase'])}</td>"
            f"<td class='mono'>{html.escape(_describe_audit(a))}</td></tr>"
            for a in self.lab.audit)
        body = self._nav() + f"""
 <div class='card'><h2>🧾 full audit trail ({len(self.lab.audit)} entries)</h2>
  <table><tr><th>#</th><th>phase</th><th>detail</th></tr>{tr}</table></div>"""
        return _page("audit trail", body)

    def sandbox_page(self):
        rules = "".join(f"<label><input type='checkbox' name='rule' "
                        f"value='{r['rid']}'"
                        f"{' checked' if r['rid'] in ('R1','R2','R3','R4','R5') else ''}>"
                        f" {r['rid']} ({r['kind']} → {r['action']})</label> "
                        for r in self.lab.rules)
        body = self._nav() + f"""
 <div class='hero'><h1>🧪 What-if sandbox</h1>
  <p>Change the rules / allowlist below and hit <b>run</b>. The sandbox is
  a throwaway dry-run lab: it never touches the live lab's state, mode,
  firewall, or pending approvals. Watching "would-block" change is the
  policy-engineering muscle.</p>
  <p class='small'>mode: pinned to dry-run · seed: {self.lab.seed} ·
  {self.lab.n_ticks} ticks</p></div>
 <div class='card'><h2>policy what-if</h2>
  <form method='post' action='/sandbox'>
   <p>enable rules: {rules}</p>
   <p>allowlist (comma-separated MACs):<br>
    <input name='allowlist' style='width:100%' placeholder='{
    html.escape(R.ITSCAN_MAC)}'></p>
   <button class='btn ok'>▶ run sandbox</button></form></div>"""
        return _page("sandbox", body)

    def sandbox_submit(self, form, ip=""):
        rules = [r["rid"] for r in self.lab.rules
                 if form.get(f"rule_{r['rid']}", "") == "on" or
                 form.get("rule") == r["rid"]]
        # checkbox naming in sandbox page sends rule=R1 multiple times —
        # handle both single and multi
        if not rules:
            rules = [r["rid"] for r in self.lab.rules
                     if form.get("rule") and r["rid"] in
                     (form["rule"] if isinstance(form["rule"], list)
                      else [form["rule"]])]
        al_raw = (form.get("allowlist") or "").strip().upper()
        allowlist = set()
        for p in (al_raw.split(",") if al_raw else
                  [R.ITSCAN_MAC]):
            p = p.strip()
            if p:
                allowlist.add(p)
        res = sandbox_whatif(rules_enabled=set(rules),
                             allowlist=allowlist, seed=self.lab.seed,
                             n_ticks=self.lab.n_ticks)
        self.store.event("response", "sandbox",
                         f"rules={sorted(rules)} allow={sorted(allowlist)}",
                         ip)
        m = res["metrics"]
        wb = "".join(f"<tr><td><code>{mac}</code></td>"
                     f"<td class='chip bad'>WOULD-BLOCK</td><td>"
                     f"{html.escape(v['rule'])}</td></tr>"
                     for mac, v in res["would_block"].items()) or \
            "<tr><td colspan=3>nothing would be blocked</td></tr>"
        body = self._nav() + f"""
 <div class='card'><h2>🧪 sandbox result
  <span class='chip info'>throwaway dry-run</span></h2>
  <p>true+ {m['true_positives']} · false+ "
   f"<span class='chip {'bad' if m['false_positives'] else 'ok'}'>"
   f"{m['false_positives']}</span> · live state touch: none (by design)</p>
  <table><tr><th>MAC</th><th>verdict</th><th>rule</th></tr>{wb}</table>
  <a class='btn info' href='/sandbox'>↩ tweak again</a></div>"""
        return _page("sandbox result", body)

    def quiz_page(self):
        body = self._nav() + f"""
 <div class='card'><h2>✅ scored quiz</h2>
  <form method='post' action='/quiz'>
   <div class='card'><h3>Q1. In dry-run mode, when R1 fires…</h3>
    <select name='q_dryrun'><option value=''>—</option>
     <option value='nothing-enforced'>the decision and 'would-block' rows are
      written, no firewall state changes</option>
     <option value='adds-row'>a firewall row appears labelled test</option>
     <option value='queues'>the action waits for approval</option></select>
   </div>
   <div class='card'><h3>Q2. Why did IT-SCAN-01 get blocked in the
     aggressive run?</h3>
    <select name='q_fp_cause'><option value=''>—</option>
     <option value='aggressive-without-allowlist'>R6 fired and the scanner
      wasn't allowlisted</option>
     <option value='rng'>random bad luck</option>
     <option value='scanner-bad'>the scanner was genuinely malicious</option>
    </select></div>
   <div class='card'><h3>Q3. In approval mode, a high-severity detection
     does what immediately?</h3>
    <select name='q_pending'><option value=''>—</option>
     <option value='queued'>queues a pending action; nothing enforced yet
      </option>
     <option value='executes'>executes instantly</option>
     <option value='nothing'>is ignored entirely</option></select></div>
   <div class='card'><h3>Q4. Rollback…</h3>
    <select name='q_rollback'><option value=''>—</option>
     <option value='safe-removes-row'>removes the containment row and logs
      the undo — safe by construction</option>
     <option value='arp'>forges an ARP to un-poison tables</option>
     <option value='deletes'>deletes the audit chain to hide traces</option>
    </select></div>
   <div class='card'><h3>Q5. The lab's scope rule means…</h3>
    <select name='q_scope'><option value=''>—</option>
     <option value='designated-only'>policies refuse any src that is not a
      designated lab test device</option>
     <option value='any'>anything detected may be blocked</option>
     <option value='admins'>only instructor IP addresses are blocked</option>
    </select></div>
   <button class='btn ok'>🏁 submit</button></form></div>"""
        return _page("quiz", body)

    def quiz_submit(self, answers, ip=""):
        r = score_response_answers(answers)
        self.store.attempt("response", "quiz", json.dumps(answers),
                           r["score"], json.dumps(r["feedback"]), ip)
        lines = "".join(f"<li>{html.escape(f)}</li>" for f in r["feedback"])
        body = self._nav() + (
            f"<div class='card'><h2>Result: {r['score']}/100</h2><ul>{lines}"
            f"</ul><a class='btn info' href='/quiz'>🔁 retry</a></div>")
        return _page("quiz result", body)

    def exercises_page(self):
        return _page("exercises", self._nav() + (
            "<div class='card'><h2>🧭 worksheet</h2><pre>"
            + html.escape(response_exercises()) + "</pre></div>"))

    # ---------------- instructor
    def instructor(self, token):
        funnel = self.store.funnel("response")
        att = self.store.attempts("response", 50)
        pend = [p for p in self.lab.pending if not p.get("closed")]
        ptr = "".join(
            f"<tr><td>#{p['pending_id']}</td><td>{p['rule']}</td>"
            f"<td><code>{p['mac']}</code></td><td>{p['action']}</td>"
            f"<td>"
            f"<form method='post' action='/api/approve?token={html.escape(token)}' style='display:inline'>"
            f"<input type='hidden' name='id' value='{p['pending_id']}'>"
            f"<button class='btn ok'>✅ approve</button></form> "
            f"<form method='post' action='/api/deny?token={html.escape(token)}' style='display:inline'>"
            f"<input type='hidden' name='id' value='{p['pending_id']}'>"
            f"<button class='btn danger'>✖ deny</button></form></td></tr>"
            for p in pend) or "<tr><td colspan=5>queue empty</td></tr>"
        rtr = "".join(
            f"<tr><td><code>{r['rid']}</code></td>"
            f"<td>{'on' if r['rid'] in self.lab.enabled_rules else 'off'}</td>"
            f"<td><form method='post' action='/api/toggle-rule?token={html.escape(token)}' style='display:inline'>"
            f"<input type='hidden' name='rid' value='{r['rid']}'>"
            f"<button class='btn ghost'>{'⏸ disable' if r['rid'] in self.lab.enabled_rules else '▶ enable'}</button></form></td></tr>"
            for r in self.lab.rules)
        atr = "".join(
            f"<tr><td>{a['time']}</td><td>{html.escape(a['question'])}</td>"
            f"<td><b>{a['score']}</b></td>"
            f"<td class='mono'>{html.escape(str(a['answer']))[:140]}</td></tr>"
            for a in att)
        modes = "".join(
            f"<option value='{m}'{' selected' if m == self.lab.mode else ''}>"
            f"{m}</option>" for m in MODES)
        body = f"""
 <div class='hero'><h1>👩‍🏫 RESPONSE-lab instructor console</h1>
  <p class='small'>Control the exercise: modes, rules, allowlist,
  approvals, time advance, reset &amp; regenerate. Students see the same
  state but cannot change it.</p></div>
 <div class='grid'>
  <div class='card'><h2>Lab controls</h2>
   <form method='post' action='/api/mode?token={html.escape(token)}'>
    mode: <select name='mode'>{modes}</select>
    <button class='btn info'>apply</button></form>
   <form method='post' action='/api/allowlist?token={html.escape(token)}'>
    allowlist (comma): <input name='value' style='width:70%' value='{
    html.escape(','.join(sorted(self.lab.allowlist)))}'>
    <button class='btn info'>apply</button></form>
   <form method='post' action='/api/advance?token={html.escape(token)}'>
    ⏭ advance simulation to tick: <input type='number' name='upto'
     value='{min(self.lab.n_ticks - 1, self.last_tick + 24)}'
     min='{max(0, self.last_tick + 1)}' max='{self.lab.n_ticks - 1}'>
    <button class='btn info'>run</button></form>
   <button class='btn danger' id='rb'>🧹 reset lab + attempts</button>
   <button class='btn warn' style='background:var(--warn);color:#422006'
    id='gb'>🎲 regenerate (seed {self.seed + 1})</button>
   <a class='btn ghost' href='/'>student view</a>
  </div>
  <div class='card'><h2>Rule toggles</h2>
   <table><tr><th>rule</th><th>state</th><th></th></tr>{rtr}</table></div>
  <div class='card'><h2>Exercise truth</h2>
   <p>attacker: <code>{ATTACKER_MAC}</code> → R1/R6/R3/R4 expected<br>
   scanner: <code>{ITSCAN_MAC}</code> → benign (allowlist) or FP victim<br>
   neighbour: <code>{NEIGHBOR_MAC}</code> → below all thresholds</p>
   <p>metrics: {html.escape(json.dumps(self.lab.metrics()))}</p>
   <p>funnel: {funnel}</p>
  </div>
 </div>
 <div class='card'><h2>⏳ pending approvals ({len(pend)})</h2>
  <table><tr><th>#</th><th>rule</th><th>target</th><th>action</th>
   <th></th></tr>{ptr}</table></div>
 <div class='card'><h2>Recent quiz attempts ({len(att)})</h2>
  <table><tr><th>time</th><th>q</th><th>score</th><th>answers</th></tr>
  {atr or '<tr><td colspan=4>none yet</td></tr>'}</table></div>
 <script>
 const TOKEN=""" + json.dumps(token) + """;
 async function rst(){if(!confirm('Reset simulation + attempts log?'))return;
  await fetch('/api/reset?token='+TOKEN,{method:'POST'});location.reload();}
 async function regen(){if(!confirm('Regenerate scenario (seed+1)?'))return;
  const r=await fetch('/api/regenerate?token='+TOKEN,{method:'POST'});
  const d=await r.json();alert('new seed '+d.seed);location.href='/';}
 document.getElementById('rb').addEventListener('click',rst);
 document.getElementById('gb').addEventListener('click',regen);
 </script>"""
        return _page("instructor — response lab", body)


def _describe_audit(a):
    p = a["phase"]
    if p == "detect":
        return f"{a.get('kind')} from {a.get('src')}: {a.get('detail','')}"
    if p == "decision":
        ref = a.get("ref", {})
        return (f"[{ref.get('rule','?')}] {ref.get('src','?')} → "
                f"{ref.get('decision','?')} — {ref.get('reason','')}"
                + (f" | {a.get('note','')}" if a.get("note") else ""))
    if p == "response":
        return (f"{a.get('action') or 'no-op'} on {a.get('mac','-')} "
                f"(rule {a.get('rule','-')}, "
                f"{'EXECUTED' if a.get('executed') else 'NOT executed'}, "
                f"mode={a.get('mode','dry-run')})")
    if p == "result":
        return (f"{a.get('note','')} {a.get('target','')} "
                f"{a.get('outcome','')}")
    if p == "rollback":
        return a.get("note", "")
    return a.get("note", "")


def make_response_server(bind, port, app: ResponseWebApp):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from urllib.parse import urlparse, parse_qs

    class H(BaseHTTPRequestHandler):
        server_version = "wifiscanner-response"
        protocol_version = "HTTP/1.1"
        _MAX_POST = 65536

        def log_message(self, *a):
            pass

        def _ok(self, s):
            if isinstance(s, str):
                s = s.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(s)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(s)

        def _json(self, obj, code=200):
            s = json.dumps(obj, indent=1).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(s)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(s)

        def _client(self):
            return self.client_address[0] if self.client_address else "?"

        def _tok_ok(self, u):
            q = parse_qs(u.query)
            return q.get("token", [""])[0] == app.token

        def do_GET(self):
            u = urlparse(self.path)
            path = u.path
            if path.startswith("/i/"):
                token = path[len("/i/"):]
                if token != app.token:
                    return self._json({"error": "not found"}, 404)
                app.store.event("response", "page-view", "instructor",
                                self._client())
                return self._ok(app.instructor(token))
            app.store.event("response", "page-view", path, self._client())
            if path == "/":
                return self._ok(app.home())
            if path == "/console":
                return self._ok(app.console())
            if path == "/rules":
                return self._ok(app.rules_page())
            if path == "/blocks":
                return self._ok(app.blocks_page())
            if path == "/audit":
                return self._ok(app.audit_page())
            if path == "/exercises":
                return self._ok(app.exercises_page())
            if path == "/quiz":
                return self._ok(app.quiz_page())
            if path == "/sandbox":
                return self._ok(app.sandbox_page())
            if path == "/api/state":
                if not self._tok_ok(u):
                    return self._json({"error": "not found"}, 404)
                return self._json({"ok": True, "mode": app.lab.mode,
                                   "tick": app.last_tick,
                                   "metrics": app.lab.metrics(),
                                   "firewall": app.lab.firewall,
                                   "pending": [p["pending_id"] for p in
                                               app.lab.pending
                                               if not p.get("closed")],
                                   "funnel": app.store.funnel("response")})
            return self._json({"error": "not found"}, 404)

        def _form(self):
            n = int(self.headers.get("Content-Length") or 0)
            if n > self._MAX_POST:
                return None
            if n == 0:
                return {}
            raw = self.rfile.read(n).decode("utf-8", "ignore")
            return {k: v[0] for k, v in parse_qs(raw).items()}

        def do_POST(self):
            u = urlparse(self.path)
            path = u.path
            form = self._form()
            if form is None:
                return self._json({"error": "bad request"}, 400)

            if path == "/quiz":
                return self._ok(app.quiz_submit(
                    {k: form.get(k, "") for k in RESP_QUIZ},
                    self._client()))
            if path == "/sandbox":
                return self._ok(app.sandbox_submit(form, self._client()))
            if path == "/rollback":
                mac = (form.get("mac") or "").strip().upper()
                ok = app.lab.rollback(mac)
                app.store.event("response", "rollback",
                                f"{mac} -> {ok}", self._client())
                return self._json({"ok": ok})
            # instructor-only surfaces
            authed = self._tok_ok(u)
            def _need(): return self._json({"error": "not found"}, 404)
            if path == "/api/reset":
                if not authed: return _need()
                n_r = app.store.reset("response")
                app.reset_lab()
                app.store.event("response", "reset", f"{n_r} rows",
                                self._client())
                return self._json({"ok": True, "removed": n_r})
            if path == "/api/regenerate":
                if not authed: return _need()
                seed = app.regenerate()
                app.store.event("response", "regenerate", f"seed={seed}",
                                self._client())
                return self._json({"ok": True, "seed": seed})
            if path == "/api/advance":
                if not authed: return _need()
                upto = app.run_to(form.get("upto", app.lab.n_ticks - 1))
                app.store.event("response", "advance", f"tick={upto}",
                                self._client())
                return self._json({"ok": True, "tick": upto,
                                   "metrics": app.lab.metrics()})
            if path == "/api/mode":
                if not authed: return _need()
                mode = form.get("mode", "dry-run")
                if mode in MODES:
                    app.lab.mode = mode
                    app.store.event("response", "mode", mode,
                                    self._client())
                return self._json({"ok": True, "mode": app.lab.mode})
            if path == "/api/toggle-rule":
                if not authed: return _need()
                rid = form.get("rid", "")
                if rid in app.lab.enabled_rules:
                    app.lab.enabled_rules.discard(rid)
                elif any(r["rid"] == rid for r in app.lab.rules):
                    app.lab.enabled_rules.add(rid)
                app.store.event("response", "toggle-rule", rid,
                                self._client())
                return self._json({"ok": True, "enabled":
                                   sorted(app.lab.enabled_rules)})
            if path == "/api/allowlist":
                if not authed: return _need()
                macs = {m.strip().upper() for m in
                        form.get("value", "").replace(";", ",").split(",")
                        if m.strip()}
                app.lab.allowlist = macs
                app.store.event("response", "allowlist", ",".join(macs),
                                self._client())
                return self._json({"ok": True, "allowlist": sorted(macs)})
            if path == "/api/approve":
                if not authed: return _need()
                ok = app.lab.approve(int(form.get("id", -1)))
                app.store.event("response", "approve", form.get("id", ""),
                                self._client())
                return self._json({"ok": ok})
            if path == "/api/deny":
                if not authed: return _need()
                ok = app.lab.deny(int(form.get("id", -1)))
                app.store.event("response", "deny", form.get("id", ""),
                                self._client())
                return self._json({"ok": ok})
            return self._json({"error": "not found"}, 404)

    return ThreadingHTTPServer((bind, port), H)


def sandbox_whatif(rules_enabled=None, allowlist=None, seed=11,
                   n_ticks=96):
    """A throwaway run for the student sandbox: the mode is hard-pinned to
    dry-run, the lab state is fully separate. Returns (metrics, firewall-
    WOULD-BE, sandbox rows cleanup)."""
    lab = ResponseLab(seed=seed, n_ticks=n_ticks)
    lab.mode = "dry-run"
    lab.allowlist = set(allowlist) if allowlist is not None else \
        set(lab.allowlist)
    if rules_enabled is not None:
        lab.enabled_rules = set(rules_enabled)
    lab.run()
    st_firewall = {}
    for a in lab.audit:
        if a["phase"] == "result" and a.get("note") == "would-block":
            st_firewall[a["target"]] = dict(action="block",
                                            rule=a.get("rule", "?"))
    return dict(metrics=lab.metrics(),
                would_block=st_firewall,
                note=("sandboxed dry-run — no state shared with the "
                      "instructor-run lab"))
