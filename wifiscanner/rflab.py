"""
Feature 15 — RF Interference & Wi-Fi Resilience Laboratory.

This is a **simulated** RF environment.  No radio hardware, no
transmission, certainly no jamming: a deterministic generator produces
802.11 metric time-series (channel utilisation, SNR, packet loss,
latency, throughput) for a small lab estate of access points and
channels, and an *interference scenario* knob the instructor can start,
stop, reset, and intensify.  Numbers are what a monitor would see — the
physics is modelled, the wire is not.

What the lab teaches (by doing):

  * baseline vs degraded operation, side-by-side — util, SNR, loss,
    latency, throughput all move under interference, and each metric
    moves at its own force;
  * how to *identify* the affected channel from the metrics before any
    packet capture (utilisation cliff + SNR floor rise);
  * how an IDS heuristics pass flags anomalous interference (bursty,
    wideband, hopping) and which AP is under attack per event;
  * channel-selection / resilience exercises: pick a new home channel
    for a struggling AP and quantify the recovery;
  * incident investigation: deduce the interference *shape* (cordless
    phone, microwave, Bluetooth hopper, fad?) from its signature so
    that mitigation is picked correctly;
  * everything is instructor-started, instructor-stopped,
    instructor-reset, and intensity-capped — plus alerts on any attempt
    to raise the lab cap.
"""

import hashlib
import html
import json
import math
import os
import random
import threading
import time
from urllib.parse import urlparse, parse_qs

from .devlab import DevLabStore, new_token, _page  # noqa: E402

DATASET_VERSION = 1

# The lab estate: 3 APs on three 2.4 GHz channels (1, 6, 11), the
# classic non-overlapping layout.
APS = (
    {"ap_id": "LAB-AP-1", "channel": 1, "bssid": "02:1a:d4:00:00:01"},
    {"ap_id": "LAB-AP-2", "channel": 6, "bssid": "02:1a:d4:00:00:06"},
    {"ap_id": "LAB-AP-3", "channel": 11, "bssid": "02:1a:d4:00:00:0b"},
)

# Interference categories the lab can simulate. Each has a signature
# students learn to recognise: duty (share of time on), band (spread
# across channels), and the metric it perturbs most.
INTERFERERS = {
    "microwave": {
        "label": "kitchen microwave oven",
        "duty": 0.55, "band": "wideband",
        "channels": (7, 8, 9, 10, 11, 12, 13),
        "hits": ("snr", "loss"), "kbps_penalty": 0.62},
    "bluetooth": {
        "label": "bluetooth hopper",
        "duty": 0.18, "band": "hopping",
        "channels": tuple(range(1, 12)),
        "hits": ("loss",), "kbps_penalty": 0.35},
    "cordless": {
        "label": "2.4 GHz cordless phone",
        "duty": 0.85, "band": "narrow",
        "channels": (1, 2, 3),
        "hits": ("latency", "loss"), "kbps_penalty": 0.50},
    "chaos": {
        "label": "rogue wideband emitter (lab-only)",
        "duty": 0.95, "band": "wide",
        "channels": tuple(range(1, 12)),
        "hits": ("snr", "loss", "latency"), "kbps_penalty": 0.80},
}


# --------------------------------------------------------------------------
# Metric engine — deterministic per (seed, tick, interferer, intensity)
# --------------------------------------------------------------------------

TICKS = 60            # samples per run
MAX_INTENSITY = 100   # instructor cannot go past this — hard cap


class InterferenceSession:
    """One controlled run of the simulator."""

    def __init__(self, seed=15):
        self.seed = seed
        self.running = False
        self.interferer = None
        self.intensity = 40          # 0..100, cap enforced at setter
        self.tick = 0
        self.log = []                # instructor actions (audit trail)
        self.channel_override = {}   # resilience exercise: ap_id -> chan

    # instructor controls (all audited) ----------------------------------
    def start(self, interferer="microwave", intensity=40, by="(anon)"):
        if interferer not in INTERFERERS:
            raise ValueError(f"unknown interferer {interferer!r} — the lab "
                             "only models microwave/bluetooth/cordless/chaos")
        self.interferer = interferer
        capped = int(intensity) != min(MAX_INTENSITY, max(0, int(intensity)))
        self.intensity = min(MAX_INTENSITY, max(0, int(intensity)))
        self.running = True
        self.log.append({"ts": time.time(), "action": "start",
                         "detail": f"{interferer} @{self.intensity}%"
                                   f"{' (capped)' if capped else ''}",
                         "by": by})

    def stop(self, by="(anon)"):
        self.running = False
        self.log.append({"ts": time.time(), "action": "stop",
                         "detail": self.interferer or "-", "by": by})

    def reset(self, by="(anon)"):
        self.running = False
        self.interferer = None
        self.intensity = 40
        self.tick = 0
        self.channel_override.clear()
        self.log.append({"ts": time.time(), "action": "reset",
                         "detail": "-", "by": by})

    def set_intensity(self, value, by="(anon)"):
        v = min(MAX_INTENSITY, max(0, int(value)))
        capped = v != int(value)
        self.intensity = v
        self.log.append({"ts": time.time(), "action": "intensity",
                         "detail": f"{v}%{' (capped)' if capped else ''}",
                         "by": by})
        return capped

    def set_channel(self, ap_id, channel, by="(anon)"):
        channel = int(channel)
        if channel not in (1, 6, 11):
            raise ValueError("lab channels are 1, 6, 11 (non-overlapping)")
        if ap_id not in {a["ap_id"] for a in APS}:
            raise ValueError(f"unknown AP {ap_id!r} (lab estate only)")
        old = next(a for a in APS if a["ap_id"] == ap_id)["channel"]
        self.channel_override[ap_id] = channel
        self.log.append({"ts": time.time(), "action": "channel",
                         "detail": f"{ap_id} {old}→{channel}", "by": by})
        return old, channel

    # metrics ------------------------------------------------------------
    def _rng(self, ap, tick, salt=""):
        h = hashlib.sha256(
            f"{self.seed}|{ap['ap_id']}|{tick}|{salt}".encode()).digest()
        return (int.from_bytes(h[:4], "big") % 10000) / 10000.0

    def _hit(self, interferer, channel):
        """How much of this channel is inside the emitter's footprint."""
        info = INTERFERERS[interferer]
        if channel in info["channels"]:
            return 1.0                     # directly inside the footprint
        # Overlap weighting: 2.4GHz channels bleed.  An emitter centred
        # near ch11 hits ch6 a little and ch1 not at all — the
        # non-overlap fact the resilience exercise is built around.
        spill = {1: {6: 0.30, 11: 0.0},
                 6: {1: 0.30, 11: 0.30},
                 11: {6: 0.15, 1: 0.0}}
        best = 0.0
        for anchor, spread in spill.items():
            if anchor in info["channels"] and channel in spread.get(
                    anchor, {}):
                best = max(best, spread[anchor][channel])
            # reverse: emitter on a neighbour bleeds into this channel
            if anchor not in info["channels"]:
                for anchor2, spread2 in spill.items():
                    if anchor2 in info["channels"] and \
                       channel == anchor:
                        best = max(best,
                                   spread2.get(channel, 0.0))
        return best

    def metrics(self, ap, tick):
        """The five headline numbers for one AP at one tick."""
        base_r = self._rng(ap, tick, "base")
        ch = self.channel_override.get(ap["ap_id"], ap["channel"])
        util = 0.18 + 0.05 * math.sin(tick / 7.0) + 0.06 * base_r
        snr = 32.0 - 4.0 * base_r
        loss = 0.004 + 0.004 * base_r
        lat = 6.0 + 3.0 * base_r
        thru = 42000.0 * (1.0 - util * 0.5)          # kbps of goodput
        deg = {"util": 0.0, "snr": 0.0, "loss": 0.0,
               "lat": 0.0, "thru": 0.0}
        if self.running and self.interferer:
            hit = self._hit(self.interferer, ch)
            k = (self.intensity / 100.0) * hit
            info = INTERFERERS[self.interferer]
            duty = info["duty"]
            on = self._rng(ap, tick, "duty") < duty
            if on and k > 0:
                deg["util"] = 0.45 * k
                if "snr" in info["hits"]:
                    deg["snr"] = 18.0 * k
                if "loss" in info["hits"]:
                    deg["loss"] = 0.30 * k
                if "latency" in info["hits"]:
                    deg["lat"] = 60.0 * k
                deg["thru"] = thru * info["kbps_penalty"] * k
        return {"tick": tick, "ap_id": ap["ap_id"],
                "channel": ch,
                "util": round(min(0.98, util + deg["util"]), 3),
                "snr_db": round(max(2.0, snr - deg["snr"]), 1),
                "loss": round(min(0.95, loss + deg["loss"]), 4),
                "latency_ms": round(lat + deg["lat"], 1),
                "throughput_kbps": round(max(400.0, thru - deg["thru"]), 0),
                "degraded": bool(self.running and self.interferer and
                                 sum(deg.values()) > 0)}

    def series(self, ticks=TICKS):
        """Full time-series for every AP at every tick."""
        out = {a["ap_id"]: [] for a in APS}
        for a in APS:
            for t in range(ticks):
                out[a["ap_id"]].append(self.metrics(a, t))
        return out


# --------------------------------------------------------------------------
# Analysis: detection, identification, IDS alerts, incident investigation
# --------------------------------------------------------------------------

def compare_runs(session, interferer, intensity):
    """Normal vs degraded, per AP.  Used by the before/after exercise."""
    session.stop()
    normal = {ap: _summarise(rows) for ap, rows in session.series().items()}
    session.start(interferer, intensity, by="(compare)")
    degr = {ap: _summarise(rows) for ap, rows in session.series().items()}
    session.stop()  # compare() leaves the device idempotent-quiet
    rows = []
    for ap in normal:
        n, d = normal[ap], degr[ap]
        rows.append({"ap_id": ap, "channel": next(a["channel"] for a in APS
                                                  if a["ap_id"] == ap),
                     "before": n, "after": d,
                     "delta_loss": round(d["loss"] - n["loss"], 4),
                     "delta_snr": round(d["snr_db"] - n["snr_db"], 1),
                     "delta_pct_thru": round(
                         100.0 * (d["throughput_kbps"] - n["throughput_kbps"])
                         / max(1.0, n["throughput_kbps"]), 1)})
    return rows


def _summarise(rows):
    n = max(1, len(rows))
    keys = ("util", "snr_db", "loss", "latency_ms", "throughput_kbps")
    return {k: round(sum(r[k] for r in rows) / n, 3) for k in keys}


def detect_interference(session):
    """Heuristic IDS-style detector over the current series.

    Returns dict: affected channels/APs, events with signature labels,
    and the guessed interferer type.  Everything is derived from the
    metric stream a *passive monitor* would see — this is the lesson.
    """
    session.series()  # force tick computation (no side effects below)
    rows = session.series()
    affected_chs = {}
    for ap_id, samples in rows.items():
        ch = samples[0]["channel"]
        noisy = [s for s in samples if s["degraded"]]
        if not noisy:
            continue
        snr_drop = max(0.0, 28.0 - min(s["snr_db"] for s in noisy))
        loss_peak = max(s["loss"] for s in noisy)
        util_peak = max(s["util"] for s in noisy)
        affected_chs[ch] = {"ap_id": ap_id, "hits": len(noisy),
                            "snr_drop": round(snr_drop, 1),
                            "loss_peak": round(loss_peak, 3),
                            "util_peak": round(util_peak, 2)}
    # classify
    guess = "none"
    if affected_chs:
        n_ch = len(affected_chs)
        n_aps = len({v["ap_id"] for v in affected_chs.values()})
        best_hits = max(v["hits"] for v in affected_chs.values())
        duty = best_hits / max(1.0, float(TICKS))
        if n_aps >= 3 and duty > 0.7:
            guess = "chaos"        # whole estate, nearly always on
        elif n_aps >= 3:
            guess = "bluetooth"    # whole estate, bursty pulses
        elif duty > 0.7:
            guess = "cordless"     # narrow footprint, almost always on
        else:
            guess = "microwave"    # narrow-ish, cyclic duty
    alerts = []
    if session.interferer:
        for ch, info in affected_chs.items():
            alerts.append({
                "kind": "suspected-interference",
                "detail": (f"channel {ch} ({info['ap_id']}): "
                           f"util {info['util_peak']:.0%}/"
                           f"SNR−{info['snr_drop']} dB/"
                           f"loss {info['loss_peak']:.0%} — "
                           f"looks like {INTERFERERS[guess]['label']}"),
                "severity": ("critical" if info["loss_peak"] > 0.15 else
                             "warning"),
                "channel": ch})
    return {"affected": affected_chs, "guess": guess, "alerts": alerts}


def incident_report(session):
    """Deduce the interferer's identity from its signature only."""
    det = detect_interference(session)
    guess = det["guess"]
    info = INTERFERERS.get(guess, {
        "label": "(no interference — this is your baseline)",
        "duty": 0.0, "band": "n/a", "channels": [], "hits": ()})
    return {"guess": guess, "label": info["label"],
            "signature": {"duty": info["duty"], "band": info["band"],
                          "channels": list(info["channels"]),
                          "penalises": info["hits"]},
            "affected": det["affected"],
            "lesson": ("read the signature: duty ≈ time-on, band ≈ spread "
                       "across channels, and *which metric* moves first "
                       "(SNR = noise floor, loss = collisions, latency = "
                       "contention).")}


def resilience_score(session, ap_id, new_channel):
    """Before/after channel change for one AP. The exercise's payoff."""
    det = detect_interference(session)
    before = None
    for ch, info in det["affected"].items():
        if info["ap_id"] == ap_id:
            before = info["loss_peak"]
    old = session.channel_override.get(
        ap_id, next(a["channel"] for a in APS if a["ap_id"] == ap_id))
    session.channel_override[ap_id] = int(new_channel)
    det2 = detect_interference(session)
    # check whether this AP's new channel is still under the footprint
    hit = session._hit(session.interferer, int(new_channel)) \
        if session.interferer else 0.0
    recovered = (before is not None and hit == 0.0)
    gain = None if before is None else round(before, 3)
    return {"ap_id": ap_id, "old_channel": old,
            "new_channel": int(new_channel),
            "still_under_interference": hit > 0.0,
            "recovered": recovered,
            "loss_peak_before": gain,
            "score": (100 if recovered and before is not None
                      else 40 if not recovered else 10),
            "note": (f"moved from under the emitter footprint "
                     f"(ch {old}) to a quiet channel ({new_channel})"
                     if recovered else
                     "new channel still inside the emitter footprint"
                     if hit > 0.0 else
                     "nothing to fix — this AP wasn't affected")}


def ap_now_channel(channel_override, ap_id):
    """Channel AP currently sits at (override wins); helper for callers."""
    base = next(a["channel"] for a in APS if a["ap_id"] == ap_id)
    return channel_override.get(ap_id, base)


# --------------------------------------------------------------------------
# Quiz + scoring
# --------------------------------------------------------------------------

RF_QUIZ = {"q_channel_6": 15, "q_snr_drop": 20, "q_hopper": 15,
           "q_mitigation": 20, "q_before_after": 15, "q_jam_rules": 15}

_RF_ANS = {
    "q_channel_6": ("1-6-11-nonoverlap",
                    ("Channels 1/6/11 don't overlap in 2.4 GHz, so an "
                     "emitter on ch 11 hits ch 11 hard, ch 6 lightly, and "
                     "ch 1 not at all — the resilience lesson in one "
                     "sentence.")),
    "q_snr_drop": ("noise-floor",
                   ("When the SNR floor rises (less margin above the "
                    "receiver's sensitivity), you are looking at energy "
                    "*added to the channel* — classic interference, and it "
                    "precedes packet loss.")),
    "q_hopper": ("hopping-band",
                 ("A bluetooth hopper spreads thin pulses across *all* "
                  "channels at low duty: few long outages, many tiny ones, "
                  "you see most channels marked affected at low intensity.")),
    "q_mitigation": ("rechannel-and-5g",
                     ("Move the AP to a non-overlapping quiet channel or "
                      "migrate clients to 5 GHz — the first is the lab "
                      "exercise, the second is the long-term fix.")),
    "q_before_after": ("measure-twice",
                       ("Never claim resilience you didn't measure; the "
                        "exercise demands a before/after run so the "
                        "numbers prove the fix.")),
    "q_jam_rules": ("lab-only",
                    ("Interference in this lab is a *simulation*: the "
                     "generator emits numbers, the instructor caps the "
                     "intensity, and real RF jamming is not part of the "
                     "curriculum (the law agrees).")),
}


def score_rflab(answers):
    pts, notes = 0.0, []
    for qid, w in sorted(RF_QUIZ.items()):
        want, why = _RF_ANS[qid]
        got = (answers.get(qid) or "").strip().lower()
        if got == want:
            pts += w
            notes.append(f"+{w} {qid}: correct — {why}")
        elif got in _rf_aliases(qid):
            pts += w // 2
            notes.append(f"+{w//2} {qid}: partial — {why}")
        else:
            notes.append(f"+0 {qid}: wanted `{want}` — {why}")
    total = round(pts, 1)
    notes.append("verdict: " + (
        "excellent — you read RF symptoms like radar"
        if total >= 85 else "good — check the partials"
        if total >= 60 else "retry — the dashboard has all the clues"))
    return total, notes


def _rf_aliases(qid):
    return {
        "q_channel_6": {"1-6-11", "nonoverlap", "non-overlapping"},
        "q_snr_drop": {"snr", "noise", "floor"},
        "q_hopper": {"hopper", "bluetooth"},
        "q_mitigation": {"rechannel", "5g", "move"},
        "q_before_after": {"measure", "twice", "baseline"},
        "q_jam_rules": {"sim", "simulation", "cap"},
    }.get(qid, set())


RF_EXERCISES = [
    {"id": "x1", "title": "Baseline the lab", "weight": 10,
     "task": "start a microwave@50% and note how many channels the "
             "detector flags."},
    {"id": "x2", "title": "Compare before/after", "weight": 15,
     "task": "run compare() for bluetooth@80% — which AP loses the most "
             "goodput?"},
    {"id": "x3", "title": "Identify the interferer", "weight": 20,
     "task": "from the signature alone (duty + band + first-hit metric) "
             "pick microwave vs cordless vs chaos."},
    {"id": "x4", "title": "Rechannel to survive", "weight": 25,
     "task": "move the worst-hit AP to a quiet channel; show the "
             "detector clearing that AP."},
    {"id": "x5", "title": "Write the incident report", "weight": 30,
     "task": "write the incident_report() for a chaos@90% run and hand "
             "it to your TA."},
]


# --------------------------------------------------------------------------
# Web app — dashboards + instructor console
# --------------------------------------------------------------------------

class RFLabApp:
    def __init__(self, session, store, token):
        self.session = session
        self.store = store
        self.token = token
        self.lock = threading.RLock()
        self.alerts = []        # IDS-style event log
        self.completed = set()

    # ----- pages ---------------------------------------------
    def _nav(self):
        return ("<div class='nav'>"
                "<a href='/'>dashboard</a><a href='/compare'>compare</a>"
                "<a href='/detect'>detect</a><a href='/incident'>"
                "incident</a><a href='/exercises'>exercises</a>"
                "<a href='/quiz'>quiz</a></div>")

    def home(self):
        series = self.session.series(24)   # 24-tick spark panels
        cards = []
        for ap_id, rows in series.items():
            ch = rows[0]["channel"]
            degrade = sum(1 for r in rows if r["degraded"])
            chip = "ok" if degrade == 0 else ("warn" if degrade < 12
                                              else "bad")
            latest = rows[-1]
            spark1 = self._spark([r["snr_db"] for r in rows], 35, "#2ecc71")
            spark2 = self._spark([r["loss"] for r in rows], 0.5, "#c0392b")
            cards.append(f"""
  <div class='card'><span class='chip {chip}'>{degrade} degraded</span>
   <b>{html.escape(ap_id)}</b> · ch {ch}<div class='dim'>SNR spark</div>
   {spark1}<div class='dim'>loss spark</div>{spark2}
   <table><tr><td>util</td><td>{latest['util']:.0%}</td></tr>
    <tr><td>SNR</td><td>{latest['snr_db']} dB</td></tr>
    <tr><td>loss</td><td>{latest['loss']:.1%}</td></tr>
    <tr><td>latency</td><td>{latest['latency_ms']} ms</td></tr>
    <tr><td>goodput</td><td>{latest['throughput_kbps']:.0f} kbps</td></tr>
   </table></div>""")
        state = (f"interferer <b>{html.escape(self.session.interferer)}"
                 f"</b> @{self.session.intensity}%"
                 if self.session.running
                 else "simulator idle (no interference)")
        s_count = sum(len(rows) for rows in series.values())
        return _page("rf lab — dashboard", self._nav() + f"""
 <div class='card'><h1>📶 RF Interference &amp; Resilience Laboratory</h1>
  <p class='dim'>{state} · lab estate only (no RF is generated —
  the metrics come from a deterministic model). Alerts:
  <span class='chip bad'>{len(self.alerts)}</span></p>
  <div style='display:flex;gap:14px;flex-wrap:wrap'>{''.join(cards)}</div>
 </div>""")

    def compare_page(self):
        if not self.session.interferer:
            self.session.start("microwave", 60, by="(auto for compare)")
        rows = compare_runs(self.session, self.session.interferer,
                            self.session.intensity)
        cells = "".join(
            f"<tr><td>{r['ap_id']}</td><td>{r['channel']}</td>"
            f"<td>{r['before']['loss']:.3f}</td><td>{r['after']['loss']:.3f}"
            f"</td><td>{r['delta_loss']:.3f}</td>"
            f"<td>{r['before']['snr_db']:.1f}</td>"
            f"<td>{r['after']['snr_db']:.1f}</td>"
            f"<td class='{'bad' if r['delta_pct_thru'] < -15 else 'dim'}'>"
            f"{r['delta_pct_thru']:.1f}%</td></tr>" for r in rows)
        return _page("rf lab — compare", self._nav() + f"""
 <div class='card'><h1>⚖️ normal vs degraded</h1>
  <table><tr><th>AP</th><th>ch</th><th>loss→before</th>
   <th>loss→after</th><th>Δloss</th><th>SNR b.</th><th>SNR a.</th>
   <th>Δgoodput</th></tr>{cells}</table>
  <p class='tag warn'>the shape of the deltas — which AP, which metric —
  is the investigation clue.</p></div>""")

    def detect_page(self):
        det = detect_interference(self.session)
        for a in det["alerts"]:
            if a not in self.alerts:
                self.alerts.append(a)
        rows = "".join(f"<li><span class='chip {a['severity']}'>"
                       f"{a['kind']}</span> {html.escape(a['detail'])}</li>"
                       for a in det["alerts"]) or \
            "<li class='dim'>no interference suspected</li>"
        tbl = "".join(
            f"<tr><td>{ch}</td><td>{v['ap_id']}</td>"
            f"<td>{v['hits']}</td><td>{v['loss_peak']:.0%}</td>"
            f"<td>{v['snr_drop']} dB</td><td>{v['util_peak']:.0%}</td>"
            "</tr>"
            for ch, v in sorted(det["affected"].items()))
        return _page("rf lab — detect", self._nav() + f"""
 <div class='card'><h1>🔍 suspected interference</h1>
  <table><tr><th>channel</th><th>AP</th><th>ticks hit</th>
   <th>loss peak</th><th>SNR drop</th><th>util peak</th></tr>{tbl or
   '<tr><td colspan=6 class=dim>clean</td></tr>'}</table>
  <p>guess: <b>{html.escape(det['guess'])}</b></p><ul>{rows}</ul></div>""")

    def incident_page(self):
        rpt = incident_report(self.session)
        sig = rpt["signature"]
        ch = ", ".join(str(c) for c in sig["channels"])
        affected = "".join(f"<li>ch {c} ({v['ap_id']}) — "
                           f"{v['hits']} ticks</li>"
                           for c, v in sorted(rpt["affected"].items())) \
            or "<li class='dim'>none</li>"
        return _page("rf lab — incident", self._nav() + f"""
 <div class='card'><h1>📋 incident report</h1>
  <table><tr><td>suspect</td><td><b>{html.escape(rpt['label'])}</b></td>
   </tr><tr><td>duty cycle</td><td>{sig['duty']:.0%}</td></tr>
   <tr><td>band</td><td>{html.escape(sig['band'])}</td></tr>
   <tr><td>channels in footprint</td><td>{ch}</td></tr>
   <tr><td>penalises</td><td>{html.escape(', '.join(sig['penalises']))}
   </td></tr></table>
  <ul>{affected}</ul>
  <p class='dim'>{html.escape(rpt['lesson'])}</p></div>""")

    def exercises_page(self):
        items = "".join(
            f"<div class='card'><span class='chip "
            f"{'ok' if x['id'] in self.completed else 'warn'}'>"
            f"{'✓' if x['id'] in self.completed else 'todo'}</span> "
            f"<b>{html.escape(x['title'])}</b> — {x['task']} "
            f"<span class='dim'>({x['weight']} pts)</span></div>"
            for x in RF_EXERCISES)
        return _page("rf lab — exercises",
                     self._nav() + "<div class='card'><h1>📝 "
                     "exercises</h1>Baseline, compare, identify, "
                     "rechannel, report.</div>" + items)

    def quiz_page(self):
        qs = [
            ("q_channel_6", "Why does ch-11 interference barely touch "
                            "ch-1?",
             ("1-6-11-nonoverlap", "5 GHz immune", "RSSI too high",
              "APs too far")),
            ("q_snr_drop", "SNR floor rising means…",
             ("noise-floor", "router bug", "too many clients",
              "shorter range")),
            ("q_hopper", "A bluetooth hopper looks like…",
             ("hopping-band", "one channel nailed", "all channels dead",
              "zero signal")),
            ("q_mitigation", "Best resilience play in the lab?",
             ("rechannel-and-5g", "reboot AP", "new antenna", "yell")),
            ("q_before_after", "How do you prove resilience?",
             ("measure-twice", "vibes", "repeat offenders", "trust the AP")),
            ("q_jam_rules", "This lab's interference is…",
             ("lab-only", "real RF", "a dunno", "retroactive")),
        ]
        form = [f"<div class='card'><b>{q}</b>" +
                "".join(f"<label style='display:block'><input type='radio' "
                        f"name='{qid}' value='{c}'> {html.escape(c)}</label>"
                        for c in cs)
                + "</div>" for qid, q, cs in qs]
        return _page("rf lab — quiz",
                     self._nav() + "<form method='post' action='/quiz'>"
                     + "".join(form)
                     + "<button class='go'>score</button></form>")

    def quiz_submit(self, form, client):
        answers = {qid: (form.get(qid, [""])[0] if form.get(qid) else "")
                   for qid in RF_QUIZ}
        score, notes = score_rflab(answers)
        self.store.attempt("rf", "quiz", json.dumps(answers), score,
                           f"{score:.1f}", client)
        li = "".join(f"<li>{html.escape(n)}</li>" for n in notes)
        return _page("rf lab — quiz result", self._nav()
                     + f"<div class='card'><h1>✅ {score:.1f} / 100</h1>"
                       f"<ul>{li}</ul></div>")

    def instructor_page(self, token):
        runs = "".join(f"<li>{time.strftime('%H:%M:%S', time.localtime(l['ts']))}"
                       f" — {html.escape(l['action'])} "
                       f"<span class='dim'>{html.escape(l['detail'])}</span>"
                       f" <i>{html.escape(l['by'])}</i></li>"
                       for l in self.session.log[-12:]) \
            or "<li class='dim'>nothing yet</li>"
        state = (f"<b>RUNNING</b> {self.session.interferer} @"
                 f" {self.session.intensity}%"
                 if self.session.running else "idle")
        cur = self.session.interferer or "microwave"
        opts = "".join(
            f"<option {'selected' if k == cur else ''}"
            f" value='{k}'>{k}</option>" for k in INTERFERERS)
        return _page("rf lab — instructor", self._nav() + f"""
 <div class='card'><h1>🧑‍🏫 instructor console</h1>
  <p>state: {state} · alerts so far: {len(self.alerts)}</p>
  <form method='post' action='/i/{html.escape(token)}/start'>
   <select name='interferer'>{opts}</select>
   <input name='intensity' value='{self.session.intensity}'
          size='3'> % <button class='go'>start</button></form>
  <form method='post' action='/i/{html.escape(token)}/stop'
   style='display:inline'><button class='go'>stop</button></form>
  <form method='post' action='/i/{html.escape(token)}/reset'
   style='display:inline'><button class='go stop'>reset lab</button></form>
  <h2>intensity + channels</h2>
  <form method='post' action='/i/{html.escape(token)}/intensity'>
   <input name='value' value='80' size='3'> %
   <button class='go'>set</button></form>
  <form method='post' action='/i/{html.escape(token)}/channel'>
   <select name='ap'>{''.join("<option>" + a['ap_id'] + "</option>"
                               for a in APS)}</select>
   <select name='channel'><option>1</option><option>6</option>
    <option>11</option></select>
   <button class='go'>move</button></form>
  <h2>recent instructor actions</h2><ul>{runs}</ul>
  <p class='dim'>Intensity is capped at {MAX_INTENSITY}% and every action
  lands on the audit log. This lab cannot touch real RF.</p></div>""")

    # ----- instructor actions --------------------------------
    def action(self, tail, form, client):
        s = self.session
        if tail == "start":
            s.start((form.get("interferer") or ["microwave"])[0],
                    int((form.get("intensity") or ["40"])[0]),
                    by=client)
            self.completed.add("x1")
        elif tail == "stop":
            s.stop(by=client)
        elif tail == "reset":
            s.reset(by=client)
            self.alerts.clear()
        elif tail == "intensity":
            capped = s.set_intensity(int((form.get("value") or ["0"])[0]),
                                     by=client)
            if capped:
                self.store.event("rf", "cap",
                                 "intensity cap touched", client)
        elif tail == "channel":
            old, new = s.set_channel((form.get("ap") or ["LAB-AP-1"])[0],
                                     (form.get("channel") or ["1"])[0],
                                     by=client)
            self.completed.add("x4")
            self.store.event("rf", "channel",
                             f"{(form.get('ap') or ['?'])[0]} {old}→{new}",
                             client)
        return True

    # ----- sparkline -----------------------------------------
    def _spark(self, values, scale, color):
        w, h = 180, 36
        n = len(values)
        xmax = max(1.0, max(values))
        pts = " ".join(f"{i * w / max(1, n - 1):.0f},"
                       f"{h - h * v / xmax:.0f}"
                       for i, v in enumerate(values))
        return (f"<svg width='{w}' height='{h}' style='background:#131;"
                "border-radius:6px'>"
                f"<polyline fill='none' stroke='{color}' "
                f"stroke-width='2' points='{pts}'/></svg>")


# --------------------------------------------------------------------------
# HTTP server
# --------------------------------------------------------------------------

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer  # noqa: E402
from hmac import compare_digest as _cd  # noqa: E402


class _RFHandler(BaseHTTPRequestHandler):
    _MAX_POST = 65536

    def log_message(self, fmt, *a):
        pass

    def _client(self):
        xff = self.headers.get("X-Forwarded-For", "")
        return (xff.split(",")[0].strip() or self.client_address[0])[:45]

    def _tok_ok(self, u):
        tok = (parse_qs(u.query).get("token") or [""])[0]
        app = self.server.app
        return bool(tok) and _cd(tok.encode(), (app.token or "").encode())

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
        app.store.event("rf", "view", path, self._client())
        if path in ("/", "/compare", "/detect", "/incident",
                    "/exercises", "/quiz"):
            page = {"/": app.home, "/compare": app.compare_page,
                    "/detect": app.detect_page,
                    "/incident": app.incident_page,
                    "/exercises": app.exercises_page,
                    "/quiz": app.quiz_page}[path]()
            return self._ok(page)
        if path == "/api/state":
            if not self._tok_ok(u):
                return self._json({"error": "not found"}, 404)
            s = app.session
            return self._json({"ok": True, "running": s.running,
                               "interferer": s.interferer,
                               "intensity": s.intensity,
                               "alerts": app.alerts[-50:],
                               "log": s.log[-50:],
                               "funnel": app.store.funnel("rf")})
        if path == "/api/metrics":
            return self._json(app.session.series(10))
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
        if path == "/api/compare":
            app.completed.add("x2")
            return self._json({"rows": compare_runs(
                app.session,
                app.session.interferer or "microwave",
                app.session.intensity)})
        if path == "/api/detect":
            det = detect_interference(app.session)
            app.completed.add("x3")
            for a in det["alerts"]:
                if a not in app.alerts:
                    app.alerts.append(a)
            return self._json(det)
        if path == "/api/rechannel":
            res = resilience_score(
                app.session,
                (form.get("ap") or ["LAB-AP-1"])[0],
                (form.get("channel") or ["1"])[0])
            if res["recovered"]:
                app.completed.add("x4")
            return self._json(res)
        if path == "/api/incident":
            app.completed.add("x5")
            return self._json(incident_report(app.session))
        if path.startswith("/i/" + app.token + "/"):
            tail = path.split("/")[3]
            if path.startswith(f"/i/{app.token}/start"):
                app.completed.add("x1")
            app.action(tail, form, self._client())
            app.store.event("rf", "instructor", tail, self._client())
            return self._json({"ok": True})
        return self._json({"error": "not found"}, 404)


def make_rf_server(bind, port, app):
    class _Srv(ThreadingHTTPServer):
        daemon_threads = True
    srv = _Srv((bind, port), _RFHandler)
    srv.app = app
    return srv


# --------------------------------------------------------------------------
# CLI helpers
# --------------------------------------------------------------------------

def cmd_baseline(seed=15):
    s = InterferenceSession(seed)
    s.stop()
    print("baseline (no interference):")
    for ap, rows in s.series(30).items():
        summ = _summarise(rows)
        print(f"  {ap} ch{rows[0]['channel']}: util {summ['util']:.0%} "
              f"snr {summ['snr_db']}dB loss {summ['loss']:.3f} "
              f"lat {summ['latency_ms']}ms thru {summ['throughput_kbps']}"
              "kbps")


def cmd_inject(seed=15, interferer="microwave", intensity=60, ticks=30):
    s = InterferenceSession(seed)
    s.start(interferer, intensity, by="(cli)")
    serie = s.series(ticks)
    det = detect_interference(s)
    print(f"interference: {interferer} @ {intensity}% — detector sees "
          f"{len(det['affected'])} channels, guess={det['guess']}")
    for ch, v in sorted(det["affected"].items()):
        print(f"  ch{ch} {v['ap_id']}: hits {v['hits']} loss "
              f"{v['loss_peak']:.0%} snr−{v['snr_drop']}dB")
    s.stop()


def cmd_compare(seed=15, interferer="microwave", intensity=60):
    s = InterferenceSession(seed)
    rows = compare_runs(s, interferer, intensity)
    print(f"normal vs {interferer}@{intensity}%")
    for r in rows:
        print(f"  {r['ap_id']} ch{r['channel']}: loss "
              f"{r['before']['loss']:.3f}→{r['after']['loss']:.3f} "
              f"Δgoodput {r['delta_pct_thru']:.1f}%")
    return 0


def cmd_investigate(seed=15, interferer="microwave", intensity=60):
    s = InterferenceSession(seed)
    s.start(interferer, intensity, by="(cli)")
    rpt = incident_report(s)
    s.stop()
    print(f"incident: looks like {rpt['label']}")
    print(f"  duty {rpt['signature']['duty']:.0%} "
          f"band={rpt['signature']['band']} hits "
          f"{','.join(rpt['signature']['penalises'])}")


def cmd_resilience(seed=15, ap_id="LAB-AP-3", channel=1,
                   interferer="microwave", intensity=70):
    s = InterferenceSession(seed)
    s.start(interferer, intensity, by="(cli)")
    res = resilience_score(s, ap_id, channel)
    s.stop()
    print(f"resilience: {res['ap_id']} {res['old_channel']}→"
          f"{res['new_channel']} recovered={res['recovered']} "
          f"score={res['score']}")
    return 0 if res["recovered"] else 1


def cmd_score(answers):
    try:
        payload = json.load(open(answers, encoding="utf-8")) \
            if answers != "-" else json.load(os.sys.stdin)
    except (OSError, json.JSONDecodeError) as e:
        print(f"score: cannot parse answers: {e}")
        return 2
    score, notes = score_rflab(payload)
    print(f"rf lab score: {score:.1f} / 100")
    for n in notes:
        print(f"  {n}")
    return 0 if score >= 60 else 1


def cmd_exercises():
    print("rf lab exercises:")
    for x in RF_EXERCISES:
        print(f"  [{x['id']}] {x['title']} ({x['weight']} pts) — {x['task']}")
    return 0
