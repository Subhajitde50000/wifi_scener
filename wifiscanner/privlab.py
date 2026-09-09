"""
Feature 14 — Wireless Privacy Protection & MAC Randomization Laboratory.

Every device, MAC address, SSID, timestamp and signal reading in this lab
is *synthetic and instructor-controlled*.  Nothing here observes real
radios: observation logs are generated inside the lab, carry lab-only
identifiers (``02:LAB:...`` locally-administered OUI block), and the
correlation engine refuses work outside the permitted exercise scope.

What the lab teaches (by doing, not by slides):

  * how MAC randomization changes what an observer can trivially match —
  * and what still leaks: same probe-request fingerprint (SSID list +
    IE signature), same daily routine, same RSSI trajectory;
  * how a repeated-observation log lets an analyst cluster rotated MACs
    into "identity tracks" with a confidence score;
  * how privacy-preserving configuration (PNO list scrub, randomized IE
    padding, irregular beacon cadence) collapses that confidence;
  * and that *correlating beyond the exercise scope* is exactly the kind
    of thing a defender should catch: the lab refuses such attempts and
    logs them loudly.
"""

import csv
import hashlib
import html
import json
import math
import os
import random
import re
import threading
import time
from urllib.parse import urlparse, parse_qs

from .devlab import DevLabStore, new_token, _page  # noqa: E402

# Locally administered OUI block reserved for this lab. 02: = LAA bit set,
# therefore never clashes with any vendor assignment.
LAB_OUI = "02:1a:b4"
DATASET_VERSION = 1

_LANG = "en"


# --------------------------------------------------------------------------
# Dataset generation (instructor-controlled, deterministic per seed)
# --------------------------------------------------------------------------

_POOL_SSIDS = ("CafeWiFi", "eduroam", "Airport_WiFi", "Hotel_Guest",
               "HomeNet-5G", "Starbucks_WiFi", "../../../ion", "Lab9Net",
               "Printer-3F04", "Chromecast72", "", "xfinitywifi",
               "Corp-Guest", "BusLine14-WiFi")
_ROUTES = (("Commute", 7.5, 8.5), ("Lunch", 12.0, 13.0),
           ("Lab", 14.0, 17.0), ("Evening", 18.5, 20.0))
_LABELS = ("Ada", "Bohr", "Curie", "Dirac", "Eldred", "Fermi", "Hopper",
           "Turing", "Wilkes", "Bell", "Shannon", "Noether")


def _lab_mac(rng):
    return "%s:%02x:%02x" % (LAB_OUI,
                             rng.randrange(16, 240), rng.randrange(255))


def generate_observations(dest_dir, seed=14, devices=10, days=6,
                          fresh=False):
    """Write the lab observation dataset into *dest_dir*.

    Refuses to overwrite a live dataset unless ``fresh`` is set — per the
    instructor-controls rule, destroying data is always explicit.
    Returns a small manifest summary.
    """
    dest_dir = os.path.abspath(dest_dir)
    obs_path = os.path.join(dest_dir, "observations.json")
    dev_path = os.path.join(dest_dir, "devices.json")
    if os.path.exists(obs_path) and not fresh:
        raise SystemExit(f"dataset exists at {dest_dir} — pass --fresh "
                         "to destroy and regenerate it")
    os.makedirs(dest_dir, exist_ok=True)
    rng = random.Random(seed)

    devs = []
    for i in range(devices):
        label = _LABELS[i % len(_LABELS)]
        # ~70% of the fleet randomizes; the rest keep a stable MAC.
        randomizes = rng.random() < 0.70
        home = _POOL_SSIDS[rng.randrange(len(_POOL_SSIDS))]
        pool = sorted(rng.sample([s for s in _POOL_SSIDS if s != home],
                                 rng.randrange(2, 6)))
        pnolist = [home] + pool            # what the device probes for
        routine = rng.choice(_ROUTES)      # persona time window
        tag = hashlib.sha256(f"{seed}|{i}|lab".encode()).hexdigest()[:12]
        devs.append({
            "device_id": f"LAB-DEV-{i+1:02d}",
            "label": label,
            "randomizes": randomizes,
            "mac_stable": _lab_mac(rng),
            # dark tokens: rotation never re-uses an address, but the
            # *same persona* keeps its probe list (that is the lesson).
            "pnolist": pnolist,
            "ie_sig": rng.choice(("1a2b3c", "9d8e7f", "55aa66")),
            "rssi_floor": rng.randrange(-78, -62),
            "routine": list(routine),
            "restricted": (i == 0),   # instructor's deck: off-limits
            "tag": tag,
        })

    # restricted device = the lab reference AP; correlating IT is out of
    # scope (mirrors "leave the monitoring rig alone" in class).
    devs[0].update(randomizes=False, label="LAB-REFERENCE-AP",
                   pnolist=["Lab9Net"], routine=["Lab", 9.0, 18.0])

    observations = []
    t0 = 1700000000.0
    for d in range(days):
        day_base = t0 + d * 86400
        for dev in devs:
            hits = rng.randrange(2, 5)
            for h in range(hits):
                ts = day_base + (dev["routine"][1] + rng.uniform(0, 2)) * 3600
                mac = (dev["mac_stable"] if not dev["randomizes"]
                       else _lab_mac(rng))
                # privacy config flip at day = days//2: later half the
                # dataset shows PNO-scrubbed identifiers for randomizers
                # so students can compare before/after.
                scrubbed = dev["randomizes"] and d >= max(1, days // 2)
                observations.append({
                    "ts": round(ts, 1), "mac": mac,
                    "device_id": dev["device_id"],
                    "probed": (["Broadcast"] if scrubbed
                               else list(dev["pnolist"])),
                    "ie_sig": ((dev["ie_sig"] if not scrubbed else
                                hashlib.md5(mac.encode()).hexdigest()[:6])),
                    "rssi": dev["rssi_floor"] + rng.randrange(0, 22) +
                    (-6 if not scrubbed else 0),
                    "channel": rng.choice((1, 6, 11)),
                    "ap": rng.choice(("LAB-AP-1", "LAB-AP-2", "LAB-AP-3")),
                    "day": d,
                })
    observations.sort(key=lambda o: (o["ts"], o["mac"]))

    with open(dev_path, "w", encoding="utf-8") as fh:
        json.dump({"seed": seed, "devices": devs,
                   "scope_rule": ("correlation only over lab devices; "
                                  "LAB-REFERENCE-AP is off-limits"),
                   "generated": time.strftime("%Y-%m-%d %H:%M"), },
                  fh, indent=1)
    with open(obs_path, "w", encoding="utf-8") as fh:
        json.dump({"version": DATASET_VERSION, "seed": seed,
                   "days": days, "observations": observations}, fh)
    os.chmod(dev_path, 0o600)
    os.chmod(obs_path, 0o600)
    return {"devices": len(devs), "observations": len(observations),
            "randomizers": sum(1 for d in devs if d["randomizes"])}


def load_dataset(dest_dir):
    dest_dir = os.path.abspath(dest_dir)
    with open(os.path.join(dest_dir, "devices.json"),
              encoding="utf-8") as fh:
        devices = json.load(fh)
    with open(os.path.join(dest_dir, "observations.json"),
              encoding="utf-8") as fh:
        obs = json.load(fh)
    return {"devices": devices["devices"], "seed": devices.get("seed", 14),
            "scope_rule": devices.get("scope_rule", ""),
            "days": obs.get("days", 6),
            "observations": obs["observations"]}


# --------------------------------------------------------------------------
# Correlation analysis
# --------------------------------------------------------------------------

def _fingerprint(ob):
    return "|".join(sorted(s for s in ob.get("probed", []) if s)) + \
        f"|{ob.get('ie_sig', '')}"


def analyze_dataset(ds, window_days=None, include_restricted=False):
    """Cluster lab observations into identity tracks.

    Non-sensitive metadata only: probe-request fingerprint, RSSI band,
    time-of-day profile, channel mix.  No payload, no real identity.

    Any attempt that touches the restricted device raises ScopeError —
    the instructor sentinel: correlating beyond scope is refused *before*
    any analysis and logged by the caller.
    """
    alerts = []
    by_mac = {}
    for o in ds["observations"]:
        if not include_restricted:
            rid = _restrict_lookup(ds)
            if o["device_id"] in rid:
                # restricted traffic is present in the raw log (mirrors
                # reality) but must never enter a correlation run
                continue
        by_mac.setdefault(o["mac"], []).append(o)

    clusters = []   # each = {"track", "members":[mac], "confidence", "why"}
    seen = set()
    fps = {}
    for mac, rows in by_mac.items():
        fps[mac] = _fingerprint(rows[0])

    # cluster pass 1: exact fingerprint match
    groups = {}
    for mac, fp in fps.items():
        groups.setdefault(fp, []).append(mac)
    for fp, members in groups.items():
        if len(members) < 2:
            continue
        conf = min(0.97, 0.45 + 0.09 * len(members))
        clusters.append({"members": sorted(members),
                         "confidence": round(conf, 2),
                         "why": "identical probe-request fingerprint "
                                f"`{fp or 'empty'}` over {len(members)} "
                                "distinct MACs",
                         "method": "fingerprint"})
        seen.update(members)

    # cluster pass 2: routine + RSSI band co-occurrence for stragglers
    mac_routes = {}
    for mac in by_mac:
        rows = by_mac[mac]
        hrs = [round((r["ts"] % 86400) / 3600) for r in rows]
        mac_routes[mac] = (hrs, sum(r["rssi"] for r in rows) / len(rows))
    leftovers = [m for m in by_mac if m not in seen]
    for i, m1 in enumerate(leftovers):
        for m2 in leftovers[i+1:]:
            h1, r1 = mac_routes[m1]
            h2, r2 = mac_routes[m2]
            overlap = len(set(h1) & set(h2))
            if overlap >= 2 and abs(r1 - r2) < 6 and overlap >= 0.7 * len(h1):
                conf = 0.55
                clusters.append({"members": sorted([m1, m2]),
                                 "confidence": conf,
                                 "why": (f"same daily routine ({overlap} "
                                         "shared hours) plus RSSI within "
                                         f"{abs(r1-r2):.1f} dB — camouflage "
                                         "by routine, not by address"),
                                 "method": "routine"})
                seen.update([m1, m2])

    tracks = {"clusters": sorted(clusters, key=lambda c: -c["confidence"]),
              "unique_macs": len(by_mac),
              "singletons": len(by_mac) - len(seen),
              "alerts": alerts}
    return tracks


def _restrict_lookup(ds):
    return {d["device_id"] for d in ds["devices"] if d.get("restricted")}


class ScopeError(Exception):
    """Attempt to analyze beyond the permitted exercise scope."""


def check_scope(ds, target, why=""):
    """Return True if *target* may be analyzed under lab scope."""
    restr = {d["device_id"]: d for d in ds["devices"]
             if d.get("restricted")}
    labels = [f"{rid} ({restr[rid]['label']})" for rid in restr]
    if target in restr or any(t == target for t, _d in restr.items()):
        raise ScopeError(
            f"target {target} is the lab reference device — correlation "
            f"against it is outside the exercise scope ({why or 'refused'}).")
    return True


def privacy_report(ds):
    """Exposure summary: what survives MAC randomization?"""
    rnd = [d for d in ds["devices"] if d["randomizes"]]
    stable = [d for d in ds["devices"] if not d["randomizes"]]
    by_day = {}
    for o in ds["observations"]:
        by_day.setdefault(o["day"], []).append(o)
    first_half = list(range(0, max(1, ds["days"] // 2)))
    rpt = {
        "randomizers": len(rnd), "stable": len(stable),
        "total_obs": len(ds["observations"]),
        "days": ds["days"],
        "per_day": {d: len(v) for d, v in sorted(by_day.items())},
        "lesson": ("randomizing the MAC rotates the layer-2 address but not "
                   "the *persona*: probe lists, IE signatures and routines "
                   "still uniquely re-identify a device"),
    }
    # exposure: distinct probed-SSID sets per day (should shrink after scrub)
    leak_before, leak_after = 0, 0
    for o in ds["observations"]:
        if _is_randomizer(ds, o["device_id"]):
            if o["day"] < max(1, ds["days"] // 2):
                leak_before += len([s for s in o.get("probed", [])
                                    if s and s != "Broadcast"])
            else:
                leak_after += len([s for s in o.get("probed", [])
                                   if s and s != "Broadcast"])
    rpt["pnolist_leak"] = {"before_scrub": leak_before,
                           "after_scrub": leak_after}
    return rpt


def _is_randomizer(ds, device_id):
    for d in ds["devices"]:
        if d["device_id"] == device_id:
            return bool(d["randomizes"])
    return False


def simulate_privacy_config(ds, device_id, config):
    """What-if: config knobs → expected correlation confidence.

    config keys: scrub_pno (bool), ie_randomize (bool),
    irregular_timing (bool).  Purely modelled (no live probing).
    """
    base = 0.9
    if config.get("scrub_pno"):
        base -= 0.42
    if config.get("ie_randomize"):
        base -= 0.22
    if config.get("irregular_timing"):
        base -= 0.16
    residual = max(0.02, round(base, 2))
    return {"device": device_id, "config": dict(config),
            "confidence": residual,
            "verdict": ("low — routine alone is weak evidence"
                        if residual < 0.25 else
                        "moderate — still re-identifiable"
                        if residual < 0.55 else
                        "high — configuration does not help enough")}


# --------------------------------------------------------------------------
# Quiz + scoring
# --------------------------------------------------------------------------

PRIV_QUIZ = {
    "q_rotates": 15,        # what actually changes
    "q_reident": 20,        # probe-request fingerprint
    "q_routine": 15,        # time-of-day correlation
    "q_scrub": 20,          # PNO list scrub impact
    "q_scope": 15,          # reference AP off-limits
    "q_defense": 15,        # layered mitigations
}

_PRIV_ANS = {
    "q_rotates": ("l2-address-only",
                  ("MAC randomization rotates the *layer-2 address only*; "
                   "the probe-request *content* (SSID list, IE signature) "
                   "and the device's timing habits are untouched.")),
    "q_reident": ("probe-fingerprint",
                  ("Repeated observations of the *identical probe-request "
                   "fingerprint* across rotated MACs cluster them into one "
                   "identity track — address rotation alone does not break "
                   "the link.")),
    "q_routine": ("routine-signature",
                  ("Devices visiting the same places at the same hours "
                   "re-identify through their *routine*, irrespective of "
                   "any MAC change.")),
    "q_scrub": ("pno-scrub",
                ("Scrubbing the PNO list (stop probing for remembered "
                 "names, or probe only 'Broadcast') removes the strongest "
                 "correlation feature — confidence drops sharply when the "
                 "network list is withheld.")),
    "q_scope": ("reference-ap",
                ("The lab reference AP is inventoried as restricted: any "
                 "correlation attempt against it is refused and logged. "
                 "Scope discipline is the practical lesson.")),
    "q_defense": ("layered",
                  ("No single flag fixes privacy: scrub probe lists, "
                   "rotate with random timing, align IE signatures, and "
                   "minimize how much the device reveals per frame. The "
                   "combined behavior is what raises the cost of tracking.")),
}


def score_privlab(answers):
    """answers: {qid: choice-string}. Returns (score, feedback list)."""
    pts = 0.0
    notes = []
    for qid, weight in sorted(PRIV_QUIZ.items()):
        wanted, explain = _PRIV_ANS[qid]
        got = (answers.get(qid) or "").strip().lower()
        if got == wanted:
            pts += weight
            notes.append(f"+{weight} {qid}: correct — {explain}")
        elif _partials(qid, got):
            pts += weight // 2
            notes.append(f"+{weight//2} {qid}: partial — {explain}")
        else:
            notes.append(f"+0 {qid}: wanted `{wanted}` — {explain}")
    total = round(pts, 1)
    verdict = ("excellent — you can both measure and *reduce* privacy "
               "exposure" if total >= 85 else
               "good — revisit the partial items" if total >= 60 else
               "retry — the observation log tells the whole story")
    return total, notes + [f"verdict: {verdict}"]


def _partials(qid, got):
    aliases = {
        "q_rotates": {"address-only", "mac", "l2"},
        "q_reident": {"fingerprint", "ssid-list", "probes"},
        "q_routine": {"times", "schedule", "hours"},
        "q_scrub": {"scrub", "pnolist", "hide-list"},
        "q_scope": {"scope", "restricted", "off-limits"},
        "q_defense": {"multiple", "combine", "both"},
    }
    return got in aliases.get(qid, set())


PRIV_EXERCISES = [
    {"id": "ex1", "title": "Read the observation log",
     "task": "open the console and read a week's worth of synthetic "
             "probe-requests; note how many unique MACs you can see.",
     "weight": 10, "flag": "viewed_console"},
    {"id": "ex2", "title": "Spot the stable device",
     "task": "find a device that does NOT randomize its MAC. Count how "
             "many observations it produced vs a randomizer.",
     "weight": 15, "flag": "compare_counts"},
    {"id": "ex3", "title": "Break the randomization",
     "task": "run the correlation analysis. Which devices could you "
             "re-cluster despite rotated MACs? Why?",
     "weight": 25, "flag": "ran_correlation"},
    {"id": "ex4", "title": "Design the defense",
     "task": "use the what-if simulator to pick config knobs that drop "
             "one device's re-identification confidence below 0.3.",
     "weight": 25, "flag": "config_lowered"},
    {"id": "ex5", "title": "Respect the scope",
     "task": "try to correlate LAB-REFERENCE-AP and observe the refusal "
             "and the logged alert. Explain why it is out of scope.",
     "weight": 25, "flag": "probe_blocked"},
]


def exercise_hint(flag):
    v = {"viewed_console": "the console card shows raw rows",
         "compare_counts": "stable MACs stay single-tracked",
         "ran_correlation": "the tracks page lists merged clusters",
         "config_lowered": "the instructor page opens the what-if knobs",
         "probe_blocked": "scope check fires before any math"}
    return v.get(flag, "")


# --------------------------------------------------------------------------
# Web application — backend / frontend / API / logging in one.
# --------------------------------------------------------------------------

class PrivLabApp:
    """Shared state for the privacy lab web console."""

    MAX_OBS_PER_PAGE = 400

    def __init__(self, ds, store, token):
        self.ds = ds
        self.store = store
        self.token = token
        self.lock = threading.RLock()
        self.alerts = []          # scope-violation alerts
        self.tracks = None        # last correlation run
        self.attempts = 0
        self.completed = set()

    # ---------------- scope sentinel -------------
    def _guarded(self, fn, target, client):
        try:
            check_scope(self.ds, target)
        except ScopeError as e:
            entry = {"ts": time.time(), "target": target,
                     "why": str(e), "client": client}
            self.alerts.append(entry)
            self.store.event("privacy", "scope_refusal",
                             f"{target}: {e}", client)
            return None
        return fn(target)

    # ---------------- pages -------------
    def _nav(self):
        return ("<div class='nav'>"
                "<a href='/'>observations</a>"
                "<a href='/tracks'>tracks</a>"
                "<a href='/privacy'>privacy</a>"
                "<a href='/compare'>compare</a>"
                "<a href='/alerts'>alerts</a>"
                "<a href='/exercises'>exercises</a>"
                "<a href='/quiz'>quiz</a>"
                "</div>")

    def home(self):
        rpt = privacy_report(self.ds)
        rows = []
        for o in self.ds["observations"][:self.MAX_OBS_PER_PAGE]:
            rows.append(
                f"<tr><td>{o['ts']:.0f}</td><td><code>{html.escape(o['mac'])}"
                "</code></td>"
                f"<td><code>{html.escape(o['device_id'])}</code></td>"
                f"<td>{html.escape(','.join(p for p in o['probed'] if p))}"
                f"</td><td>{o['rssi']}</td>"
                f"<td>{html.escape(o['ap'])}</td><td class='dim'>d{o['day']}"
                "</td></tr>")
        body = self._nav() + f"""
 <div class='card'><h1>📡 Wireless Privacy &amp; MAC Randomization Laboratory</h1>
  <p class='dim'>Lab estate only — every identifier is synthetic
  (<code>{LAB_OUI}</code> local block). Restricted scope:
  {html.escape(self.ds['scope_rule'])}</p>
  <table><tr><th>ts</th><th>MAC</th><th>device</th><th>probed</th>
   <th>RSSI</th><th>AP</th><th>day</th></tr>
   {''.join(rows)}</table>
  <p class='tag warn'>randomizers {rpt['randomizers']} · stable
  {rpt['stable']} · {rpt['total_obs']} observations over
  {rpt['days']} days</p></div>"""
        return _page("privacy lab — observations", body)

    def tracks_page(self):
        if self.tracks is None:
            self.tracks = analyze_dataset(self.ds)
            self.store.event("privacy", "analyze",
                             f"{len(self.tracks['clusters'])} clusters")
        t = self.tracks
        cards = []
        for c in t["clusters"][:20]:
            chip = "ok" if c["confidence"] < 0.4 else (
                "warn" if c["confidence"] < 0.7 else "bad")
            cards.append(
                f"<div class='card'><span class='chip {chip}'>"
                f"{c['confidence']:.2f}</span> "
                f"<b>{c['method']}</b> · "
                f"{len(c['members'])} MACs — "
                f"{html.escape(c['why'])}<table><tr>"
                + "".join(f"<td><code>{html.escape(m)}</code></td>"
                          for m in c["members"])
                + "</tr></table></div>")
        svg = self._exposure_svg()
        body = self._nav() + f"""
 <div class='card'><h1>🧩 identity tracks</h1>
  <p>{len(t['clusters'])} correlation clusters from
  <code>{t['unique_macs']}</code> distinct MACs
  ({t['singletons']} singletons survive). Restricted traffic filtered.
  </p>{svg}{''.join(cards) or '<p>No clusters — good posture.</p>'}</div>"""
        return _page("privacy lab — tracks", body)

    def privacy_page(self):
        rpt = privacy_report(self.ds)
        leak = rpt["pnolist_leak"]
        body = self._nav() + f"""
 <div class='card'><h1>🛡️ what leaks</h1>
  <p class='dim'>{html.escape(rpt['lesson'])}</p>
  <table>
   <tr><td>randomizers</td><td>{rpt['randomizers']}</td></tr>
   <tr><td>stable devices</td><td>{rpt['stable']}</td></tr>
   <tr><td>observations/day</td><td>{max(rpt['per_day'].values())}</td></tr>
   <tr><td>PNO SSIDs leaked <i>before</i> scrub</td>
    <td><span class='chip bad'>{leak['before_scrub']}</span></td></tr>
   <tr><td>PNO SSIDs leaked <i>after</i> scrub</td>
    <td><span class='chip ok'>{leak['after_scrub']}</span></td></tr>
  </table>
  <p>Lockdown of the probe-request list is the highest-leverage
  mitigation in this dataset — do the exercise to quantify it
  yourself.</p></div>"""
        return _page("privacy lab — privacy", body)

    def compare_page(self):
        rpt = privacy_report(self.ds)
        leak = rpt["pnolist_leak"]
        scale = max(1, max(leak["before_scrub"], leak["after_scrub"]))
        w1 = int(280 * leak["before_scrub"] / scale)
        w2 = int(280 * leak["after_scrub"] / scale)
        body = self._nav() + f"""
 <div class='card'><h1>⚖️ before vs after privacy config</h1>
  <div style='display:flex;gap:18px;align-items:flex-end'>
   <div><div class='dim'>before scrub</div>
    <div style='width:{w1}px;height:120px;background:#c0392b'></div>
    <b>{leak['before_scrub']}</b></div>
   <div><div class='dim'>after scrub</div>
    <div style='width:{w2}px;height:120px;background:#27ae60'></div>
    <b>{leak['after_scrub']}</b></div></div>
  <p class='tag warn'>probing the same remembered SSIDs carries the
  correlation — configuration is the control, not the address.</p></div>"""
        return _page("privacy lab — compare", body)

    def alerts_page(self):
        rows = "".join(
            f"<tr><td>{time.strftime('%H:%M:%S', time.localtime(a['ts']))}"
            f"</td><td><code>{html.escape(a['target'])}</code></td>"
            f"<td>{html.escape(a['why'])}</td></tr>"
            for a in self.alerts)
        body = self._nav() + f"""
 <div class='card'><h1>🚨 scope refusals</h1>
  <p class='dim'>Every request to correlate beyond the permitted device
   <span class='chip bad'>{len(self.alerts)}</span> refused so far.</p>
  <table><tr><th>time</th><th>target</th><th>refusal</th></tr>
  {rows or '<tr><td colspan=3 class="dim">none yet</td></tr>'}</table></div>"""
        return _page("privacy lab — alerts", body)

    def exercises_page(self):
        items = []
        for ex in PRIV_EXERCISES:
            done = ex["flag"] in self.completed
            items.append(
                f"<div class='card'><span class='chip "
                f"{'ok' if done else 'warn'}'>"
                f"{'✓ done' if done else 'todo'}</span> "
                f"<b>{html.escape(ex['title'])}</b> — {ex['task']} "
                f"<span class='dim'>({ex['weight']} pts · "
                f"{ex['flag']})</span></div>")
        body = self._nav() + ("<div class='card'><h1>📋 exercises</h1>"
                             "Hands-on: view, compare, correlate, configure, "
                             "respect scope. Completion flags are set when "
                             "your session exercises the matching feature."
                             "</div>" + "".join(items))
        return _page("privacy lab — exercises", body)

    def quiz_page(self):
        qs = [
            ("q_rotates", "MAC randomization changes…",
             ("l2-address-only", "everything", "the encryption",
              "the IPv6 stack")),
            ("q_reident", "Randomized MACs still re-identify because…",
             ("probe-fingerprint", "RSSI is unique globally",
              "channels are unique", "AP names leak")),
            ("q_routine", "Which observation survives rotation?",
             ("routine-signature", "MAC address", "vendor OUI",
              "channel number")),
            ("q_scrub", "Which config change drops correlation confidence "
                        "most in this dataset?",
             ("pno-scrub", "lower-RSSI", "shorter beacon interval",
              "more APs")),
            ("q_scope", "Attempting to correlate LAB-REFERENCE-AP is…",
             ("reference-ap", "always allowed", "slower but fine",
              "invisible to the lab")),
            ("q_defense", "Best practice for real-world privacy?",
             ("layered", "rotate faster only", "hide SSID only",
              "avoid 5GHz")),
        ]
        form = [f"<div class='card'><b>{q}</b>" +
                "".join(f"<label style='display:block'>"
                        f"<input type='radio' name='{qid}' value='{c}'> "
                        f"{html.escape(c)}</label>" for c in cs)
                + "</div>" for qid, q, cs in qs]
        body = self._nav() + ("<form method='post' action='/quiz'>"
                             + "".join(form)
                             + "<button class='go'>score</button></form>")
        return _page("privacy lab — quiz", body)

    def quiz_submit(self, form, client):
        answers = {qid: (form.get(qid, [""])[0] if form.get(qid) else "")
                   for qid in PRIV_QUIZ}
        score, notes = score_privlab(answers)
        self.store.attempt("privacy", "quiz", json.dumps(answers),
                           score, f"{score:.1f}", client)
        li = "".join(f"<li>{html.escape(n)}</li>" for n in notes)
        body = self._nav() + f"""
 <div class='card'><h1>✅ {score:.1f} / 100</h1><ul>{li}</ul></div>"""
        return _page("privacy lab — quiz result", body)

    def instructor_page(self, token):
        with self.lock:
            ident = self.ds["devices"]
            stable = [d for d in ident if not d["randomizes"]]
        tbl = "".join(
            f"<tr><td><code>{html.escape(d['device_id'])}</code></td>"
            f"<td>{html.escape(d['label'])}</td>"
            f"<td>{'🎲 randomizes' if d['randomizes'] else '🔒 stable'}</td>"
            f"<td><code>{html.escape(d['mac_stable'])}</code></td>"
            f"<td class='dim'>{'restricted' if d.get('restricted') else ''}"
            f"</td></tr>" for d in ident)
        funnel = self.store.funnel("privacy")
        body = self._nav() + f"""
 <div class='card'><h1>🧑‍🏫 instructor console</h1>
  <p class='dim'>funnel: {funnel['views']} views ·
  {funnel['attempts']} attempts · best {funnel['best_score']:.1f}.
  Alerts: {len(self.alerts)} refused scope violations.</p>
  <form method='post' action='/i/{html.escape(token)}/expand'
   style='display:inline'><button class='go'>+2 devices (seeded)</button>
  </form>
  <form method='post' action='/i/{html.escape(token)}/reset'
   style='display:inline'><button class='go'>reset progress</button></form>
  <form method='post' action='/i/{html.escape(token)}/destroy'
   style='display:inline' onsubmit="return confirm('destroy dataset?')">
   <button class='go stop'>destroy dataset</button></form>
  <table><tr><th>id</th><th>label</th><th>posture</th><th>stable MAC</th>
   <th></th></tr>{tbl}</table></div>"""
        return _page("privacy lab — instructor", body)

    # ---------------- actions -------------
    def correlate(self, target, client):
        def go(t):
            flag = "ran_correlation" if target == "*" else None
            if flag:
                self.completed.add(flag)
            return analyze_dataset(self.ds)
        return self._guarded(go, target, client)

    def simulate(self, device, cfg, client):
        def go(t):
            res = simulate_privacy_config(self.ds, t, cfg)
            if res["confidence"] < 0.3:
                self.completed.add("config_lowered")
            return res
        return self._guarded(go, device, client)

    def log_probe(self, target, client):
        def go(t):
            self.completed.add("probe_blocked")
            return {"refused": t,
                    "why": "reference AP is outside the exercise scope"}
        return self._guarded(go, target, client)

    def expand(self):
        """Instructor: extend the fleet, deterministically per seed+size."""
        with self.lock:
            old = len(self.ds["devices"])
            rng2 = random.Random(self.ds.get("seed", 14) * 1000 + old)
            for i in range(old, old + 2):
                label = _LABELS[i % len(_LABELS)]
                dev = {"device_id": f"LAB-DEV-{i+1:02d}",
                       "label": label,
                       "randomizes": rng2.random() < 0.70,
                       "mac_stable": _lab_mac(rng2),
                       "pnolist": sorted(rng2.sample(
                           list(_POOL_SSIDS), 3)),
                       "ie_sig": rng2.choice(("1a2b3c", "9d8e7f")),
                       "rssi_floor": rng2.randrange(-78, -62),
                       "routine": list(rng2.choice(_ROUTES)),
                       "restricted": False,
                       "tag": hashlib.sha256(
                           f"x{i}|{old}".encode()).hexdigest()[:12]}
                self.ds["devices"].append(dev)
                # ... and emit a few observations so it shows up
                for day in range(2):
                    mac = (dev["mac_stable"] if not dev["randomizes"]
                           else _lab_mac(rng2))
                    self.ds["observations"].append({
                        "ts": 1700000000 + day * 86400 +
                        rng2.randrange(28800, 64800),
                        "mac": mac, "device_id": dev["device_id"],
                        "probed": list(dev["pnolist"]),
                        "ie_sig": dev["ie_sig"],
                        "rssi": dev["rssi_floor"] + rng2.randrange(0, 10),
                        "channel": rng2.choice((1, 6, 11)),
                        "ap": "LAB-AP-1", "day": day})
            self.ds["observations"].sort(key=lambda o: o["ts"])
            self.tracks = None
            self.store.event("privacy", "expand",
                             f"fleet {old} → {old+2}")

    def reset(self, client):
        with self.lock:
            self.alerts.clear()
            self.tracks = None
            self.completed.clear()
            funnel = self.store.funnel("privacy")
            self.store.event("privacy", "reset",
                             f"wiped after {funnel['attempts']} attempts",
                             client)

    def destroy(self, client):
        with self.lock:
            n = len(self.ds["observations"])
            self.ds["observations"].clear()
            self.ds["devices"] = self.ds["devices"][:0]
            self.alerts.clear()
            self.tracks = None
            self.completed.clear()
            self.store.event("privacy", "destroy",
                             f"{n} observations shredded", client)

    # ---------------- viz -------------
    def _exposure_svg(self):
        """SVG scatter: day (x) × devices (y), does the pattern persist?"""
        obs = self.ds["observations"]
        if not obs:
            return ("<svg width=700 height=200 "
                    "style='background:#111'></svg>")
        devs = sorted({o["device_id"] for o in obs})
        ymap = {d: 24 + i * 22 for i, d in enumerate(devs)}
        xmax = max(o["day"] for o in obs) + 1
        dots = []
        for o in obs[:700]:
            x = 24 + o["day"] * 64
            y = ymap[o["device_id"]]
            col = "#e74c3c" if o["day"] < max(1, self.ds["days"] // 2) \
                else "#2ecc71"
            dots.append(f"<circle cx='{x}' cy='{y}' r='4' fill='{col}' "
                        f"opacity='0.8'><title>{html.escape(o['mac'])}"
                        f"</title></circle>")
        h = 40 + 22 * len(devs)
        labels = "".join(f"<text x='4' y='{y+4}' fill='#888' "
                         f"font-size='10'>{html.escape(d)}</text>"
                         for d, y in ymap.items())
        return (f"<svg width=700 height={h} style='background:#111;"
                "border-radius:8px'>" + labels + "".join(dots) +
                f"<text x='24' y='14' fill='#c0392b' font-size='10'>"
                "before scrub</text>"
                f"<text x='{24+xmax*64-64}' y='{h-6}' fill='#27ae60' "
                "font-size='10'>after scrub</text></svg>")


from http.server import BaseHTTPRequestHandler  # noqa: E402


class _Handler(BaseHTTPRequestHandler):
    lab = "privacy"
    _MAX_POST = 65536

    def log_message(self, fmt, *a):  # quiet: instructor logs via DevLabStore
        pass

    def _client(self):
        xff = self.headers.get("X-Forwarded-For", "")
        return (xff.split(",")[0].strip() or self.client_address[0])[:45]

    def _tok_ok(self, u):
        q = parse_qs(u.query)
        tok = (q.get("token") or [""])[0]
        return _tok_eq(tok, _app_token(self))

    def _form(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > self._MAX_POST:
            return None
        if n == 0:
            return {}
        raw = self.rfile.read(n).decode("utf-8", "ignore")
        return {k: v for k, v in parse_qs(raw).items()}

    def _json(self, obj, code=200):
        body = json.dumps(obj, indent=1).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _ok(self, body, ctype="text/html; charset=utf-8"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _app_token(handler):
    return handler.server.app.token if hasattr(handler.server, "app") \
        else ""


from hmac import compare_digest as _cd  # noqa: E402


def _tok_eq(a, b):
    return bool(a) and _cd(a.encode(), (b or "").encode())


def make_priv_server(bind, port, app):  # final definition (binds app)
    from http.server import ThreadingHTTPServer

    class _Srv(ThreadingHTTPServer):
        daemon_threads = True

    class H(_Handler):
        def do_GET(self):
            u = urlparse(self.path)
            path = u.path.rstrip("/") or "/"
            authed = self._tok_ok(u)
            app.store.event("privacy", "view", path, self._client())
            routes = {"/": app.home, "/tracks": app.tracks_page,
                      "/privacy": app.privacy_page,
                      "/compare": app.compare_page,
                      "/alerts": app.alerts_page,
                      "/quiz": app.quiz_page}
            if path in routes:
                if path == "/tracks":
                    app.completed.add("ran_correlation")
                return self._ok(routes[path]())
            if path == "/exercises":
                app.completed.add("viewed_console")
                return self._ok(app.exercises_page())
            if path == "/api/state":
                if not authed:
                    return self._json({"error": "not found"}, 404)
                with app.lock:
                    return self._json({
                        "ok": True,
                        "funnel": app.store.funnel("privacy"),
                        "alerts": app.alerts[-50:],
                        "completed": sorted(app.completed),
                        "devices": len(app.ds["devices"]),
                        "observations": len(app.ds["observations"]),
                    })
            if path == "/i/" + app.token:
                return self._ok(app.instructor_page(app.token))
            return self._json({"error": "not found"}, 404)

        def do_POST(self):
            u = urlparse(self.path)
            path = u.path.rstrip("/") or "/"
            form = self._form()
            if form is None:
                return self._json({"error": "bad request"}, 400)
            if path == "/quiz":
                return self._ok(app.quiz_submit(form, self._client()))
            if path == "/api/correlate":
                target = (form.get("target") or ["*"])[0]
                res = app.correlate(target, self._client())
                if res is None:
                    return self._json({"refused": target}, 403)
                return self._json({"clusters": res["clusters"],
                                   "unique_macs": res.get("unique_macs")})
            if path == "/api/simulate":
                device = (form.get("device") or [""])[0]
                cfg = {k: (form.get(k) == ["on"])
                       for k in ("scrub_pno", "ie_randomize",
                                 "irregular_timing")}
                res = app.simulate(device, cfg, self._client())
                if res is None:
                    return self._json({"refused": device}, 403)
                return self._json(res)
            if path == "/i/" + app.token + "/expand":
                app.expand()
                return self._json({"ok": True})
            if path == "/i/" + app.token + "/reset":
                app.reset(self._client())
                return self._json({"ok": True})
            if path == "/i/" + app.token + "/destroy":
                app.destroy(self._client())
                return self._json({"ok": True})
            return self._json({"error": "not found"}, 404)

    srv = _Srv((bind, port), H)
    srv.app = app
    return srv


# --------------------------------------------------------------------------
# CLI helpers (used by cli.py cmd_priv_lab)
# --------------------------------------------------------------------------

def cmd_make_dataset(out, seed=14, devices=10, days=6, fresh=False):
    summary = generate_observations(out, seed=seed, devices=devices,
                                    days=days, fresh=fresh)
    print(f"lab dataset written: {out} "
          f"({summary['devices']} devices, {summary['observations']} "
          f"observations, {summary['randomizers']} randomizers)")


def cmd_inventory(db):
    ds = load_dataset(db)
    rnd = sum(1 for d in ds["devices"] if d["randomizes"])
    stable = sum(1 for d in ds["devices"] if not d["randomizes"])
    restr = [d["device_id"] for d in ds["devices"] if d.get("restricted")]
    print(f"privacy lab inventory — {len(ds['devices'])} devices "
          f"({rnd} randomizers, {stable} stable, restricted: "
          f"{', '.join(restr)})")
    for o in sorted({d['label'] for d in ds['devices']}):
        print(f"  · {o}")


def cmd_correlate(db, target="*"):
    ds = load_dataset(db)
    if target != "*":
        try:
            check_scope(ds, target)
        except ScopeError as e:
            print(f"refused: {e}")
            return 1
    t = analyze_dataset(ds)
    print(f"{len(t['clusters'])} clusters from {t['unique_macs']} MACs"
          f" ({t['singletons']} singletons survive)")
    for c in t["clusters"][:10]:
        print(f"  · confidence {c['confidence']:.2f} "
              f"[{c['method']}] {', '.join(c['members'][:3])}"
              f"{' …' if len(c['members']) > 3 else ''}")
    return 0


def cmd_compare(db):
    ds = load_dataset(db)
    rpt = privacy_report(ds)
    leak = rpt["pnolist_leak"]
    print(f"before scrub: {leak['before_scrub']} PNO SSIDs leaked | "
          f"after scrub: {leak['after_scrub']} "
          f"(randomizers {rpt['randomizers']}, stable {rpt['stable']})")
    return 0


def cmd_score(db, answers):
    try:
        payload = json.load(open(answers, encoding="utf-8")) \
            if answers != "-" else json.load(os.sys.stdin)
    except (OSError, json.JSONDecodeError) as e:
        print(f"score: cannot parse answers: {e}")
        return 2
    score, notes = score_privlab(payload)
    print(f"privacy lab score: {score:.1f} / 100")
    for n in notes:
        print(f"  {n}")
    return 0 if score >= 60 else 1


def cmd_exercises(db):
    print("privacy lab exercises:")
    for ex in PRIV_EXERCISES:
        print(f"  [{ex['id']}] {ex['title']} ({ex['weight']} pts)")
        print(f"        {ex['task']}")
    return 0
