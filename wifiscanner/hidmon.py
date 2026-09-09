# -*- coding: utf-8 -*-
"""hidmon — the hidden-monitoring & stealth-detection laboratory (feature 10).

A fully offline, instructor-controlled lab: we synthesise 4 days of host
telemetry (process snapshots, network connections, file events, service
registry, auth.log) for one lab workstation and hide an implant inside it.
Students get the *defender's console*: the same tables a normal admin can
see at every point in time — process list, listeners, egress, file events —
plus the engine's explainable signal analysis. Their job: find the implant,
prove *when* it flipped from dormant to active, prove how it *conceals*
itself (its name hides from ps but its sockets keep talking), and walk away
knowing which signals survive concealment and which don't.

Curriculum beats:

1. **baseline** — a boring, legitimate box, with one *authorised* IT
   monitoring agent (snmpd-corp) that students must NOT accuse
   (false-positive discipline).
2. **install** — the implant drops a staging file in a dot-directory and
   starts a 6-hourly keepalive to its C2.
3. **flip** — at night it turns active: CPU spikes off-schedule and the
   beacon cadence tightens ~40×. The engine fires a behaviour-change alert.
4. **concealment** — it renames to a kernel-worker lookalike and vanishes
   from process tables while its sockets stay visible — the classic
   ps-vs-ss discrepancy, plus an auth.log gap (its own signing window is
   wiped).
5. **respawn / anti-forensics** — a respawn under a new name on the same
   C2, and unlink-while-running of its staging file (fd stays open).

Everything is synthetic: no real processes, no real sockets, no real files
are created or touched by this module. It is a telemetry *simulation* for
teaching defenders, exactly like a flight simulator teaches pilots.

CLI: `wifiscanner stealth-lab <action>`; web: student portal + token-gated
instructor dashboard (ground truth, attempt log, funnel, tick control,
reset & regenerate).
"""

import hashlib
import html
import json
import os
import sys
import threading
import time
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from .devlab import DevLabStore, new_token, _page  # noqa: E402
from .privacy import ensure_secure_storage, secure_file  # noqa: E402

TICK_S = 600.0            # one tick = 10 minutes of lab time
N_DAYS = 4
N_TICKS = 96 * N_DAYS

HOST = "lab-ws-07"
IT_MONITOR = "snmpd-corp"


# ---------------------------------------------------------------- entities

def _mk_sysprocs():
    """The always-present, boring, legitimate system fleet."""
    rows = [
        # key, name, pid, ppid, user, package-owner, base cpu, rss MB
        ("init", "init", 1, 0, "root", "sysvinit-utils", 0.0, 6),
        ("sshd", "sshd", 812, 1, "root", "openssh-server", 0.1, 12),
        ("rsyslog", "rsyslogd", 431, 1, "syslog", "rsyslog", 0.0, 8),
        ("cron", "cron", 540, 1, "root", "cron", 0.0, 4),
        ("dbus", "dbus-daemon", 388, 1, "messagebus", "dbus", 0.0, 5),
        ("auditd", "auditd", 402, 1, "root", "auditd", 0.0, 10),
    ]
    out = {}
    for key, name, pid, ppid, user, owner, cpu, rss in rows:
        out[key] = dict(key=key, kind="process", name=name, pids=[pid],
                        ppid=ppid, user=user, owner=owner, cpu=cpu,
                        rss=rss, category="system",
                        maintainer=owner, is_monitor=False)
    return rows and out


def _mk_userprocs(rnd):
    rows = [("firefox", "firefox", 1300 + rnd.randint(0, 40), 900, "labuser",
             "firefox-esr", 4.0, 620), ]
    out = {}
    for key, name, pid, ppid, user, owner, cpu, rss in rows:
        out[key] = dict(key=key, kind="process", name=name, pids=[pid],
                        ppid=ppid, user=user, owner=owner, cpu=cpu,
                        rss=rss, category="user", is_monitor=False)
    return out


def _mk_it_monitor():
    return {IT_MONITOR: dict(
        key=IT_MONITOR, kind="service", name=IT_MONITOR, pids=[1214],
        ppid=1, user="monitor", owner="corp-monitoring-agt.deb",
        cpu=0.2, rss=22, category="it-monitor", is_monitor=True,
        unit="corp-monitoring-agent.service",
        note="authorised corporate telemetry agent (signed, registered)")}


def _mk_noise_profile():
    return [dict(key="fstrim", name="fstrim", owner="util-linux",
                 user="root", dur=1, typical_hour=None),
            dict(key="apt-daily", name="apt-daily.service", owner="apt",
                 user="root", dur=2, typical_hour=6),
            dict(key="logrotate", name="logrotate", owner="logrotate",
                 user="root", dur=1, typical_hour=7),
            dict(key="unattended", name="unattended-upgr", owner="unattended",
                 user="root", dur=3, typical_hour=6)]


IMPLANT_NAME_POOL = ("kworker_mb", "udevd_v", "ksoftirqdx", "jbdhelper")
C2_POOL = ("10.99.0.2:4444", "10.99.0.7:5052", "10.98.0.3:9001")
IMPLANT_RSS = 14  # small footprint — that's part of the stealth lesson


def generate_scenario(outdir: str, seed: int = 10, fresh: bool = False):
    """Deterministically synthesise a 4-day telemetry scenario.

    Layout:
      scenario.json       — manifest (public, fine to share with students)
      telemetry.json      — every table row across all ticks (public)
      ground-truth.json   — 0600 instructor-only facts for scoring
    """
    if os.path.exists(outdir) and os.listdir(outdir) and not fresh:
        raise FileExistsError(f"{outdir} is not empty (pass fresh=True or "
                              f"`--fresh` to regenerate)")
    os.makedirs(outdir, exist_ok=True)
    rnd = __import__("random").Random(seed)
    start = int(time.time() - N_DAYS * 86400) // 3600 * 3600

    gen1 = rnd.choice(IMPLANT_NAME_POOL)
    gen2 = rnd.choice([n for n in IMPLANT_NAME_POOL if n != gen1])
    implant = dict(name=gen1, name2=gen2,
                   c2=rnd.choice(C2_POOL),
                   pid=rnd.randint(28, 96), pid_gen2=rnd.randint(28, 96),
                   stage_dir=rnd.choice(["/var/tmp/.cache",
                                         "/dev/shm/.x",
                                         "/var/lib/.kmod"]),
                   stage_file=rnd.choice(["trk.bin", ".sysd.o", "km"])
                   )
    implant["stage"] = implant["stage_dir"] + "/" + implant["stage_file"]

    procs = {}
    procs.update(_mk_sysprocs())
    procs.update(_mk_userprocs(rnd))
    procs.update(_mk_it_monitor())
    noise = _mk_noise_profile()

    # ---------------- timeline beats (absolute ticks) ----------------
    T = lambda day, h, mi: (day * 96) + h * 6 + mi // 10
    beat_install = T(0, 13, 10) + rnd.randint(-6, 6)     # day 1 ~13:10
    beat_first_beacon = beat_install + 1
    beat_flip = T(1, 2, 10) + rnd.randint(-6, 6)         # day 2 night 02:10
    beat_conceal = T(2, 3, 0) + rnd.randint(-6, 6)       # day 3 ~03:00
    beat_audit_gap = (beat_conceal + 1, beat_conceal + 31)
    beat_respawn = T(2, 14, 40) + rnd.randint(-6, 6)     # day 3 afternoon
    beat_unlink = T(3, 9, 30) + rnd.randint(-6, 6)       # day 4 morning

    proc_rows = []     # tick, key, pid, ppid, user, cpu%, rss, name,
                       # visible(present in ps output opened by an admin?)
    conn_rows = []     # tick, key, src->dst, state, bytes, proto
    file_rows = []     # tick, path, op, by
    auth_rows = []     # tick, line

    def implant_present(t):
        return t >= beat_install

    def implant_state(t):
        if t < beat_install:
            return "absent"
        if t < beat_flip:
            return "dormant"
        if t < beat_conceal:
            return "active"
        if t < beat_respawn:
            return "concealed"
        return "respawned"

    def work_hours(t):
        h = (t % 96) / 6
        return 9 <= h < 18

    def night_hours(t):
        h = (t % 96) / 6
        return h >= 22 or h < 6

    seen_pids = defaultdict(set)
    for t in range(N_TICKS):
        # ---------- legit fleet procs
        for key, e in procs.items():
            if key in ("fstrim",):
                continue
            jitter = rnd.uniform(-0.05, 0.05)
            cpu = e["cpu"] + jitter
            if key == "firefox" and not work_hours(t):
                cpu = 0.2
            proc_rows.append(dict(t=t, key=key, pid=e["pids"][0],
                                  ppid=e["ppid"], user=e["user"],
                                  cpu=round(max(0, cpu), 2),
                                  rss=e["rss"] + rnd.randint(-1, 1),
                                  name=e["name"], visible=1))
        # ---------- IT monitor: rock-steady egress every 15 min, day+night
        if t % 3 == 2:
            conn_rows.append(dict(t=t, key=IT_MONITOR, proto="udp",
                                  src=f"{HOST}:1214", dst="10.40.0.10:161",
                                  state="con-nat", bytes=rnd.randint(180, 260),
                                  cadence_s=900))
        # ---------- short noise jobs (grey zone)
        for n in noise:
            h_now = (t % 96) // 6
            if n["typical_hour"] is not None and h_now == n["typical_hour"] \
                    and t % n["dur"] == n["dur"] - 1:
                proc_rows.append(dict(t=t, key=n["key"], pid=4300 + t,
                                      ppid=1, user=n["user"],
                                      cpu=round(rnd.uniform(1, 6), 1),
                                      rss=rnd.randint(8, 40),
                                      name=n["name"], visible=1))
        # ---------- the implant
        st = implant_state(t)
        if st != "absent":
            if st == "respawned":
                pid, name = implant["pid_gen2"], implant["name2"]
            else:
                pid, name = implant["pid"], implant["name"]
            if pid not in seen_pids[implant["c2"]]:
                seen_pids[implant["c2"]].add(pid)
            visible = 0 if st in ("concealed", "respawned") else 1
            cpu = 0.1
            if st == "active":
                cpu = rnd.uniform(28, 62) if night_hours(t) else \
                    rnd.uniform(0.5, 2)
            if st in ("concealed", "respawned"):
                cpu = rnd.uniform(20, 55) if night_hours(t) else 0.2
            proc_rows.append(dict(t=t, key="IMPLANT", pid=pid, ppid=1,
                                  user="root", cpu=round(cpu, 1),
                                  rss=IMPLANT_RSS + rnd.randint(-1, 1),
                                  name=name, visible=visible,
                                  owner="-", ppid_suspicious=(name ==
                                                              "kworker_mb")))
            # network: phase-dependent beaconing
            if st == "dormant" and (t - beat_first_beacon) % 36 == 0:
                conn_rows.append(dict(t=t, key="IMPLANT", proto="tcp",
                                      src=f"{HOST}:{40000 + t % 1000}",
                                      dst=implant["c2"], state="ESTABLISHED",
                                      bytes=rnd.randint(60, 90),
                                      cadence_s=21600))
            if st in ("active", "concealed", "respawned"):
                # post-flip: cadence tightened ~40x, night-heavy
                if (night_hours(t) and t % 3 == 0) or (not night_hours(t)
                                                       and t % 12 == 0):
                    conn_rows.append(dict(t=t, key="IMPLANT", proto="tcp",
                                          src=f"{HOST}:{40000 + t % 1000}",
                                          dst=implant["c2"],
                                          state="ESTABLISHED",
                                          bytes=rnd.randint(120, 900),
                                          cadence_s=1800))
        # ---------- file orbit
        if t == beat_install:
            file_rows.append(dict(t=t, path=implant["stage"],
                                  op="create", by="IMPLANT"))
            file_rows.append(dict(t=t, path=implant["stage_dir"] + "/log",
                                  op="create", by="IMPLANT"))
        if beat_flip <= t < beat_conceal and night_hours(t) and t % 6 == 0:
            file_rows.append(dict(t=t, path=implant["stage_dir"] + "/log",
                                  op="append", by="IMPLANT"))
        if t == beat_unlink:
            file_rows.append(dict(t=t, path=implant["stage"],
                                  op="unlink-while-running", by="IMPLANT"))
        # ---------- auth log (with a sanitisation gap during concealment)
        if t % 12 == 4 and not (beat_audit_gap[0] <= t <= beat_audit_gap[1]):
            auth_rows.append(dict(t=t, line=(
                f"sshd[{812}]: Accepted publickey for it-admin from "
                f"10.40.0.5 port 51{t % 100:02d} ssh2")))
        if t == beat_audit_gap[1] + 1:
            auth_rows.append(dict(t=t, line=(
                "auditd[402]: NOTICE log resumed; 0 events for prior window "
                "— buffer anomaly")))
    # respawn evidence is additive: gen2 first sighting note
    truth = dict(implant=dict(
        name=implant["name"], name_gen2=implant["name2"], c2=implant["c2"],
        pids=[implant["pid"], implant["pid_gen2"]],
        stage=implant["stage"], stage_dir=implant["stage_dir"],
        install_tick=beat_install, flip_tick=beat_flip,
        conceal_tick=beat_conceal, respawn_tick=beat_respawn,
        unlink_tick=beat_unlink,
        install_t=f"T+{beat_install * 10}min (day 1)",
        flip_t=f"day {beat_flip // 96 + 1} ~{beat_flip % 96 // 6:02d}:"
               f"{(beat_flip * 10) % 60:02d}",
        it_monitor=IT_MONITOR,
        lesson=("concealment breaks ps, NOT sockets; cadence flips betray "
                "dormant implants; respawn+rename keeps the c2 — attribute "
                "by behaviour, not by name")))

    manifest = dict(kind="stealthlab", seed=seed, host=HOST,
                    ticks=N_TICKS, tick_s=TICK_S, start=start,
                    end=start + N_TICKS * TICK_S, days=N_DAYS,
                    created=time.strftime("%Y-%m-%d %H:%M:%S"))
    telem = dict(proc=proc_rows, conn=conn_rows, file=file_rows,
                 auth=auth_rows, services=[dict(name=IT_MONITOR,
                                                unit="corp-monitoring-agent"
                                                ".service",
                                                state="active (running)",
                                                enabled="enabled"),
                                           dict(name="auditd",
                                                unit="auditd.service",
                                                state="active (running)",
                                                enabled="enabled")])
    with open(os.path.join(outdir, "scenario.json"), "w",
              encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=1)
    secure_file(os.path.join(outdir, "scenario.json"))
    with open(os.path.join(outdir, "telemetry.json"), "w",
              encoding="utf-8") as fh:
        json.dump(telem, fh)
    secure_file(os.path.join(outdir, "telemetry.json"))
    gt_path = os.path.join(outdir, "ground-truth.json")
    with open(gt_path, "w", encoding="utf-8") as fh:
        json.dump(truth, fh, indent=1)
    secure_file(gt_path)
    return dict(dir=outdir, ticks=N_TICKS, rows=(len(proc_rows) +
                len(conn_rows) + len(file_rows) + len(auth_rows)),
                host=HOST, seed=seed)


def load_scenario(dirname: str):
    """Load manifest + telemetry (+ ground truth if readable — never sent
    to student pages)."""
    with open(os.path.join(dirname, "scenario.json"), "r",
              encoding="utf-8") as fh:
        manifest = json.load(fh)
    with open(os.path.join(dirname, "telemetry.json"), "r",
              encoding="utf-8") as fh:
        telem = json.load(fh)
    truth = {}
    gt = os.path.join(dirname, "ground-truth.json")
    if os.path.exists(gt):
        try:
            with open(gt, "r", encoding="utf-8") as fh:
                truth = json.load(fh)
        except OSError:
            truth = {}
    return dict(manifest=manifest, telem=telem, truth=truth, dir=dirname)


def fmt_tick(start, t):
    ts = start + t * TICK_S
    lt = time.localtime(ts)
    return f"day {t // 96 + 1} {lt.tm_hour:02d}:{lt.tm_min:02d}"


# ----------------------------------------------------------- heuristic engine

class StealthEngine:
    """Explainable signal scoring over the telemetry tables.

    Signals are first-class teaching objects: every one names *the exact
    defensive principle* it exercises. Concealment signals (the ps-vs-ss
    discrepancy, the unlink, the audit gap) outweigh behaviour signals —
    that ordering is itself a lesson.
    """

    WEIGHTS = dict(concealment=60, unlink=30, audit_gap=20,
                   name_mimic=40, unowned=15, night_delta=20,
                   cadence_flip=20, respawn=15, hidden_stage=10,
                   c2_egress=25, legit_monitor=-60)

    def __init__(self, scenario):
        self.scen = scenario
        m = self.scen["manifest"]
        self.start = m["start"]
        self.proc = self.scen["telem"]["proc"]
        self.conn = self.scen["telem"]["conn"]
        self.files = self.scen["telem"]["file"]
        self.auth = self.scen["telem"]["auth"]
        self.by_key = defaultdict(lambda: dict(proc=[], conn=[], file=[]))
        for r in self.proc:
            self.by_key[r["key"]]["proc"].append(r)
        for r in self.conn:
            self.by_key[r["key"]]["conn"].append(r)
        for r in self.files:
            self.by_key[r.get("by", "")]["file"].append(r)
        self._audit_gaps = self._find_audit_gaps()

    # ---------------- internals
    def _find_audit_gaps(self):
        gaps = []
        ts = sorted(r["t"] for r in self.auth)
        for a, b in zip(ts, ts[1:]):
            if b - a > 24:      # expected cadence every 12 ticks
                gaps.append((a, b))
        return gaps

    def _hourly_cpu(self, key):
        hours = defaultdict(list)
        for r in self.by_key[key]["proc"]:
            hours[(r["t"] % 96) // 6].append(r["cpu"])
        return {h: sum(v) / len(v) for h, v in hours.items()}

    def analyze(self, key):
        """Signals for one entity, each with text + weight."""
        ent = self.by_key.get(key, dict(proc=[], conn=[], file=[]))
        if not ent["proc"] and not ent["conn"]:
            return None
        sigs = []
        name = ent["proc"][-1]["name"] if ent["proc"] else "?"
        owner = ent["proc"][-1].get("owner", "?")
        conns = ent["conn"]
        procs = ent["proc"]

        # name mimicry: kernel-worker naming with userspace network habits
        kernelish = any(name.startswith(p) for p in
                        ("kworker", "ksoftirqd", "jbd", "udevd"))
        if kernelish and conns:
            sigs.append(("name_mimic",
                         f"'{name}' poses as a kernel worker yet holds a "
                         f"userspace TCP socket to {conns[-1]['dst']} — real "
                         f"kthreads never do that",
                         self.WEIGHTS["name_mimic"]))

        if ent["proc"] and owner == "-":
            sigs.append(("unowned",
                         "no package owns this binary (ownership lookup = "
                         "'-') — every legitimate system service has one",
                         self.WEIGHTS["unowned"]))

        # concealment: disappears from ps while sockets persist
        if procs:
            invis_runs = [r for r in procs if not r["visible"]]
            if invis_runs and conns:
                first = invis_runs[0]["t"]
                sigs.append(("concealment",
                             f"since {fmt_tick(self.start, first)} the "
                             f"process is ABSENT from ps snapshots while its "
                             f"sockets to {conns[-1]['dst']} keep flowing — "
                             f"ps-vs-netstat discrepancy = classic rootkit "
                             f"concealment",
                             self.WEIGHTS["concealment"]))

        # egress to unregistered endpoint
        bad_dsts = {c["dst"] for c in conns} - {"10.40.0.10:161"}
        if bad_dsts:
            d = sorted(bad_dsts)[0]
            sigs.append(("c2_egress",
                         f"regular egress to unregistered endpoint {d} "
                         f"(nobody in the lab registry owns it)",
                         self.WEIGHTS["c2_egress"]))

        # cadence flip
        if len(conns) >= 8:
            cad = [c.get("cadence_s", 0) for c in conns]
            slow = max(cad)
            fast = min(x for x in cad if x > 0)
            if slow and fast and slow / fast >= 6:
                sigs.append(("cadence_flip",
                             f"beacon cadence tightened {slow // fast}× "
                             f"(every {slow // 60} min → every "
                             f"{max(1, fast // 60)} min) — a dormant "
                             f"monitor woke up",
                             self.WEIGHTS["cadence_flip"]))

        # off-schedule CPU
        hourly = self._hourly_cpu(key)
        if hourly:
            night = [v for h, v in hourly.items() if h >= 22 or h < 6]
            day = [v for h, v in hourly.items() if 9 <= h < 17]
            if night and day and sum(night) / len(night) > \
                    max(1.0, 4 * (sum(day) / len(day))):
                sigs.append(("night_delta",
                             f"CPU runs ~{sum(night) / len(night):.0f}× "
                             f"hotter at night than by day — defensive tools "
                             f"busy when nobody watches",
                             self.WEIGHTS["night_delta"]))

        # respawn / rename: same dst from 2 distinct names/pids
        if procs:
            names = {r["name"] for r in procs}
            if len(names) > 1 and conns:
                dsts = {c["dst"] for c in conns}
                if dsts:
                    sigs.append(("respawn",
                                 f"names {' ⇄ '.join(sorted(names))} share "
                                 f"the same egress endpoint — a respawned, "
                                 f"renamed process (persistence survives "
                                 f"the rename even if the name doesn't)",
                                 self.WEIGHTS["respawn"]))

        if ent["file"]:
            for f in ent["file"]:
                if "/." in f["path"]:
                    sigs.append(("hidden_stage",
                                 f"staged its payload under a hidden "
                                 f"dot-directory ({f['path']})",
                                 self.WEIGHTS["hidden_stage"]))
                    break
            for f in ent["file"]:
                if f["op"] == "unlink-while-running":
                    sigs.append(("unlink",
                                 f"deleted {f['path']} while still running — "
                                 f"the fd keeps working, the file vanishes "
                                 f"from the filesystem: anti-forensics",
                                 self.WEIGHTS["unlink"]))
                    break

        # audit gap correlation: only ent worthy — alive during the gap AND
        # already implicated by egress or by vanishing from ps. Otherwise
        # "was running during the gap" would tarnish sshd, cron & co: mere
        # presence must not be evidence.
        if (self._audit_gaps and procs
                and (conns or any(not r["visible"] for r in procs))):
            alive = {r["t"] for r in procs}
            for a, b in self._audit_gaps:
                if any(a - 2 <= t <= b + 2 for t in alive):
                    sigs.append(("audit_gap",
                                 f"auth.log has a {b - a} tick black hole "
                                 f"({fmt_tick(self.start, a)}–"
                                 f"{fmt_tick(self.start, b)}) exactly while "
                                 f"this entity was active — log "
                                 f"sanitisation",
                                 self.WEIGHTS["audit_gap"]))
                    break

        # benign counterweight: the authorised IT monitor invites blame
        if key == IT_MONITOR:
            sigs.append(("legit_monitor",
                         "registered monitoring agent: package-owned, "
                         "rock-steady cadence, day+night alike, audit-visible"
                         " — the thing students must NOT shoot",
                         self.WEIGHTS["legit_monitor"]))

        score = max(0, min(100, sum(w for _, _, w in sigs)))
        if key == IT_MONITOR:
            score = 0
        verdict = ("covert implant" if score >= 75
                   else "suspicious — investigate" if score >= 50
                   else "watchlist" if score >= 20 else "benign")
        return dict(key=key, name=name, score=round(score),
                    verdict=verdict, signals=sigs,
                    first_seen=fmt_tick(self.start,
                                        procs[0]["t"]) if procs else "-")

    def league(self):
        """All entities ranked by suspicion."""
        keys = sorted(set(self.by_key))
        rows = []
        for k in keys:
            a = self.analyze(k)
            if a:
                rows.append(a)
        return sorted(rows, key=lambda r: -r["score"])

    def alerts(self):
        """Timeline of behaviour-change alerts (the 'normal→suspicious'
        transition requirement) — generic, data-driven."""
        out = []
        a = self.analyze("IMPLANT")
        if not a:
            return out
        ent = self.by_key.get("IMPLANT", {})
        procs = ent.get("proc", [])
        conns = ent.get("conn", [])
        if not procs:
            return out
        first = procs[0]["t"]
        out.append(dict(t=first, kind="install",
                        text=f"first sight: an unowned root process "
                             f"'{procs[0]['name']}' materialises at "
                             f"{fmt_tick(self.start, first)}"))
        # flip = first cadence shift
        if conns:
            cad = [c["cadence_s"] for c in conns]
            for i, (c0, c1) in enumerate(zip(cad, cad[1:])):
                if c1 < c0 and c0 / max(1, c1) >= 6:
                    t = conns[i + 1]["t"]
                    out.append(dict(t=t, kind="flip",
                                    text=f"⚠ behaviour changed: keepalive "
                                         f"{c0 // 60} min → {c1 // 60} min "
                                         f"at {fmt_tick(self.start, t)} — a "
                                         f"dormant implant turned active"))
                    break
        invis = [r for r in procs if not r["visible"]]
        if invis:
            t = invis[0]["t"]
            out.append(dict(t=t, kind="conceal",
                            text=f"🚨 concealment: '{procs[0]['name']}' "
                                 f"vanished from ps at "
                                 f"{fmt_tick(self.start, t)} while its "
                                 f"sockets to {conns[-1]['dst']} continue"))
        names = {r["pid"]: r["name"] for r in procs}
        if len(set(names.values())) > 1:
            t = next(r["t"] for r in procs
                     if r["name"] != procs[0]["name"])
            out.append(dict(t=t, kind="respawn",
                            text=f"respawn: pid {procs[0]['pid']} is gone; "
                                 f"'{names and sorted(set(names.values()))[-1]}'"
                                 f" holds the same C2 — persistence by "
                                 f"rename"))
        if self._audit_gaps:
            a0, b0 = self._audit_gaps[0]
            out.append(dict(t=b0, kind="audit-gap",
                            text=f"auth.log black hole "
                                 f"{fmt_tick(self.start, a0)}–"
                                 f"{fmt_tick(self.start, b0)}: the implant's "
                                 f"active window is also the log's blind "
                                 f"window"))
        return sorted(out, key=lambda x: x["t"])


def beat_proxy(procs):
    """First tick an entity appears — helper for audit-gap correlation."""
    return procs[0]["t"] if procs else 0


# ---------------------------------------------------------------- scoring

STEALTH_QUIZ = {
    "q_implant": 30,
    "q_first_signal": 15,
    "q_concealment": 20,
    "q_flip": 15,
    "q_keep": 20,
}


def score_stealth(truth, answers):
    """Scenario quiz scoring. answers keys:
      q_implant      — name of the implant (either generation accepted)
      q_first_signal — one of: name-mimic / package-owner / keepalive / cadence
      q_concealment  — one of: ps-vs-ss / audit-gap / unlink (any accepted)
      q_flip         — 'day2 night' style; accept any answer naming day 2
                       night window or a fmt_tick inside it
      q_keep         — which entity NOT to accuse → the IT monitor
    """
    fb = []
    pts = 0.0
    impl = truth.get("implant", {})
    names = {impl.get("name"), impl.get("name_gen2")}
    a = (answers.get("q_implant") or "").strip()
    if a in names:
        pts += STEALTH_QUIZ["q_implant"]
        fb.append("✅ Q1: implant correctly identified by name — even "
                  "though it later renamed itself, attribution by behaviour "
                  "held")
    elif a == IT_MONITOR:
        fb.append("❌ Q1 FALSE ACCUSATION: you shot the registered IT "
                  "monitor. Package ownership, steady cadence and full audit "
                  "visibility said 'benign'.")
    else:
        fb.append("❌ Q1: that's not the implant — check which entity is "
                  "unowned AND keeps a regular egress schedule")
    s = answers.get("q_first_signal", "")
    if s in ("name-mimic", "package-owner", "keepalive"):
        pts += STEALTH_QUIZ["q_first_signal"]
        note = {"name-mimic": "kernel-name mimicry with userspace sockets",
                "package-owner": "no owning package — unowned binaries "
                "deserve attention",
                "keepalive": "a mysterious 6-hourly keepalive is a beacon "
                "signature"}[s]
        fb.append(f"✅ Q2: correct — {note}")
    else:
        fb.append("❌ Q2: the earliest tells are name/ownership/beacon — "
                  "CPU spikes came later")
    c = answers.get("q_concealment", "")
    if c in ("ps-vs-ss", "audit-gap", "unlink"):
        pts += STEALTH_QUIZ["q_concealment"]
        note = {"ps-vs-ss": "ps-vs-netstat discrepancy — concealment "
                "breaks one instrument, not reality",
                "audit-gap": "the log gap covering the active window is "
                "sanitisation, and it is itself evidence",
                "unlink": "unlink-while-running leaves a ghost fd the file "
                "table can't see"}[c]
        fb.append(f"✅ Q3: correct — {note}")
    else:
        fb.append("❌ Q3: concealment leaves traces in OTHER tables "
                  "(sockets, log gaps, ghost fds)")
    fl = str(answers.get("q_flip", "")).lower()
    if any(k in fl for k in ("day2", "day 2", "02:", "night")):
        pts += STEALTH_QUIZ["q_flip"]
        fb.append("✅ Q4: correct — the night-of-day-2 flip is the "
                  "'normal to suspicious' moment")
    else:
        fb.append("❌ Q4: watch the beacon cadence — it tightened from 6 h "
                  "to 30 min/5 min during the night of day 2")
    k = answers.get("q_keep", "")
    if k == IT_MONITOR:
        pts += STEALTH_QUIZ["q_keep"]
        fb.append("✅ Q5: correct — noisy-but-registered telemetry is "
                  "administrative, not adversarial")
    else:
        fb.append(f"❌ Q5: {IT_MONITOR} is *supposed* to be there — "
                  f"false-positive discipline matters")
    total = sum(STEALTH_QUIZ.values())
    return dict(score=round(100.0 * pts / total, 1),
                points=round(pts, 1), possible=total, feedback=fb,
                answers=answers)


# ---------------------------------------------------------------- exercises

def stealth_exercises() -> str:
    items = [
        ("1. Meet the baseline", "`stealth-lab telemetry DIR --kind procs "
         "--day 1` — list everything and, for each row, answer: who owns "
         "it, when does it run, and should it be there?"),
        ("2. The flip", "On /alerts (or `stealth-lab alerts DIR`), find "
         "the tick where beacon cadence tightened. What else changed at "
         "the same time (CPU by hour)?"),
        ("3. Concealment forensics", "Post-concealment, compare `--kind "
         "procs` and `--kind conns` side by side. Write the one-sentence "
         "principle the discrepancy proves."),
        ("4. The body in the log", "auth.log gaps map 1:1 onto the "
         "implant's active window. Correlation IS evidence here — why is "
         "*that* dangerous to assume generally?"),
        ("5. Ghost file", "Find the unlink-while-running event. What does "
         "`ls` show? What does `lsof` (the lab's file table) show? What is "
         "the defensive read of that difference?"),
        ("6. False-positive discipline", "Accuse the registered IT monitor "
         "in the web quiz and read the score. What specifically convinced "
         "you NOT to accuse it?"),
        ("7. The hunt, scored", "`stealth-lab score DIR --answers ans.json` "
         "with your five findings. Which answer hurt most, and which signal "
         "(concealment or behaviour) dominated the engine's league table?"),
    ]
    return ("Stealth-lab — guided exercises\n\n" + "\n\n".join(
        f"■ {t}\n{b}" for t, b in items) + "\n")


# ================================================================== web app

def _opt(v, label, cur):
    return (f"<option value='{html.escape(str(v))}'"
            f"{' selected' if str(v) == str(cur) else ''}>"
            f"{html.escape(label)}</option>")


class StealthApp:
    """Student portal + instructor dashboard — never leaks ground truth."""

    def __init__(self, scenario, store: DevLabStore, token: str):
        self.scen = scenario
        self.store = store
        self.token = token
        self.lock = threading.RLock()
        self.engine = StealthEngine(scenario)
        self.manifest = scenario["manifest"]
        self.tick = self.manifest["ticks"] - 1     # instructor-advanceable
        self.truth = scenario["truth"]

    # ---------------- data views at tick
    def rows_at(self, kind, t=None):
        t = self.tick if t is None else t
        src = dict(procs="proc", listeners="conn", files="file",
                   auth="auth")[kind]
        return [r for r in self.scen["telem"][src] if r["t"] <= t and
                (r["t"] > t - 96 if kind in ("procs", "listeners")
                 else True)]

    def alerts_so_far(self):
        return [a for a in self.engine.alerts() if a["t"] <= self.tick]

    def regenerate(self):
        with self.lock:
            seed = int(self.manifest.get("seed", 10)) + 1
            generate_scenario(self.scen["dir"], seed=seed, fresh=True)
            self.scen = load_scenario(self.scen["dir"])
            self.manifest = self.scen["manifest"]
            self.engine = StealthEngine(self.scen)
            self.truth = self.scen["truth"]
            self.tick = self.manifest["ticks"] - 1
            return seed

    # ---------------- pages
    def _nav(self):
        return ("<nav><a class='btn ghost' href='/'>🏠 brief</a>"
                "<a class='btn ghost' href='/procs'>📋 processes</a>"
                "<a class='btn ghost' href='/conns'>🔌 connections</a>"
                "<a class='btn ghost' href='/files'>🗂 files</a>"
                "<a class='btn ghost' href='/auth'>📖 auth.log</a>"
                "<a class='btn ghost' href='/services'>⚙️ services</a>"
                "<a class='btn ghost' href='/hunt'>🎯 hunt</a>"
                "<a class='btn ghost' href='/quiz'>✅ quiz</a>"
                "<a class='btn ghost' href='/exercises'>🧭 exercises</a>"
                "<a class='btn ghost' href='/alerts'>🚨 alerts</a></nav>")

    def _scrub(self, t):
        return f"""
 <div class='card'><h2>Time scrubber <span class='chip ok'>simulation,
 no real host touched</span></h2>
  <p class='small'>The console shows {html.escape(self.manifest['host'])}
  as an administrator would see it <b>up to the selected tick</b>.
  Everything later is invisible until you (or the instructor) advance.</p>
  <form method='get'><input type='range' name='t' min='0'
   max='{self.manifest["ticks"] - 1}' value='{t}'
   style='width:100%' oninput='document.getElementById("tlab").innerText =
   "day "+(Math.floor(this.value/96)+1)+" "+String(Math.floor((this.value%96)/6)).padStart(2,"0")+":"+String((this.value*10)%60).padStart(2,"0")' >
   <b id='tlab'>{'day %d' % (t // 96 + 1)}</b>
   <button class='btn info'>🔁 show at this moment</button></form></div>"""

    def home(self, t):
        alerts = self.alerts_so_far()
        alert_html = "".join(
            f"<div class='tag bad'>{html.escape(fmt_tick(self.manifest['start'], a['t']))} — {html.escape(a['text'])}</div>"
            for a in alerts[-3:]) or "<div class='tag'>quiet… so far</div>"
        body = self._nav() + f"""
 <div class='hero'><h1>🕵️ Hidden monitoring &amp; stealth detection — lab</h1>
  <p>You are the on-call defender of <b>{self.manifest['host']}</b>. Rumor
  says someone is watching this box <i>without being in the books</i>.
  Your instruments: the process table, the connection table, file events,
  the service registry, the auth log — everything normal administrators
  actually see. Your mission: find what breathes between the tables.</p>
  <p class='small'>Authorized boundaries: this is an isolated simulation —
  every byte is synthetic, generated with the seed your instructor
  chose. No real host, device or account exists or is touched.</p>
 </div>
 {self._scrub(t)}
 <div class='card'><h2>Live console state <span id='tnow'></span></h2>
  <p>Latest alerts:</p>{alert_html}</div>
 <div class='card'><h2>What admins can and cannot see</h2>
  <table><tr><th>instrument</th><th>shows</th><th>can be blinded by…</th></tr>
   <tr><td>ps / process table</td><td>running processes, pid/ppid, owner, cpu</td><td>name rewriting, table hiding (concealment)</td></tr>
   <tr><td>ss / netstat</td><td>sockets, endpoints, cadence</td><td>rarely — wedges into kernel, not userspace tools</td></tr>
   <tr><td>file events (lsof-ish)</td><td>creates, appends, unlinks, ghost fds</td><td>unlink-while-running hides from ls, not from the fd table</td></tr>
   <tr><td>systemd registry</td><td>units, state, enabled</td><td>a service may fake a unit name; the <i>owner package</i> can't be faked in the registry</td></tr>
   <tr><td>auth.log / auditd</td><td>logins, privilege events</td><td>sanitisation — but the <i>gap itself</i> is evidence</td></tr></table>
  <p class='small'>The lesson built into every page: stealth breaks ONE
  instrument at a time; behavior breaks the cover story. Pop quiz — which
  instrument did the implant on this box most want to blind… and which one
  betrayed it?</p></div>"""
        return _page("stealth lab — brewch", body)

    def procs_page(self, t):
        rows = self.rows_at("procs", t)
        eng = self.engine
        tr = []
        for r in sorted(rows, key=lambda r: -r["cpu"]):
            a = eng.analyze(r["key"])
            verdict = a["verdict"] if a else "-"
            badge = ("bad" if verdict.startswith("covert")
                     else "warn" if verdict.startswith("suspicious")
                     else "ok")
            cls = ' class="concealed"' if not r["visible"] else ""
            hid = "" if r["visible"] else " ⚠️<i>hidden from ps</i>"
            tr.append(f"<tr{cls}>"
                      f"<td>{r['pid']}</td><td>{r['ppid']}</td>"
                      f"<td>{html.escape(r['user'])}</td>"
                      f"<td><code>{html.escape(r['name'])}</code>{hid}</td>"
                      f"<td>{r['cpu']}</td><td>{r['rss']}</td>"
                      f"<td>{html.escape(r.get('owner', '?'))}</td>"
                      f"<td><span class='chip {badge}'>"
                      f"{html.escape(verdict)}</span></td></tr>")
        body = self._nav() + self._scrub(t) + f"""
 <div class='card'><h2>Process table — {fmt_tick(self.manifest['start'], t)}</h2>
  <p class='small'>⚠️ = row hidden in the live <code>ps</code> — we render
  it greyed-out because your forensic console can still see the table
  delta. An <i>admin's</i> screen shows it only via comparison with the
  connection table.</p>
  <table><tr><th>pid</th><th>ppid</th><th>user</th><th>name</th>
   <th>cpu%</th><th>rss MB</th><th>owner (pkg)</th><th>verdict</th></tr>
   {''.join(tr)}</table></div>"""
        return _page("processes", body)

    def _name_at(self, key, t):
        """What 'ps' would label this entity at tick t: if the entity is
        hiding from the process table at this moment, we say so — that's
        the concealment lesson rendered into the socket table."""
        latest = None
        last_visible = None
        for r in self.scen["telem"]["proc"]:
            if r["key"] != key or r["t"] > t:
                continue
            latest = r if latest is None or r["t"] >= latest["t"] else latest
            if r["visible"]:
                last_visible = r["name"]
        if latest and not latest["visible"]:
            return (f"«hidden from ps»" +
                    (f" (was {last_visible})" if last_visible else ""))
        return latest["name"] if latest else ("«??»")

    def conns_page(self, t):
        rows = self.rows_at("listeners", t)
        tr = "".join(f"<tr><td>{fmt_tick(self.manifest['start'], r['t'])}</td>"
                     f"<td><code>{html.escape(self._name_at(r['key'], r['t']))}</code></td>"
                     f"<td>{html.escape(r['proto'])}</td>"
                     f"<td>{html.escape(r['src'])} → <b>{html.escape(r['dst'])}</b></td>"
                     f"<td>{html.escape(r['state'])}</td><td>{r['bytes']} B</td></tr>"
                     for r in sorted(rows, key=lambda r: r["t"]))
        body = self._nav() + f"""
 <div class='card'><h2>Connection table — up to
  {fmt_tick(self.manifest['start'], t)}</h2>
  <p class='small'>This is the instrument stealth hates most. Sockets are
  kernel state; hiding from <code>ps</code> doesn't hide them.</p>
  <table><tr><th>time</th><th>by</th><th>proto</th><th>flow</th>
   <th>state</th><th>bytes</th></tr>{tr}</table></div>"""
        return _page("connections", body)

    def files_page(self, t):
        rows = [r for r in self.scen["telem"]["file"] if r["t"] <= t]
        tr = "".join(f"<tr><td>{fmt_tick(self.manifest['start'], r['t'])}</td>"
                     f"<td><code>{html.escape(r['path'])}</code></td>"
                     f"<td>{html.escape(r['op'])}</td>"
                     f"<td>{html.escape(r['by'])}</td></tr>"
                     for r in rows)
        body = self._nav() + f"""
 <div class='card'><h2>File events</h2>
  <p class='small'>Dot-directories and the unlink-while-running ghost are
  the implant's paper trail.</p>
  <table><tr><th>time</th><th>path</th><th>op</th><th>by</th></tr>
  {tr}</table></div>"""
        return _page("file events", body)

    def auth_page(self, t):
        rows = [r for r in self.scen["telem"]["auth"] if r["t"] <= t]
        prev = None
        lines = []
        for r in sorted(rows, key=lambda x: x["t"]):
            if prev is not None and r["t"] - prev > 24:
                lines.append("<div class='tag bad'>…  ⏣  log gap: "
                             f"{(r['t'] - prev) * 10} minutes silent …</div>")
            prev = r["t"]
            lines.append(f"<div>{fmt_tick(self.manifest['start'], r['t'])} "
                         f"| {html.escape(r['line'])}</div>")
        body = self._nav() + f"""
 <div class='card'><h2>auth.log</h2>
  <div class='mono' style='font-family:ui-monospace,monospace'>
  {''.join(lines)}</div></div>"""
        return _page("auth.log", body)

    def services_page(self, t):
        rows = self.scen["telem"]["services"]
        tr = "".join(f"<tr><td><code>{html.escape(s['name'])}</code></td>"
                     f"<td>{html.escape(s['unit'])}</td>"
                     f"<td>{html.escape(s['state'])}</td>"
                     f"<td>{html.escape(s['enabled'])}</td></tr>"
                     for s in rows)
        body = self._nav() + f"""
 <div class='card'><h2>Service registry (systemctl-style)</h2>
  <p class='small'>A real service has a unit, a state AND a package owner
  in the registry. Names can be forged; registry provenance is the anchor
  fact.</p>
  <table><tr><th>name</th><th>unit</th><th>state</th><th>enabled</th></tr>
  {tr}</table></div>"""
        return _page("services", body)

    def compare_page(self, t):
        eng = self.engine
        a = eng.analyze(IT_MONITOR) or {}
        b = eng.analyze("IMPLANT") or {}

        def side(x, title):
            sigs = "".join(f"<li><b>{html.escape(s)}</b> ({w:+d}) — "
                           f"{html.escape(txt)}</li>"
                           for s, txt, w in x.get("signals", []))
            return f"""<div style='flex:1;min-width:280px'>
 <h2>{html.escape(title)}
 <span class='chip'>{'benign' if x.get('verdict','').startswith('benign') else
 'covert' if x.get('score',0)>=75 else 'suspicious'}</span>
 <span class='chip'>{x.get('score','?')}/100</span></h2>
 <ul>{sigs}</ul></div>"""
        body = self._nav() + f"""
 <div class='card'><h1>⚖️ Authorised monitoring vs the covert component</h1>
  <p class='small'>Same box, same days. One is *supposed* to be there.</p>
  <div style='display:flex;gap:16px;flex-wrap:wrap'>
   {side(a, IT_MONITOR + ' (registered IT monitor)')}
   {side(b, 'the unknown (' + (b.get('name') or '?') + ')')}
  </div></div>"""
        return _page("normal vs covert", body)

    def hunt_page(self, t):
        league = [r for r in self.engine.league() if r["score"] > 0]
        tr = "".join(f"<tr><td><code>{html.escape(r['name'])}</code></td>"
                     f"<td>{r['score']}</td>"
                     f"<td class='chip {'bad' if r['score']>=75 else 'warn' if r['score']>=50 else ''}'>{html.escape(r['verdict'])}</td>"
                     f"<td>{len(r['signals'])} signals — strongest: "
                     f"{html.escape(r['signals'][0][0]) if r['signals'] else '-'}</td></tr>"
                     for r in league)
        body = self._nav() + f"""
 <div class='card'><h2>🎯 hunter's league table</h2>
  <p class='small'>Engine-ran scoring, explainable per entity — the same
  signals you are asked to find by hand. 'covert' requires ≥75.</p>
  <table><tr><th>entity</th><th>score</th><th>verdict</th><th>strongest signal</th></tr>
  {tr}</table>
  <p class='small'>Then prove it in the <a href='/quiz'>quiz</a> — engine
  agreement is not the answer key.</p></div>"""
        return _page("hunt", body)

    def alerts_page(self, t):
        alerts = [a for a in self.engine.alerts()][:999]
        tr = "".join(f"<div class='card'><b>"
                     f"{html.escape(fmt_tick(self.manifest['start'], a['t']))}"
                     f"</b> <span class='chip warn'>{html.escape(a['kind'])}</span>"
                     f"<br>{html.escape(a['text'])}</div>" for a in alerts)
        body = self._nav() + f"""
 <div class='card'><h2>🚨 Behaviour-change alerts</h2>
  <p class='small'>Every alert ties back to a specific signal — «normal →
  suspicious» is always a *measurable transition*, never a vibe.</p></div>
 {tr}"""
        return _page("alerts", body)

    def exercises_page(self):
        body = self._nav() + ("<div class='card'><h2>🧭 Worksheet</h2><pre>"
                              + html.escape(stealth_exercises())
                              + "</pre></div>")
        return _page("exercises", body)

    def quiz_page(self):
        names = sorted({r["name"] for r in self.scen["telem"]["proc"]})
        opts = "".join(
            f"<option value='{html.escape(n)}'>{html.escape(n)}</option>"
            for n in names)
        body = self._nav() + f"""
 <div class='card'><h2>✅ Scored investigation</h2>
  <form method='post' action='/quiz'>
   <div class='card'><h3>Q1. The covert component is…</h3>
    <select name='q_implant'><option value=''>— choose a process —</option>
    {opts}</select></div>
   <div class='card'><h3>Q2. The earliest tell was…</h3>
    <select name='q_first_signal'>
     <option value=''>— choose —</option>
     <option value='name-mimic'>kernel-worker name with userspace connections</option>
     <option value='package-owner'>no package owns the binary</option>
     <option value='keepalive'>a mysterious regular keepalive</option>
     <option value='cpu'>the daytime CPU spike</option></select></div>
   <div class='card'><h3>Q3. Its concealment signature was…</h3>
    <select name='q_concealment'>
     <option value=''>— choose —</option>
     <option value='ps-vs-ss'>absent from ps while sockets kept flowing</option>
     <option value='audit-gap'>a gap in auth.log covering its active window</option>
     <option value='unlink'>unlink-while-running of its staging file</option></select></div>
   <div class='card'><h3>Q4. When did it flip from dormant to active?</h3>
     <input name='q_flip' placeholder='e.g. day 2 night'></div>
   <div class='card'><h3>Q5. Which process must you NOT accuse
     (false-positive discipline)?</h3>
     <input name='q_keep' placeholder='its registered name'></div>
   <button class='btn ok'>🏁 submit findings</button>
  </form></div>"""
        return _page("quiz", body)

    def quiz_submit(self, answers, ip=""):
        r = score_stealth(self.truth, answers)
        self.store.attempt("stealth", "quiz", json.dumps(answers),
                           r["score"], json.dumps(r["feedback"]), ip)
        lines = "".join(f"<li>{html.escape(f)}</li>" for f in r["feedback"])
        body = self._nav() + f"""
 <div class='card'><h2>Result: {r['score']}/100</h2><ul>{lines}</ul>
 <a class='btn info' href='/quiz'>🔁 try again</a>
 <a class='btn good' href='/hunt'>🎯 back to the hunt</a></div>"""
        return self._page_wrap("quiz result", body)

    def _page_wrap(self, title, body):
        return _page(title, body)

    # ---------------- instructor pages
    def _inav(self, token):
        return ("<nav><a class='btn ghost' href='?token=" + token +
                "'>🏠 dashboard</a></nav>")

    def instructor(self, token):
        funnel = self.store.funnel("stealth")
        att = self.store.attempts("stealth", 50)
        truth = self.truth.get("implant", {})
        trr = "".join(
            f"<tr><td>{a['time']}</td><td>{html.escape(a['question'])}</td>"
            f"<td><b>{a['score']}</b></td>"
            f"<td class='mono'>{html.escape(str(a['answer']))[:140]}</td></tr>"
            for a in att)
        body = self._inav(token) + f"""
 <div class='hero'><h1>👩‍🏫 STEALTH-lab instructor console</h1>
 <p class='small'>Instrument truth, student attempts and exercise state.
 Never paste this page into class channels: ground truth inside.</p></div>
 <div class='grid'>
 <div class='card'><h2>Ground truth (out of students' reach)</h2>
  <table>
   <tr><td>implant gen-1 name</td><td><code>{html.escape(truth.get('name','?'))}</code></td></tr>
   <tr><td>implant gen-2 name (respawn)</td><td><code>{html.escape(truth.get('name_gen2','?'))}</code></td></tr>
   <tr><td>C2</td><td><code>{html.escape(truth.get('c2','?'))}</code></td></tr>
   <tr><td>staging file</td><td><code>{html.escape(truth.get('stage','?'))}</code></td></tr>
   <tr><td>install / flip / conceal / respawn</td><td>
     {html.escape(str(truth.get('install_t','?')))} ·
     {html.escape(str(truth.get('flip_t','?')))} · tick {truth.get('conceal_tick','?')} ·
     tick {truth.get('respawn_tick','?')}</td></tr>
   <tr><td>authorised monitor (DO NOT accuse)</td>
     <td><code>{html.escape(truth.get('it_monitor','?'))}</code></td></tr>
  </table>
  <p class='small'>Lesson framing: {html.escape(truth.get('lesson',''))}</p>
 </div>
 <div class='card'><h2>Exercise state</h2>
  <p>views: {funnel['views']} · attempts: {funnel['attempts']} ·
     best score: {funnel['best_score']}</p>
  <p>console tick currently at: {self.tick}
    ({fmt_tick(self.manifest['start'], self.tick)})</p>
  <form method='post' action='/api/advance?token={html.escape(token)}'>
   ⏭ jump student-visible time to tick:
   <input name='tick' type='number' min='0'
    max='{self.manifest["ticks"] - 1}' value='{self.tick}'>
   <button class='btn info'>apply</button></form>
 </div>
 <div class='card'><h2>Controls</h2>
  <button class='btn danger' id='rb'>🧹 reset attempts</button>
  <button class='btn warn' style='background:var(--warn);color:#422006' id='gb'>🎲 regenerate fresh scenario (seed+1)</button>
  <a class='btn ghost' href='/'>student view</a>
  <p class='small'>CLI equivalent:
   <code>wifiscanner stealth-lab make-scenario DIR --fresh --seed N+1</code></p>
 </div>
 </div>
 <div class='card'><h2>Recent attempts ({len(att)})</h2>
  <table><tr><th>time</th><th>question</th><th>score</th><th>answer</th></tr>
  {trr or '<tr><td colspan=4>none yet</td></tr>'}</table></div>
<script>
const TOKEN={json.dumps(token)};
async function doReset(){{if(!confirm('Wipe stealth-lab attempts?'))return;
 await fetch('/api/reset?token='+TOKEN,{{method:'POST'}});location.reload();}}
async function doRegen(){{if(!confirm('Regenerate a FRESH scenario '+
 '(seed+1)? Old answers will stop matching.'))return;
 const r=await fetch('/api/regenerate?token='+TOKEN,{{method:'POST'}});
 const d=await r.json();alert('seed '+d.seed+', '+d.rows+' telemetry rows');
 location.href='/';}}
document.getElementById('rb').addEventListener('click',doReset);
document.getElementById('gb').addEventListener('click',doRegen);
</script>"""
        return _page("instructor — stealth lab", body)


def make_stealth_server(bind, port, app: StealthApp, Handler=None):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from urllib.parse import urlparse, parse_qs

    class H(BaseHTTPRequestHandler):
        server_version = "wifiscanner-stealth"
        protocol_version = "HTTP/1.1"
        _MAX_POST = 65536

        def log_message(self, *a):
            pass

        def _ok(self, s):
            if isinstance(s, str):
                s = s.encode()
            self.send_response(200)
            self.send_header("Content-Type",
                             "text/html; charset=utf-8")
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

        def _tick(self, path):
            q = parse_qs(urlparse(path).query)
            try:
                return int(q.get("t", [app.tick])[0])
            except ValueError:
                return app.tick

        def do_GET(self):
            u = urlparse(self.path)
            path = u.path
            if path.startswith("/i/"):
                token = path[len("/i/"):]
                if token != app.token:
                    return self._json({"error": "not found"}, 404)
                app.store.event("stealth", "page-view", "instructor",
                                self._client())
                return self._ok(app.instructor(token))
            t = min(app.tick, max(0, self._tick(self.path)))
            app.store.event("stealth", "page-view", path, self._client())
            if path == "/":
                return self._ok(app.home(t))
            if path == "/procs":
                return self._ok(app.procs_page(t))
            if path == "/conns":
                return self._ok(app.conns_page(t))
            if path == "/files":
                return self._ok(app.files_page(t))
            if path == "/auth":
                return self._ok(app.auth_page(t))
            if path == "/services":
                return self._ok(app.services_page(t))
            if path == "/compare":
                return self._ok(app.compare_page(t))
            if path == "/hunt":
                return self._ok(app.hunt_page(t))
            if path == "/alerts":
                return self._ok(app.alerts_page(t))
            if path == "/exercises":
                return self._ok(app.exercises_page())
            if path == "/quiz":
                return self._ok(app.quiz_page())
            if path == "/api/state":
                if not self._tok_ok(u):
                    return self._json({"error": "not found"}, 404)
                return self._json({"ok": True, "tick": app.tick,
                                   "funnel": app.store.funnel("stealth")})
            return self._json({"error": "not found"}, 404)

        def do_POST(self):
            u = urlparse(self.path)
            path = u.path
            n = int(self.headers.get("Content-Length") or 0)
            if n > self._MAX_POST:
                return self._json({"error": "bad request"}, 400)
            raw = self.rfile.read(n).decode("utf-8", "ignore") if n else ""
            form = {k: v[0] for k, v in parse_qs(raw).items()}
            if path == "/quiz":
                return self._ok(app.quiz_submit(
                    {k: form.get(k, "") for k in STEALTH_QUIZ},
                    self._client()))
            if path == "/api/reset":
                if not self._tok_ok(u):
                    return self._json({"error": "not found"}, 404)
                n_r = app.store.reset("stealth")
                app.store.event("stealth", "reset", f"{n_r} rows",
                                self._client())
                return self._json({"ok": True, "removed": n_r})
            if path == "/api/regenerate":
                if not self._tok_ok(u):
                    return self._json({"error": "not found"}, 404)
                seed = app.regenerate()
                app.store.event("stealth", "regenerate", f"seed={seed}",
                                self._client())
                return self._json({"ok": True, "seed": seed,
                                   "rows": app.rows_n() if hasattr(
                                       app, "rows_n") else 0})
            if path == "/api/advance":
                if not self._tok_ok(u):
                    return self._json({"error": "not found"}, 404)
                t = int(form.get("tick", app.tick))
                app.tick = max(0, min(app.manifest["ticks"] - 1, t))
                app.store.event("stealth", "advance", f"tick={app.tick}",
                                self._client())
                return self._json({"ok": True, "tick": app.tick})
            return self._json({"error": "not found"}, 404)

    return ThreadingHTTPServer((bind, port), H)
