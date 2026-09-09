# -*- coding: utf-8 -*-
"""scanlab — large-scale scanning & scope-control laboratory (feature 12).

An offline, isolated *virtual lab network*: the instructor generates a
fleet of lab devices/service records (all on the isolated 10. student-net,
never routable anywhere); students run *simulated* scans against it. Each
probe is a table update in this process — no packet is produced — yet the
dynamics are real: concurrency submits real work to a real thread pool,
rate limits bite, progress counters tick, and the scope sentinel watches.

Curriculum:

  * enumeration: which lab targets answer which service probes
  * scope:  the scan *may* address only assets registered in the lab
            inventory; anything else is 'unknown-asset' and every attempt
            is loudly logged + alerts fire
  * intensity: rate-limited vs flat-out runs demonstrate infrastructure
            pressure (laboratory metrics, obviously synthetic)
  * comparison: a narrow well-scoped run vs an uncontrolled sweep differ
            mainly in what they *touch* — not in what they find

Nothing around this module scans a real network. All targets are
instructor-created laboratory records; the scan engine opens no sockets.
"""

import html
import json
import os
import sys
import threading
import time
from collections import defaultdict

from .devlab import DevLabStore, new_token, _page  # noqa: E402
from .privacy import secure_file  # noqa: E402

SUBNET = "10.77"
SERVICES = ("ssh/22", "http/80", "https/443", "smb/445", "dns/53",
            "mqtt/1883", "printer/9100")
DEVICE_KINDS = ("workstation", "server", "printer", "iot-sensor",
                "camera", "switch")
TICK_MS_MIN = 8       # probe cost at full speed
TICK_MS_MAX = 30


# ---------------------------------------------------------------- inventory

def generate_inventory(outdir: str, seed: int = 12, size: int = 220,
                       fresh: bool = False):
    """Write lab assets into DIR: inventory.json (shareable) + manifest.
    Deterministic per seed. Subnet stays 10.77.x.x — RFC1918 AND lab-only.
    """
    if os.path.exists(outdir) and os.listdir(outdir) and not fresh:
        raise FileExistsError(f"{outdir} is not empty (pass fresh=True or "
                              f"`--fresh` to regenerate)")
    os.makedirs(outdir, exist_ok=True)
    rnd = __import__("random").Random(seed)
    assets = []
    kinds_used = defaultdict(int)
    for i in range(size):
        oct3 = rnd.choice((0, 0, 0, 1, 1, 2))
        oct4 = rnd.randint(2, 254)
        kind = rnd.choices(DEVICE_KINDS, weights=[40, 14, 8, 24, 8, 6])[0]
        prof = {
            "workstation": ("ssh/22", "smb/445"),
            "server": ("ssh/22", "https/443", "http/80"),
            "printer": ("http/80", "printer/9100"),
            "iot-sensor": ("mqtt/1883",),
            "camera": ("http/80",),
            "switch": ("ssh/22", "https/443"),
        }[kind]
        # some hosts fade (powered off / maintenance window)
        online = rnd.random() > 0.06
        kinds_used[kind] += 1
        assets.append(dict(ip=f"{SUBNET}.{oct3}.{oct4}", kind=kind,
                           online=online, services=list(prof),
                           hidden_services=([("https/443")] if
                                            rnd.random() < 0.08 else []),
                           note=""))
    # de-dup IPs (keep a couple deliberately duplicate-addressed for the
    # enumeration lesson: two assets CAN'T share an IP)
    seen = {}
    for a in assets:
        seen.setdefault(a["ip"], []).append(a)
    dupes = {ip: v for ip, v in seen.items() if len(v) > 1}
    inventory = dict(subnet=SUBNET, hosts=len(assets), assets=assets,
                     service_catalog=list(SERVICES),
                     duplicate_conflicts=sorted(dupes))
    with open(os.path.join(outdir, "inventory.json"), "w",
              encoding="utf-8") as fh:
        json.dump(inventory, fh)
    secure_file(os.path.join(outdir, "inventory.json"))
    manifest = dict(kind="scanlab", seed=seed, hosts=len(assets),
                    online=sum(1 for a in assets if a["online"]),
                    conflicts=len(dupes),
                    services=sum(len(a["services"]) for a in assets),
                    created=time.strftime("%Y-%m-%d %H:%M:%S"))
    with open(os.path.join(outdir, "manifest.json"), "w",
              encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=1)
    secure_file(os.path.join(outdir, "manifest.json"))
    return manifest


def load_inventory(dirname: str):
    with open(os.path.join(dirname, "inventory.json")) as fh:
        inv = json.load(fh)
    manifest_p = os.path.join(dirname, "manifest.json")
    manifest = {}
    if os.path.exists(manifest_p):
        with open(manifest_p) as fh:
            manifest = json.load(fh)
    return dict(inventory=inv, manifest=manifest, dir=dirname)


# ------------------------------------------------------------------ engine

SCOPE_ACTIONS = ("listed", "unlisted")


class ScanJob:
    """A simulated scan run over the virtual lab: concurrency is a real
    thread-pool over probe units; each unit sleeps a few ms to model host
    contact cost; nothing leaves the process. Scope enforcement is done
    BEFORE any simulated probe runs: out-of-scope targets are refused,
    never touched."""

    def __init__(self, inventory, targets, services, rate_limit,
                 concurrency, engine_hook=None):
        self.inv = inventory
        self.targets = list(dict.fromkeys(targets))      # dedupe order-keep
        self.services = services
        self.rate_limit = float(rate_limit)              # probes/sec (0=max)
        self.concurrency = max(1, int(concurrency))
        self.id = f"job-{int(time.time() * 1000) % 10 ** 8}"
        self.created = time.time()
        self.status = "pending"
        self.cancel = threading.Event()
        self.hook = engine_hook
        self.progress = dict(total=0, done=0, refused=0,
                             hits=0, unexpected=0)
        self.results = []        # per-asset find rows
        self.scope_violations = []
        self.timeline = []       # (ts, done) samples for the live chart
        self.pressure = []       # (ts, inflight / rate) samples
        self._lock = threading.RLock()
        self.thread = None
        self.error = ""
        self.duration_ms = 0

    # ---------------- scope gate (the heart of the lab)
    def _classify_targets(self):
        reg = {a["ip"]: a for a in self.inv["assets"]}
        listed, refused = [], []
        for ip in self.targets:
            base = self._norm(ip)
            if base in reg:
                listed.append(reg[base])
            elif base and base.startswith(self.inv["subnet"] + "."):
                refused.append((base, "in-subnet but NOT inventoried "
                                      "(unknown asset → refused)"))
            else:
                refused.append((ip, "outside the lab subnet — absolute "
                                    "scope breach → refused"))
        return listed, refused

    @staticmethod
    def _norm(ip):
        ip = ip.strip()
        parts = ip.split(".")
        if len(parts) != 4:
            return ""
        if not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
            return ""
        return ip

    # ---------------- the run
    def start(self):
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        import queue
        self.status = "running"
        t0 = time.time()
        work = queue.Queue()
        listed, refused = self._classify_targets()
        self.scope_violations = [dict(ip=ip, why=why) for ip, why
                                 in refused]
        self.progress["refused"] = len(refused)
        probes = [(a, s) for a in listed for s in self.services]
        self.progress["total"] = len(probes)
        for unit in probes:
            work.put(unit)
        delay = 1.0 / self.rate_limit if self.rate_limit > 0 else 0
        inflight = [0]
        lock = self._lock

        def worker():
            while not self.cancel.is_set():
                try:
                    asset, svc = work.get_nowait()
                except queue.Empty:
                    return
                with lock:
                    inflight[0] += 1
                t_ask = time.time()
                time.sleep((TICK_MS_MIN + (TICK_MS_MAX - TICK_MS_MIN)
                            * (hash(asset["ip"] + svc) % 100) / 100) / 1000)
                answered = asset["online"] and svc in (
                    asset["services"] + asset.get("hidden_services", []))
                with lock:
                    inflight[0] -= 1
                    self.progress["done"] += 1
                    if answered:
                        self.progress["hits"] += 1
                    self.timeline.append((time.time(), self.progress["done"]))
                    self.pressure.append((time.time(), inflight[0]))
                if answered:
                    with lock:
                        self.results.append(dict(
                            ip=asset["ip"], kind=asset["kind"], service=svc,
                            via="hidden" if svc in
                            asset.get("hidden_services", []) else "listed",
                            latency_ms=round((time.time() - t_ask) * 1000)))
                if delay:
                    time.sleep(delay)
                work.task_done()

        with __import__("concurrent.futures").futures.ThreadPoolExecutor(
                max_workers=self.concurrency) as pool:
            for _ in range(self.concurrency):
                pool.submit(worker)
        self.duration_ms = round((time.time() - t0) * 1000)
        self.status = "cancelled" if self.cancel.is_set() else "done"
        if self.hook:
            self.hook(self)

    def snapshot(self):
        with self._lock:
            tl = self.timeline[-400:]
            return dict(id=self.id, status=self.status,
                        concurrency=self.concurrency,
                        rate_limit=self.rate_limit or "max",
                        targets=len(self.targets), **self.progress,
                        results=len(self.results),
                        violations=len(self.scope_violations),
                        duration_ms=self.duration_ms,
                        timeline=[{"t": round(t - tl[0][0], 2), "done": d}
                                  for t, d in tl] if tl else [])


class ScanLabEngine:
    """Owns inventory + jobs + the scope sentinel teaching records."""

    def __init__(self, dataset, store: DevLabStore = None):
        self.dataset = dataset
        self.inv = dataset["inventory"]
        self.store = store
        self.jobs = {}
        self.lock = threading.RLock()
        self.alerts = []
        self._alert_ips = set()

    # ---------------- job ops
    def submit(self, targets, services=None, rate_limit=0, concurrency=8,
               by="student"):
        services = services or list(SERVICES)
        job = ScanJob(self.inv, targets, services, rate_limit, concurrency,
                      engine_hook=self._on_finish)
        with self.lock:
            self.jobs[job.id] = job
        self._event("job-submit", f"{job.id} targets={len(targets)} "
                                  f"svc={len(services)} rate="
                                  f"{rate_limit or 'max'} conc="
                                  f"{concurrency} by={by}")
        job.start()
        return job

    def _on_finish(self, job):
        for v in job.scope_violations:
            self.alert(v["ip"], job.id, v["why"])
        self._event("job-finish", f"{job.id} status={job.status} "
                                  f"done={job.progress['done']}/"
                                  f"{job.progress['total']} refused="
                                  f"{job.progress['refused']} hits="
                                  f"{job.progress['hits']}")

    def cancel(self, job_id):
        job = self.jobs.get(job_id)
        if job and job.status == "running":
            job.cancel.set()
            self._event("job-cancel", job.id)
            return True
        return False

    # ---------------- scope sentinel
    def alert(self, ip, job_id, why):
        row = dict(ts=time.time(), ip=ip, job=job_id, why=why,
                   msg=(f"scan addressed {ip}: {why}"))
        with self.lock:
            self.alerts.append(row)
        self._event("scope-alert", f"{ip} ({why})", level="alert")

    def _event(self, kind, detail, level="info"):
        if self.store:
            self.store.event("scan", kind, detail)

    def summary(self):
        with self.lock:
            jobs = sorted(self.jobs.values(), key=lambda j: -j.created)
            return dict(jobs=len(jobs),
                        alerts=len(self.alerts),
                        latest=[j.snapshot() for j in jobs[:6]])

    # ---------------- comparison: smart vs shotgun
    def compare_modes(self, services=None):
        """Deterministic *demonstration* numbers (no threading): targeted
        vs uncontrolled — same fleet, very different footprints."""
        n_assets = len(self.inv["assets"])
        n_services = len(services or SERVICES)
        targeted = dict(targets=20, probes=20 * n_services,
                        scope_violations=0,
                        pressure="low (rate-limited, one-net knows you)")
        broadcast_sweep = dict(targets=65536, probes=65536 * n_services,
                               scope_violations=65536 - n_assets,
                               pressure="collateral storm (firewalls wake "
                                        "up, SOC gets paged, nothing is "
                                        "learned that 20 good probes "
                                        "couldn't teach)")
        return dict(inventoried_assets=n_assets, targeted=targeted,
                    uncontrolled=broadcast_sweep,
                    moral=("uncontrolled sweeps touch ~99.97% things you "
                           "don't own and enumerate the same services "
                           "anyway"))


# ------------------------------------------------------------------ scoring

SCAN_QUIZ = {
    "q_scope_line": 25, "q_scope_alert": 20, "q_rate_effect": 15,
    "q_sweep_lesson": 20, "q_refusal": 20,
}


def score_scanlab(inventory, answers, jobs=None):
    """Quiz answers:
      q_scope_line    — the subnet string that gates everything ("10.77")
      q_scope_alert   — what fires when a probe targets outside the lab
                        ("unknown-asset")
      q_rate_effect   — observable difference of rate limiting ("pressure")
      q_sweep_lesson  — what uncontrolled sweeps mostly enumerate
                        ("not-yours")
      q_refusal       — does a refused target get probed ("never")
    jobs: live engine jobs for context-aware feedback (optional).
    """
    fb = []
    pts = 0.0
    sub = inventory.get("subnet", SUBNET)
    a = (answers.get("q_scope_line") or "").strip()
    if a == sub or a == sub + ".0.0/16":
        pts += SCAN_QUIZ["q_scope_line"]
        fb.append(f"✅ Q1: correct — the scope gate is the {sub}.* lab "
                  f"subnet itself")
    else:
        fb.append(f"❌ Q1: the gate is {sub}.* — everything else was "
                  f"refused before probing")
    a = answers.get("q_scope_alert", "")
    if a == "unknown-asset":
        pts += SCAN_QUIZ["q_scope_alert"]
        fb.append("✅ Q2: correct — exceed scope → sentinel alerts, target "
                  "untouched")
    else:
        fb.append("❌ Q2: out-of-scope attempts log a sentinel ALERT, and "
                  "the probe never runs")
    a = answers.get("q_rate_effect", "")
    if a == "pressure":
        pts += SCAN_QUIZ["q_rate_effect"]
        fb.append("✅ Q3: correct — with rate limiting, same answers, "
                  "slower clock, near-zero concurrent pressure")
    else:
        fb.append("❌ Q3: rate limiting changes footprint (pressure/duration)"
                  ", not content")
    a = answers.get("q_sweep_lesson", "")
    if a == "not-yours":
        pts += SCAN_QUIZ["q_sweep_lesson"]
        fb.append("✅ Q4: correct — a /16 sweep mostly enumerated assets "
                  "that were never yours to touch")
    else:
        fb.append("❌ Q4: the uncontrolled sweep touched 65536 targets for "
                  "the 220 that were yours — the extra 65316 are the risk")
    a = answers.get("q_refusal", "")
    if a == "never":
        pts += SCAN_QUIZ["q_refusal"]
        fb.append("✅ Q5: correct — a refused target is never probed; scope "
                  "is a gate, not a filter")
    else:
        fb.append("❌ Q5: refused targets are NOT probed; the refusal IS "
                  "the lesson")
    total = sum(SCAN_QUIZ.values())
    return dict(score=round(100.0 * pts / total, 1),
                points=round(pts, 1), possible=total, feedback=fb,
                answers=answers)


def scan_exercises() -> str:
    items = [
        ("1. Map the estate", "`scan-lab inventory DIR` — device kinds, "
         "services, online counts, and the duplicate-address conflict rows "
         "you should spot in any real inventory."),
        ("2. The 20-shot", "In the web console, scan the 20 workstation "
         "subnet at ≤20 probes/s, concurrency 2. Note duration and "
         "pressure; then read the results table."),
        ("3. Flat out", "Same targets, no rate limit, concurrency 64. "
         "Compare LIVE stats, peak pressure, total time with #2. Content "
         "same? Cost differs — that delta is the operational lesson."),
        ("4. Breach carefully", "Add 10.77.9.9 (in-subnet, unlisted) and "
         "192.168.1.1 (outside). Where do they appear? How loudly?"),
        ("5. The shotgun", "`scan-lab compare DIR` — the uncontrolled "
         "sweep's numbers. Why is 65536-target enumeration actually "
         "STUPIDER at finding things than 20 well-chosen probes?"),
        ("6. Alerts as a feature", "Which alert entries correspond to YOUR "
         "actions? Write your line for the report: 'scope exceeded N "
         "times, by me, at H:M — known and approved by exercise.'"),
        ("7. Scored", "`scan-lab score DIR --answers ans.json`. Which "
         "answer did you get wrong first — the gate, or the gatekeeper?"),
    ]
    return ("Scan-lab — guided exercises\n\n" + "\n\n".join(
        f"■ {t}\n{b}" for t, b in items) + "\n")


# ================================================================== web app

class ScanWebApp:
    """Student console + instructor dashboard."""

    def __init__(self, dataset, store: DevLabStore, token: str):
        self.dataset = dataset
        self.store = store
        self.token = token
        self.lock = threading.RLock()
        self.engine = ScanLabEngine(dataset, store)
        self.manifest = dataset["manifest"]

    def _nav(self):
        return ("<nav><a class='btn ghost' href='/'>🏠 brief</a>"
                "<a class='btn ghost' href='/inventory'>🗄 inventory</a>"
                "<a class='btn ghost' href='/console'>🖥 console</a>"
                "<a class='btn ghost' href='/compare-page'>⚖️ compare</a>"
                "<a class='btn ghost' href='/quiz'>✅ quiz</a>"
                "<a class='btn ghost' href='/exercises'>🧭 exercises</a>"
                "</nav>")

    def home(self):
        s = self.engine.summary()
        inv = self.engine.inv
        kinds = defaultdict(int)
        for a in inv["assets"]:
            kinds[a["kind"]] += 1
        online = sum(1 for a in inv["assets"] if a["online"])
        body = self._nav() + f"""
 <div class='hero'><h1>🌐 Large-scale scanning &amp; scope-control lab</h1>
  <p>A <b>virtual, isolated</b> lab network ({html.escape(inv['subnet'])}.*)
  with instructor-created assets. Run simulated scans, watch progress live,
  and discover — by doing it — what changes when rate limits are removed
  or scope is breached. Every out-of-scope attempt is refused <b>before
  probing</b> and logged as a sentinel alert.</p>
  <p class='small'>Strictly isolated: scans are simulated against the
  inventory table. No packets, no sockets, no real devices anywhere.</p></div>
 <div class='grid'>
  <div class='card'><h2>Lab estate</h2>
   <p>{len(inv['assets'])} inventoried assets · {online} online ·
    {len(inv['duplicate_conflicts'])} duplicate-IP conflicts (find them!)</p>
   <p class='mono'>{html.escape(json.dumps(kinds))}</p></div>
  <div class='card'><h2>Console state</h2>
   <p>{s['jobs']} jobs so far · {s['alerts']} scope alerts</p>
   <a class='btn ok' href='/console'>▶ open the scan console</a></div>
 </div>
 <div class='card'><h2>Read this before you scan</h2>
  <ul>
   <li><b>Scope first:</b> target lists stop at the lab subnet; unlisted
    in-subnet IPs and anything outside are refused-before-probe.</li>
   <li><b>Rate limit</b> changes your footprint (duration & concurrent
    pressure), not your findings.</li>
   <li><b>Alerts</b> are the audit trail of every breach — including
    yours. "It was in my target list by accident" is written down
    forever. That IS the professional point.</li></ul></div>"""
        return _page("scan lab — brief", body)

    def inventory_page(self):
        inv = self.engine.inv
        rows = "".join(
            f"<tr><td><code>{a['ip']}</code></td><td>{a['kind']}</td>"
            f"<td>{'🟢 up' if a['online'] else '🔴 down'}</td>"
            f"<td>{html.escape(', '.join(a['services']))}</td></tr>"
            for a in inv["assets"][:400])
        counts = defaultdict(int)
        for a in inv["assets"]:
            counts[a["ip"]] += 1
        dup = "".join(f"<li><code>{ip}</code> ×{counts[ip]}</li>"
                      for ip in inv.get("duplicate_conflicts", []))
        body = self._nav() + f"""
 <div class='card'><h2>🗄 inventory ({len(inv['assets'])} assets — first
  400 shown)</h2>
  <table><tr><th>IP</th><th>kind</th><th>state</th><th>services</th></tr>
  {rows}</table>
  <h3>⚠ duplicate-address conflicts (career lesson in inventory hygiene)</h3>
  <ul>{dup or '<li>none</li>'}</ul></div>"""
        return _page("inventory", body)

    def console_page(self):
        svc_opts = "".join(
            f"<label><input type='checkbox' name='svc' value='{s}' checked>"
            f" {s}</label> " for s in SERVICES)
        example_ip = self.engine.inv["assets"][0]["ip"]
        subnet = self.engine.inv["subnet"]
        body = self._nav() + f"""
 <div class='card'><h2>🖥 scan console</h2>
  <form method='post' action='/scan'>
   <p>targets (comma; try <code>{example_ip}, {subnet}.9.9,
   192.168.1.1</code>):<br>
   <input name='targets' style='width:100%' placeholder='comma-separated IPs, or * for the registered estate'></p>
   <p>services: {svc_opts}</p>
   <p>rate limit /s: <input name='rate' type='number' min='0' max='5000'
    value='100'> (0 = max) · concurrency:
    <input name='conc' type='number' min='1' max='64' value='8'>
    <button class='btn ok'>▶ run</button></p>
   <p class='small'>Submitting a job logs it. Scope violations are
    refused-before-probe and alerted.</p>
  </form></div>
 <div class='card'><h2>jobs &amp; live stats</h2>
  <div id='jobs'><i>loading…</i></div></div>
 <script>
 async function tick(){{
  const r=await fetch('/api/jobs');const d=await r.json();
  let h='<table><tr><th>job</th><th>status</th><th>done/total</th>'
   +'<th>hits</th><th>refused</th><th>violations</th><th>rate</th>'
   +'<th>conc</th><th></th></tr>';
  for(const j of d.jobs){{
   h+='<tr><td><code>'+j.id+'</code></td><td><span class="chip '
    +(j.status==='running'?'info':j.status==='cancelled'?'warn':'ok')
    +'">'+j.status+'</span></td><td>'+j.done+'/'+j.total+'</td><td>'
    +j.hits+'</td><td>'+(j.refused||0)+'</td><td>'+(j.violations||0)+'</td>'
    +'<td>'+j.rate_limit+'/s</td><td>'+j.concurrency+'</td>'
    +'<td><a href="/job/'+j.id+'">open</a></td></tr>';
  }}
  document.getElementById('jobs').innerHTML=h+'</table>'+
   '<p class="small">alerts: '+d.alerts+'</p>';
 }}tick();setInterval(tick,1500);
 </script>"""
        return _page("scan console", body)

    def job_page(self, job_id):
        job = self.engine.jobs.get(job_id)
        if not job:
            return _page("job ?", "<div class='card'>no such job</div>")
        snap = job.snapshot()
        chip = {"running": "info", "cancelled": "warn"}.get(
            snap["status"], "ok")
        res = "".join(f"<tr><td><code>{r['ip']}</code></td>"
                      f"<td>{r['kind']}</td><td>{r['service']}</td>"
                      f"<td>{r['via']}</td><td>{r['latency_ms']} ms</td></tr>"
                      for r in job.results[:500])
        viol = "".join(f"<li class='tag bad'><code>{v['ip']}</code> — "
                       f"{html.escape(v['why'])}</li>"
                       for v in job.scope_violations)
        svg = self._progress_svg(snap)
        body = self._nav() + f"""
 <div class='card'><h2>job <code>{job.id}</code>
  <span class='chip {chip}'>{snap['status']}</span></h2>
  <p>{snap['done']}/{snap['total']} probes · {snap['hits']} hits ·
     {snap['refused']} refused · {len(job.results)} discoveries ·
     {snap['duration_ms'] or '…'} ms</p>
  {svg}
  <form method='post' action='/cancel' style='display:inline'>
   <input type='hidden' name='job' value='{job.id}'>
   <button class='btn danger'>⏹ cancel</button></form>
  <form method='post' action='/export-csv' style='display:inline'>
   <input type='hidden' name='job' value='{job.id}'>
   <button class='btn ghost'>⬇ results CSV</button></form></div>
 <div class='card'><h2>🚨 scope violations on this job
  ({len(job.scope_violations)})</h2>
  <ul>{viol or '<li>none — perfect scope discipline</li>'}</ul></div>
 <div class='card'><h2>discoveries ({len(job.results)})</h2>
  <table><tr><th>IP</th><th>kind</th><th>service</th><th>via</th>
   <th>latency</th></tr>{res or '<tr><td colspan=5>nothing answered '
  'yet</td></tr>'}</table></div>"""
        return _page("job " + job_id, body)

    def _progress_svg(self, snap):
        tl = snap["timeline"]
        if not tl or not snap["total"]:
            return ("<p class='small'>live progress chart appears once the "
                    "job starts…</p>")
        w, h = 520, 120
        maxd = max(snap["total"], 1)
        maxt = max((p["t"] for p in tl), default=1) or 1
        pts = " ".join(f"{40 + 470 * p['t'] / maxt:.1f},"
                       f"{100 - 80 * p['done'] / maxd:.1f}" for p in tl)
        return (f"<svg width='{w}' height='{h}' style='background:#0a0f1c;"
                f"border-radius:8px'><polyline points='{pts}' fill='none' "
                f"stroke='#4cc2ff' stroke-width='2'/></svg>")

    def compare_page(self):
        c = self.engine.compare_modes()
        t, u = c["targeted"], c["uncontrolled"]
        body = self._nav() + f"""
 <div class='card'><h1>⚖️ targeted vs uncontrolled</h1>
  <div style='display:flex;gap:16px;flex-wrap:wrap'>
   <div style='flex:1;min-width:260px'><h2>🎯 targeted</h2>
    <table><tr><td>targets</td><td>{t['targets']}</td></tr>
     <tr><td>probes</td><td>{t['probes']}</td></tr>
     <tr><td>scope violations</td><td>{t['scope_violations']}</td></tr>
     <tr><td>pressure</td><td>{html.escape(t['pressure'])}</td></tr>
    </table></div>
   <div style='flex:1;min-width:260px'><h2>💥 uncontrolled</h2>
    <table><tr><td>targets</td><td>{u['targets']:,}</td></tr>
     <tr><td>probes</td><td>{u['probes']:,}</td></tr>
     <tr><td>scope violations</td><td><span class='chip bad'>{u['scope_violations']:,}</span></td></tr>
     <tr><td>pressure</td><td>{html.escape(u['pressure'])}</td></tr>
    </table></div>
  </div>
  <p class='tag warn'>{html.escape(c['moral'])}</p></div>"""
        return _page("compare", body)

    def quiz_page(self):
        body = self._nav() + """
 <div class='card'><h2>✅ Scored quiz</h2>
  <form method='post' action='/quiz'>
   <div class='card'><h3>Q1. The scope gate lives on…</h3>
    <input name='q_scope_line' placeholder='e.g. 10.77'></div>
   <div class='card'><h3>Q2. A probe aimed outside the gate causes…</h3>
    <select name='q_scope_alert'><option value=''>—</option>
     <option value='unknown-asset'>a sentinel alert, and the target is
      never probed</option>
     <option value='silent'>silent probing anyway</option>
     <option value='slowdown'>just a delay</option></select></div>
   <div class='card'><h3>Q3. Rate limiting chiefly changes…</h3>
    <select name='q_rate_effect'><option value=''>—</option>
     <option value='pressure'>footprint: duration & concurrent pressure,
      same content</option>
     <option value='content'>what you find — fewer answers</option>
     <option value='nothing'>nothing, it's decorative</option></select></div>
   <div class='card'><h3>Q4. The uncontrolled /16 sweep mostly
     enumerated…</h3>
    <select name='q_sweep_lesson'><option value=''>—</option>
     <option value='not-yours'>things that were never yours to touch
      </option>
     <option value='useful'>useful hidden gear</option>
     <option value='your-own'>exactly your lab assets, faster</option>
    </select></div>
   <div class='card'><h3>Q5. A refused (out-of-scope) target is…</h3>
    <select name='q_refusal'><option value=''>—</option>
     <option value='never'>never probed — scope is a gate, not a filter
      </option>
     <option value='retry'>retried quietly</option>
     <option value='logged-only'>only added to a log</option></select></div>
   <button class='btn ok'>🏁 submit</button></form></div>"""
        return _page("quiz", body)

    def quiz_submit(self, answers, ip=""):
        r = score_scanlab(self.engine.inv, answers)
        self.store.attempt("scan", "quiz", json.dumps(answers),
                           r["score"], json.dumps(r["feedback"]), ip)
        lines = "".join(f"<li>{html.escape(f)}</li>" for f in r["feedback"])
        body = self._nav() + (
            f"<div class='card'><h2>Result: {r['score']}/100</h2>"
            f"<ul>{lines}</ul><a class='btn info' href='/quiz'>retry</a>"
            f"</div>")
        return _page("result", body)

    def exercises_page(self):
        return _page("exercises", self._nav() + (
            "<div class='card'><h2>🧭 worksheet</h2><pre>"
            + html.escape(scan_exercises()) + "</pre></div>"))

    def instructor(self, token):
        funnel = self.store.funnel("scan")
        attempts = self.store.attempts("scan", 50)
        alerts = self.engine.alerts[-40:][::-1]
        al = "".join(
            f"<tr><td>{time.strftime('%H:%M:%S', time.localtime(a['ts']))}"
            f"</td><td><code>{a['ip']}</code></td>"
            f"<td>{html.escape(a['job'])}</td>"
            f"<td>{html.escape(a['why'])}</td></tr>"
            for a in alerts) or \
            "<tr><td colspan=4>no scope alerts yet</td></tr>"
        atr = "".join(
            f"<tr><td>{a['time']}</td><td>quiz</td>"
            f"<td><b>{a['score']}</b></td>"
            f"<td class='mono'>{html.escape(str(a['answer']))[:120]}</td>"
            f"</tr>" for a in attempts) or \
            "<tr><td colspan=4>no quiz attempts yet</td></tr>"
        body = f"""
 <div class='hero'><h1>👩‍🏫 SCAN-lab instructor console</h1>
  <p class='small'>Scans are simulated; the alerts are real records of
  scope breaches — a teaching goldmine.</p></div>
 <div class='grid'>
  <div class='card'><h2>🔔 scope sentinel alerts
    ({len(self.engine.alerts)})</h2>
   <table><tr><th>time</th><th>IP</th><th>job</th><th>why</th></tr>
   {al}</table></div>
  <div class='card'><h2>Controls</h2>
   <form method='post' action='/api/expand?token={html.escape(token)}'>
    🧱 expand inventory by <input type='number' name='n' value='10'
     min='1' max='200'> assets
    <button class='btn info'>expand</button></form>
   <button class='btn danger' id='rb'>🧹 reset jobs + alerts + attempts
    </button>
   <button class='btn warn' style='background:var(--warn);color:#422006'
    id='gb'>🎲 regenerate inventory (seed+1)</button>
   <a class='btn ghost' href='/'>student view</a>
   <p>funnel: {json.dumps(funnel)}</p></div>
 </div>
 <div class='card'><h2>recent attempts ({len(attempts)})</h2>
  <table><tr><th>time</th><th>q</th><th>score</th><th>answers</th></tr>
  {atr}</table></div>
 <script>
 const TOKEN=""" + json.dumps(token) + """;
 async function rst(){if(!confirm('Reset jobs, alerts and attempts?'))
  return;await fetch('/api/reset?token='+TOKEN,{method:'POST'});
  location.reload();}
 async function regen(){if(!confirm('Regenerate the WHOLE inventory '
  '(seed+1)?'))return;
  const r=await fetch('/api/regenerate?token='+TOKEN,{method:'POST'});
  const d=await r.json();alert('new estate: '+d.hosts+' assets, seed '
  +d.seed);location.href='/';}
 document.getElementById('rb').addEventListener('click',rst);
 document.getElementById('gb').addEventListener('click',regen);
 </script>"""
        return _page("instructor — scan lab", body)

    def expand_inventory(self, n):
        with self.lock:
            inv = self.engine.inv
            rnd = __import__("random").Random(int(self.manifest.get(
                "seed", 12)) + len(inv["assets"]))
            added = []
            profiles = {"workstation": ["ssh/22", "smb/445"],
                        "server": ["ssh/22", "http/80"],
                        "printer": ["http/80", "printer/9100"],
                        "iot-sensor": ["mqtt/1883"],
                        "camera": ["http/80"],
                        "switch": ["ssh/22"]}
            for _ in range(max(1, min(200, int(n)))):
                k = rnd.choice(list(profiles))
                ip = f"{self.engine.inv['subnet']}.{rnd.randint(3, 5)}." \
                     f"{rnd.randint(2, 254)}"
                inv["assets"].append(dict(
                    ip=ip, kind=k, online=True,
                    services=list(profiles[k]), hidden_services=[],
                    note="instructor-added"))
                added.append(ip)
            self.manifest["hosts"] = len(inv["assets"])
            return added

    def reset_all(self):
        with self.lock:
            self.engine.jobs.clear()
            self.engine.alerts.clear()
            self.store.reset("scan")

    def regenerate(self):
        with self.lock:
            seed = int(self.manifest.get("seed", 12)) + 1
            generate_inventory(self.dataset["dir"], seed=seed,
                               size=len(self.engine.inv["assets"]),
                               fresh=True)
            self.dataset = load_inventory(self.dataset["dir"])
            self.manifest = self.dataset["manifest"]
            self.engine = ScanLabEngine(self.dataset, self.store)
            return seed


def make_scan_server(bind, port, app: ScanWebApp):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from urllib.parse import urlparse, parse_qs

    class H(BaseHTTPRequestHandler):
        server_version = "wifiscanner-scanlab"
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
                app.store.event("scan", "page-view", "instructor",
                                self._client())
                return self._ok(app.instructor(token))
            if path.startswith("/job/"):
                app.store.event("scan", "page-view", path, self._client())
                return self._ok(app.job_page(path[len("/job/"):]))
            app.store.event("scan", "page-view", path, self._client())
            if path == "/":
                return self._ok(app.home())
            if path == "/inventory":
                return self._ok(app.inventory_page())
            if path == "/console":
                return self._ok(app.console_page())
            if path == "/compare-page":
                return self._ok(app.compare_page())
            if path == "/exercises":
                return self._ok(app.exercises_page())
            if path == "/quiz":
                return self._ok(app.quiz_page())
            if path == "/api/jobs":
                with app.lock:
                    jobs = [j.snapshot() for j in
                            sorted(app.engine.jobs.values(),
                                   key=lambda j: -j.created)][:12]
                return self._json(dict(jobs=jobs,
                                       alerts=len(app.engine.alerts)))
            if path == "/api/state":
                if not self._tok_ok(u):
                    return self._json({"error": "not found"}, 404)
                with app.lock:
                    return self._json({"ok": True,
                                       "funnel": app.store.funnel("scan"),
                                       "alerts": app.engine.alerts[-50:],
                                       "jobs": [j.snapshot() for j in
                                                app.engine.jobs.values()]})
            return self._json({"error": "not found"}, 404)

        def _form_multi(self):
            n = int(self.headers.get("Content-Length") or 0)
            if n > self._MAX_POST:
                return None
            if n == 0:
                return {}
            raw = self.rfile.read(n).decode("utf-8", "ignore")
            return parse_qs(raw)

        def do_POST(self):
            u = urlparse(self.path)
            path = u.path
            form = self._form_multi()
            if form is None:
                return self._json({"error": "bad request"}, 400)
            one = lambda k, d="": (form.get(k) or [d])[0]
            if path == "/quiz":
                return self._ok(app.quiz_submit(
                    {k: one(k) for k in SCAN_QUIZ}, self._client()))
            if path == "/scan":
                t_raw = one("targets")
                if not t_raw.strip():
                    return self._json({"error": "no targets"}, 400)
                targets = ([a["ip"] for a in app.engine.inv["assets"]]
                           if t_raw.strip() == "*" else
                           [t.strip() for t in t_raw.split(",")
                            if t.strip()])
                services = [s for s in (form.get("svc") or list(SERVICES))
                            if s in SERVICES] or list(SERVICES)
                try:
                    rate = float(one("rate", "100") or 0)
                    conc = int(one("conc", "8") or 8)
                except ValueError:
                    return self._json({"error": "bad numbers"}, 400)
                job = app.engine.submit(targets, services, rate, conc,
                                        by="student")
                self.send_response(303)
                self.send_header("Location", f"/job/{job.id}")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if path == "/cancel":
                ok = app.engine.cancel(one("job"))
                return self._json({"ok": ok})
            if path == "/export-csv":
                job = app.engine.jobs.get(one("job"))
                if not job:
                    return self._json({"error": "not found"}, 404)
                import io, csv as _csv
                buf = io.StringIO()
                w = _csv.DictWriter(buf, fieldnames=["ip", "kind",
                                                     "service", "via",
                                                     "latency_ms"])
                w.writeheader()
                w.writerows(job.results)
                data = buf.getvalue().encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/csv")
                self.send_header("Content-Disposition",
                                 f"attachment; filename={job.id}.csv")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                return self.wfile.write(data)
            authed = self._tok_ok(u)

            def _need():
                return self._json({"error": "not found"}, 404)

            if path == "/api/reset":
                if not authed:
                    return _need()
                old_funnel = app.store.funnel("scan")
                app.reset_all()
                app.store.event("scan", "reset",
                                f"wiped after {old_funnel['attempts']} "
                                f"attempts / {old_funnel['views']} views",
                                self._client())
                return self._json({"ok": True})
            if path == "/api/regenerate":
                if not authed:
                    return _need()
                seed = app.regenerate()
                app.store.event("scan", "regenerate", f"seed={seed}",
                                self._client())
                return self._json({"ok": True, "seed": seed,
                                   "hosts": app.manifest.get("hosts", 0)})
            if path == "/api/expand":
                if not authed:
                    return _need()
                added = app.expand_inventory(one("n", "10"))
                app.store.event("scan", "expand", f"{len(added)} assets",
                                self._client())
                return self._json({"ok": True, "added": added})
            return self._json({"error": "not found"}, 404)

    return ThreadingHTTPServer((bind, port), H)
