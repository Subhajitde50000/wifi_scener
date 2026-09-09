"""Device-identity laboratories: MAC randomization & correlation (``mac-lab``)
and long-term tracking (``track-lab``).

Both labs work on **instructor-controlled, synthetic datasets** — never on
real bystanders. A dataset is a directory produced by
``mac-lab make-dataset`` / ``track-lab make-dataset``:

* ``sensor-<name>.pcap`` — one pcap per authorised lab sensor, carrying
  802.11 probe-request bursts (Radiotap with a dBm antenna-signal field);
* ``manifest.json`` — seed, time span, sensors, frame count;
* ``ground-truth.csv`` (0600, instructor-only) — which lab device actually
  owns which MACs, including the deliberate *trap* devices.

Feature 8 (``mac-lab``) teaches MAC randomization and correlation:

* devices emit per-device probe IE *fingerprints* (ordered tag list +
  vendor OUIs — the classic "randomization is not enough" vector),
  directed-probe SSID sets, RSSI and burst cadence;
* the correlation engine scores candidate MAC pairs with explicit evidence
  (fingerprint, SSID-set Jaccard, rotation hand-off timing, RSSI, cadence)
  and **anti-evidence** (simultaneous observation = definitively two
  devices — this breaks naive fingerprint-only matching, and two same-model
  "twin" devices in the dataset make sure students meet that mistake);
* confidence is graduated and deliberately hedged — correlation is a
  hypothesis with error bars, never a proof of identity;
* scoring (`mac-lab score`, web quiz) awards correct merges AND correct
  rejections, with feedback on the twin trap.

Feature 9 (``track-lab``) teaches persistent tracking and its risks:

* multi-day observations across authorised lab sensors → visit
  sessionization, dwell, weekday/hour heatmaps, movement edges;
* short-window vs long-window contrast (``--since``) shows how "nothing
  learned" becomes "full daily routine" purely by longer retention;
* identity traps: a decoy with the same OUI and a similar schedule
  (OUI-keyed tracking mis-assigns it) and a rotating device that defeats
  MAC-keyed tracking entirely (the privacy defence, observed working);
* scored quiz (identity, trackability, main movement edge, short-window
  conclusion) plus a privacy-implications brief;
* dataset reset/regenerate (`--fresh`, dashboard button) for each class.

Everything is stdlib-only, deterministic per seed, and offline.
"""
from __future__ import annotations

import csv
import hashlib
import html
import json
import os
import secrets as _secrets
import sqlite3
import struct
import threading
import time
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .oui import is_randomized, lookup as oui_lookup
from .privacy import ensure_secure_storage, secure_file
from .wpalab import Frame80211, _RADIOTAP8, read_pcap, walk_ies, write_pcap

__all__ = ["generate_maclab_dataset", "generate_tracklab_dataset",
           "load_dataset", "CorrelationEngine", "Tracker",
           "score_maclab", "score_tracklab", "DevLabStore",
           "maclab_exercises", "tracklab_exercises"]

# ---------------------------------------------------------------- radiotap

_RT_FIELDS = {0: (8, 8), 1: (1, 1), 2: (1, 1), 3: (2, 4), 4: (2, 2),
              5: (1, 1), 6: (1, 1), 7: (2, 2), 8: (2, 2), 9: (2, 2),
              10: (1, 1), 11: (1, 1), 12: (1, 1), 13: (1, 1), 14: (2, 2),
              15: (4, 4)}


def _rtap_write(rssi_dbm: int) -> bytes:
    """9-byte Radiotap header carrying only a dBm antenna-signal field."""
    return struct.pack("<BBHI", 0, 0, 9, 1 << 5) + bytes([rssi_dbm & 0xFF])


def _rtap_parse(data: bytes):
    """→ (802.11 body, rssi or None)."""
    if len(data) < 8 or data[0] != 0:
        return None, None
    hdr_len = int.from_bytes(data[2:4], "little")
    if hdr_len < 8 or hdr_len > len(data):
        return None, None
    present = int.from_bytes(data[4:8], "little")
    off = 8
    if present & (1 << 31):                          # extended bitmap(s)
        more = 4
        present >>= 0
        while data[4 + more - 4 + 3] & 0x80:         # another word follows
            more += 4
        off = 8 + more - 4
    rssi = None
    bitmap = present
    w = 0
    extra_start = off
    for bit in range(0, 22):
        if not (bitmap >> bit) & 1:
            continue
        if bit not in _RT_FIELDS:
            break
        align, size = _RT_FIELDS[bit]
        off += -off % align
        if bit == 5 and off < hdr_len:
            rssi = int.from_bytes(data[off:off + 1], "big", signed=True)
        off += size
        w += 1
    return data[hdr_len:], rssi


# ------------------------------------------------------------ observations

def _fp_key(ies):
    """Deterministic fingerprint of a probe request: ordered IE ids +
    vendor OUIs."""
    ids, ouis = [], []
    for ie_id, data in ies:
        ids.append(str(ie_id))
        if ie_id == 221 and len(data) >= 3:
            ouis.append(data[:3].hex())
    return (".".join(ids) + "|" + ",".join(sorted(set(ouis))))


class Obs:
    __slots__ = ("ts", "sensor", "mac", "rssi", "ssid", "fp", "fp_seq")

    def __init__(self, ts, sensor, mac, rssi, ssid, fp, fp_seq):
        self.ts, self.sensor, self.mac, self.rssi = ts, sensor, mac, rssi
        self.ssid, self.fp, self.fp_seq = ssid, fp, fp_seq

    def row(self):
        return {"ts": round(self.ts, 1),
                "time": time.strftime("%m-%d %H:%M:%S", time.localtime(self.ts)),
                "sensor": self.sensor, "mac": self.mac, "rssi": self.rssi,
                "probed_ssid": self.ssid or "(wildcard)",
                "fingerprint": self.fp}


class DeviceProfile:
    """Synthetic device *behaviour* class used by the generators."""

    def __init__(self, name, ies, probed_ssids, rotates=False,
                 base_interval=60.0, bursts=3):
        self.name = name
        self.ies = ies                        # [(ie_id, bytes), ...]
        self.probed_ssids = probed_ssids
        self.rotates = rotates
        self.base_interval = base_interval
        self.bursts = bursts


# Realistic probe IE sets (ordered; content abridged but structurally real)
_RATES = b"\x82\x84\x8b\x96\x24\x30\x48\x6c"
PROFILE_IOS = DeviceProfile(
    "ios-phone",
    [(1, _RATES), (50, _RATES[:4]), (45, b"\xff\x00"), (107, b"\x00"),
     (127, b"\xef"), (191, b"\x01\x00"), (221, b"\x00\x17\xf2\x0a\x00"),
     (221, b"\x00\x50\xf2\x04\x10")],
    ["HomeNet-24", "CampusNet"], rotates=True, base_interval=45.0)
PROFILE_ANDROID = DeviceProfile(
    "android-phone",
    [(1, _RATES), (50, _RATES[:4]), (3, b"\x06"), (45, b"\xff\x00"),
     (70, b"\x00"), (107, b"\x00"), (127, b"\xff"), (191, b"\x01\x00"),
     (192, b"\x00\x00"), (221, b"\x00\x10\x18\x02"), (255, b"\x05")],
    ["HomeNet-24", "UniEdu"], rotates=True, base_interval=72.0)
PROFILE_WIN = DeviceProfile(
    "windows-laptop",
    [(1, _RATES), (50, _RATES[:4]), (3, b"\x06"), (45, b"\xff\x01"),
     (61, b"\x0e"), (221, b"\x00\x50\xf2\x04\x11"), (255, b"\x07")],
    ["HomeNet-24", "printer-direct", "CorpNet"], rotates=False,
    base_interval=95.0)
PROFILE_IOT = DeviceProfile(
    "iot-badge",
    [(1, _RATES[:4]), (3, b"\x06"), (45, b"\x00\x00")],
    ["LabIoT"], rotates=False, base_interval=20.0, bursts=1)


def _rand_mac(rnd, randomized=True):
    b = [rnd.randint(0, 255) for _ in range(6)]
    if randomized:
        b[0] = (b[0] & 0xFC) | 0x02              # locally administered, unicast
    else:                                        # keep a stable "real OUI" mac
        b[:3] = [0x3C, 0x5A, 0xB4]
    return ":".join(f"{x:02X}" for x in b)


def _probe_frame(mac: bytes, seq: int, profile: DeviceProfile,
                 directed_ssid: str = "") -> bytes:
    """802.11 probe-request (management subtype 4)."""
    hdr = (b"\x40\x00\x00\x00" + b"\xff" * 6 + mac + b"\xff" * 6
           + struct.pack("<H", (seq & 0x0FFF) << 4))
    ssid_b = directed_ssid.encode()
    body = bytes([0, len(ssid_b)]) + ssid_b
    for ie_id, data in profile.ies:
        body += bytes([ie_id, len(data)]) + data[:255]
    return hdr + body


def _burst(records, rnd, sensor, mac_s, ts, profile: DeviceProfile,
           rssi_base: int, seq0: int):
    """Emit one probe burst: wildcard + one directed probe per known SSID."""
    mac_b = bytes(int(x, 16) for x in mac_s.split(":"))
    n = 0
    for i in range(profile.bursts):
        t = ts + i * profile.base_interval / profile.bursts * 0.05 \
            + rnd.uniform(0, 0.4)
        rssi = int(rssi_base + rnd.uniform(-3, 3))
        targets = [""] + profile.probed_ssids
        for k, tgt in enumerate(targets):
            records.setdefault(sensor, []).append(
                (t + 0.002 * k,
                 _rtap_write(rssi) + _probe_frame(mac_b, seq0 + n, profile,
                                                  tgt)))
            n += 1
    return n


def _write_sensor_pcaps(outdir: str, sensors: list, records: dict) -> int:
    total = 0
    for sensor in sensors:
        recs = sorted(records.get(sensor, []))
        path = os.path.join(outdir, f"sensor-{sensor}.pcap")
        write_pcap(path, [(t, r) for t, r in recs], 127)
        total += len(recs)
    return total


def _write_manifest(outdir, kind, seed, sensors, start, end, frames,
                    extra=None):
    manifest = {"kind": kind, "seed": seed, "sensors": sensors,
                "start": start, "end": end, "frames": frames,
                "created": time.strftime("%Y-%m-%d %H:%M:%S")}
    if extra:
        manifest.update(extra)
    path = os.path.join(outdir, "manifest.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=1)
    secure_file(path)
    return path


def _write_ground_truth(outdir, rows):
    path = os.path.join(outdir, "ground-truth.csv")
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["device", "label", "profile",
                                           "macs", "rotates", "notes"])
        w.writeheader()
        w.writerows(rows)
    secure_file(path)
    return path


# ------------------------------------------------ mac-lab dataset generator

def generate_maclab_dataset(outdir: str, seed: int = 8, fresh: bool = False):
    """Two-day, two-sensor lab dataset with a rotator, twin decoys, a stable
    laptop + IoT beacon, and background one-shot probes.

    Ground truth (instructor-only):
      Device-A  rotator (iOS profile) — 3 randomized MACs across windows
      Device-B1/B2 twins (Android profile) — identical fingerprints,
                deliberately SIMULTANEOUS (naive fingerprint merging fails)
      Device-C  windows laptop (stable MAC, distinct fingerprint)
      Device-D  IoT badge (stable MAC, tiny fingerprint, directed probe)
      noise     one-shot randomized probes, never correlated
    """
    if os.path.exists(outdir) and os.listdir(outdir) and not fresh:
        raise FileExistsError(f"{outdir} is not empty (pass fresh=True or "
                              f"`--fresh` to regenerate)")
    os.makedirs(outdir, exist_ok=True)
    rnd = __import__("random").Random(seed)
    sensors = ["lab-a", "corridor"]
    start = int(time.time() - 2 * 86400) // 60 * 60
    records = defaultdict(list)
    truth = []

    def window(day, hour, minute, dur_min):
        t0 = start + day * 86400 + hour * 3600 + minute * 60
        return t0, t0 + dur_min * 60

    # Device-A: the legitimate randomizer — SAME-DAY chained windows: every
    # rotation happens 30-150 s after the previous address goes quiet, so
    # the dataset carries real rotation hand-offs (the decisive behavioural
    # evidence). The three MACs recur the next day (repeat patterns).
    mac_a = [_rand_mac(rnd) for _ in range(3)]
    plan = [(0, 8, 5, "lab-a", -48, 10, 0),
            (0, 8, 40, "corridor", -61, 10, 1),
            (0, 9, 10, "lab-a", -50, 10, 2),
            (1, 9, 20, "lab-a", -50, 12, 0),
            (1, 10, 0, "corridor", -55, 10, 1)]
    prev_end = prev_idx = prev_day = None
    for day, h, mi, sensor, rssi, dur, idx in plan:
        t0 = start + day * 86400 + h * 3600 + mi * 60
        if (prev_end is not None and day == prev_day
                and idx != prev_idx and t0 - prev_end > 180.0):
            t0 = prev_end + rnd.uniform(30, 150)
        t0, t1 = t0, t0 + dur * 60
        t = t0
        while t < t1:
            _burst(records, rnd, sensor, mac_a[idx], t, PROFILE_IOS, rssi,
                   int(t) & 0xFFF)
            t += PROFILE_IOS.base_interval + rnd.uniform(-8, 8)
        prev_end, prev_idx, prev_day = t1, idx, day
    truth.append(dict(device="Device-A", label="rotator-phone",
                      profile="ios-phone", macs=";".join(mac_a),
                      rotates="yes",
                      notes="same handset: fingerprint+SSID set+rotation "
                            "handoffs; MACs never overlap in time"))

    # Devices B1/B2: the twins — identical model/fingerprint/SSID set,
    # present AT THE SAME TIME at different sensors (anti-evidence).
    mac_b1, mac_b2 = _rand_mac(rnd), _rand_mac(rnd)
    for day in (0, 1):
        t0, t1 = window(day, 12, 0, 35)
        t = t0
        while t < t1:
            _burst(records, rnd, "lab-a", mac_b1, t, PROFILE_ANDROID, -55,
                   int(t) & 0xFFF)
            _burst(records, rnd, "corridor", mac_b2, t + 0.05,
                   PROFILE_ANDROID, -66, int(t) & 0xFFF)
            t += PROFILE_ANDROID.base_interval + rnd.uniform(-9, 9)
    truth.append(dict(device="Device-B1", label="twin-phone-1",
                      profile="android-phone", macs=mac_b1, rotates="no",
                      notes="twin of Device-B2: identical fingerprint AND SSID "
                            "set — but observed SIMULTANEOUSLY with B2, so it "
                            "is provably a different physical device"))
    truth.append(dict(device="Device-B2", label="twin-phone-2",
                      profile="android-phone", macs=mac_b2, rotates="no",
                      notes="the correlation trap (see Device-B1)"))

    # Device-C: laptop, stable MAC, unique fingerprint
    mac_c = "10:22:33:CC:DD:01"
    for day in (0, 1):
        t0, t1 = window(day, 10, 0, 90)
        t = t0
        while t < t1:
            _burst(records, rnd, "lab-a", mac_c, t, PROFILE_WIN, -42,
                   int(t) & 0xFFF)
            t += PROFILE_WIN.base_interval + rnd.uniform(-10, 10)
    truth.append(dict(device="Device-C", label="laptop", profile="windows-laptop",
                      macs=mac_c, rotates="no",
                      notes="stable MAC — correlation unnecessary; control case"))

    # Device-D: IoT badge, stable, only ever probes LabIoT
    mac_d = "44:01:BB:10:20:30"
    t0, t1 = start, start + 2 * 86400
    t = t0
    while t < t1:
        _burst(records, rnd, "lab-a", mac_d, t, PROFILE_IOT, -35, int(t) & 0xFFF)
        t += 600
    truth.append(dict(device="Device-D", label="iot-badge", profile="iot-badge",
                      macs=mac_d, rotates="no",
                      notes="constant beacon-like presence; singleton SSID"))

    # background one-shots: random MAC, wildcards + a per-device *unique*
    # public SSID (so they correlate weakly but never plausibly with the
    # protagonists — the realistic "grey zone" students must reject)
    for k in range(14):
        m = _rand_mac(rnd)
        base_prof = rnd.choice([PROFILE_ANDROID, PROFILE_IOS])
        noise_prof = DeviceProfile(base_prof.name, base_prof.ies,
                                   [f"PublicNet-{seed}-{k}"],
                                   base_interval=base_prof.base_interval)
        _burst(records, rnd, rnd.choice(sensors), m,
               start + rnd.uniform(3600, 1.8 * 86400),
               noise_prof, rnd.randint(-75, -45), 1)

    frames = _write_sensor_pcaps(outdir, sensors, records)
    _write_manifest(outdir, "maclab", seed, sensors, start,
                    start + 2 * 86400, frames)
    _write_ground_truth(outdir, truth)
    return {"dir": outdir, "devices": len(truth), "frames": frames,
            "sensors": sensors, "seed": seed}


# ---------------------------------------------- track-lab dataset generator

def generate_tracklab_dataset(outdir: str, seed: int = 9, days: int = 14,
                              fresh: bool = False):
    """Multi-day presence dataset across four authorised lab sensors.

    Ground truth:
      Student-A    stable OUI phone: weekday 09:00 lab-north (~45 min),
                   12:30 canteen (~30 min), 15:10 lab-south (~60 min)
      Decoy-A'     SAME OUI prefix as Student-A, weekday 09:05 corridor —
                   an OUI/schedule lookalike that naive identity-by-OUI
                   analysis assigns to Student-A (false-positive lesson)
      Visitor-B    randomized phone, new MAC every visit (by-MAC tracking
                   fails completely — the privacy defence working)
      Staff-IoT    badge: every day 08:00 corridor, 08:10 lab-north
      noise        one-shot randomized probes
    """
    if os.path.exists(outdir) and os.listdir(outdir) and not fresh:
        raise FileExistsError(f"{outdir} is not empty (pass --fresh)")
    os.makedirs(outdir, exist_ok=True)
    rnd = __import__("random").Random(seed)
    # anchor the dataset to end ~1h ago, aligned to local midnight
    now = time.time()
    lt = time.localtime(now)
    # align 'end' to local midnight
    end = now - (lt.tm_hour * 3600 + lt.tm_min * 60 + lt.tm_sec)
    start = end - days * 86400
    sensors = ["lab-north", "lab-south", "corridor", "canteen"]
    records = defaultdict(list)
    truth = []

    mac_student = "3C:5A:B4:71:00:42"
    mac_decoy = "3C:5A:B4:77:12:99"          # same OUI prefix as Student-A
    # a quiet but positive OUI signal both students would note
    mac_badge = "44:01:BB:AA:00:11"

    prof_a = PROFILE_ANDROID                 # Student-A + decoy share profile
    prof_b = PROFILE_IOS                     # Visitor-B

    def visit(sensor, mac, t0, dur_s, profile, rssi):
        t = t0
        while t < t0 + dur_s:
            _burst(records, rnd, sensor, mac, t, profile, rssi, int(t) & 0xFFF)
            t += profile.base_interval + rnd.uniform(-6, 6)

    for d in range(days):
        day = start + d * 86400
        wd = time.localtime(day).tm_wday     # 0=Mon
        is_weekday = wd < 5
        if is_weekday:
            # Student-A's routine
            visit("lab-north", mac_student, day + 9 * 3600, 45 * 60,
                  prof_a, -46)
            visit("canteen", mac_student, day + 12 * 3600 + 30 * 60,
                  30 * 60, prof_a, -52)
            visit("lab-south", mac_student, day + 15 * 3600 + 10 * 60,
                  60 * 60, prof_a, -49)
            # The decoy: also weekday mornings, but in the corridor.
            visit("corridor", mac_decoy, day + 9 * 3600 + 5 * 60,
                  12 * 60, prof_a, -63)
        # Visitor-B: daily but at random hours, brand-new MAC each visit
        mac_v = _rand_mac(rnd)
        visit(rnd.choice(sensors), mac_v,
              day + rnd.uniform(8, 19) * 3600, rnd.uniform(8, 25) * 60,
              prof_b, rnd.randint(-70, -45))
        # Staff badge: every day, corridor -> lab-north
        visit("corridor", mac_badge, day + 8 * 3600, 5 * 60, PROFILE_IOT, -38)
        visit("lab-north", mac_badge, day + 8 * 3600 + 10 * 60, 50 * 60,
              PROFILE_IOT, -40)
    for _ in range(days * 6):                # background passers-by
        visit(rnd.choice(sensors), _rand_mac(rnd),
              start + rnd.uniform(1800, days * 86400 - 1800),
              rnd.uniform(60, 240),
              rnd.choice([prof_a, prof_b]), rnd.randint(-78, -50))

    truth.append(dict(device="Student-A", label="target-student-phone",
                      profile="android-phone", macs=mac_student,
                      rotates="no",
                      notes="the tracking target: weekday lab-north 09:00 → "
                            "canteen 12:30 → lab-south 15:10"))
    truth.append(dict(device="Decoy-A'", label="visitor-lookalike",
                      profile="android-phone", macs=mac_decoy, rotates="no",
                      notes="SAME OUI + similar morning window as Student-A "
                            "but corridor-only; OUI-based identity attribution "
                            "floats it into Student-A — the trap"))
    truth.append(dict(device="Visitor-B", label="rotating-phone",
                      profile="ios-phone", macs="(rotates daily)",
                      rotates="yes",
                      notes="new randomized MAC per visit: by-MAC tracking "
                            "sees ~14 unrelated 'devices' — an effective "
                            "privacy defence, visibly working"))
    truth.append(dict(device="Staff-IoT", label="staff-badge",
                      profile="iot-badge", macs=mac_badge, rotates="no",
                      notes="fixed corridor→lab-north morning loop"))

    frames = _write_sensor_pcaps(outdir, sensors, records)
    _write_manifest(outdir, "tracklab", seed, sensors, start, end, frames,
                    {"days": days})
    _write_ground_truth(outdir, truth)
    return {"dir": outdir, "devices": len(truth), "frames": frames,
            "sensors": sensors, "days": days, "seed": seed}


# ------------------------------------------------------------------ loading

def load_dataset(dirname: str):
    """Dataset dir → {"manifest", "obs": [Obs], "truth": rows (if readable)}."""
    manifest_p = os.path.join(dirname, "manifest.json")
    if not os.path.exists(manifest_p):
        raise FileNotFoundError(f"no manifest.json in {dirname} — generate "
                                f"one with `make-dataset`")
    with open(manifest_p, encoding="utf-8") as fh:
        manifest = json.load(fh)
    obs = []
    for fn in sorted(os.listdir(dirname)):
        if not (fn.startswith("sensor-") and fn.endswith(".pcap")):
            continue
        sensor = fn[len("sensor-"):-len(".pcap")]
        _link, raws = read_pcap(os.path.join(dirname, fn))
        for ts, raw in raws:
            body, rssi = _rtap_parse(raw)
            if body is None:
                continue
            f = Frame80211(body, ts)
            if not (f.valid and f.ftype == 0 and f.subtype == 4):
                continue
            ssid = ""
            ies = list(walk_ies(f.payload))
            fp = _fp_key(ies)
            for ie_id, data in ies:
                if ie_id == 0:
                    ssid = data.decode("utf-8", "ignore") if data else ""
                    break
            mac = ":".join(f"{b:02X}" for b in f.a2)
            obs.append(Obs(ts, sensor, mac, rssi, ssid, fp, f.seq))
    truth = []
    gt = os.path.join(dirname, "ground-truth.csv")
    if os.path.exists(gt):
        with open(gt, newline="", encoding="utf-8") as fh:
            truth = list(csv.DictReader(fh))
    return {"manifest": manifest, "obs": obs, "truth": truth, "dir": dirname}


def obs_by_mac(obs_list):
    by = defaultdict(lambda: {"mac": "", "fp": "", "ssids": set(),
                              "sensor_spans": defaultdict(list),
                              "rssis": defaultdict(list), "ts_all": []})
    for o in obs_list:
        d = by[o.mac]
        d["mac"] = o.mac
        d["fp"] = o.fp or d["fp"]
        if o.ssid:
            d["ssids"].add(o.ssid)
        d["sensor_spans"][o.sensor].append(o.ts)
        if o.rssi is not None:
            d["rssis"][o.sensor].append(o.rssi)
        d["ts_all"].append(o.ts)
    for d in by.values():
        d["first"] = min(d["ts_all"])
        d["last"] = max(d["ts_all"])
        d["frames"] = len(d["ts_all"])
        d["rssi_mean"] = (sum(sum(v) / len(v) for v in d["rssis"].values())
                          / len(d["rssis"]) if d["rssis"] else None)
        d["windows"] = {s: (min(v), max(v)) for s, v in
                        d["sensor_spans"].items()}
    return dict(by)


# ============================================================ MAC-LAB ENGINE

class CorrelationEngine:
    """Evidence-weighted MAC correlation with explicit uncertainty.

    For every pair of observed MACs the engine accumulates supporting
    evidence AND anti-evidence, then reports a graduated verdict — never a
    bare "same device", because correlation is always a hypothesis:

      different  — hard anti-evidence (simultaneous presence; stable vs
                   randomized semantics)
      high       — fingerprint + SSID set equal, rotation hand-off seen,
                   no anti-evidence (≥85)
      likely     — fingerprint + SSID equal, timing only suggestive (65–84)
      possible   — fingerprint equal but little corroboration (45–64)
      low        — weak or absent evidence (<45)
    """

    HANDOFF_S = 180.0          # max rotation hand-off gap
    RSSI_CLOSE = 6.0
    CADENCE_REL = 0.35

    def __init__(self, obs_list):
        self.by_mac = obs_by_mac(obs_list)
        self.macs = sorted(self.by_mac, key=lambda m: self.by_mac[m]["first"])

    @staticmethod
    def _sessions(ts_list, gap_s=300.0):
        """Sessionize timestamps on a >gap_s silence split → [(start,end)]."""
        ts = sorted(ts_list)
        if not ts:
            return []
        out = [[ts[0], ts[0]]]
        for t in ts[1:]:
            if t - out[-1][1] > gap_s:
                out.append([t, t])
            else:
                out[-1][1] = t
        return [(a, b) for a, b in out]

    def _handoffs(self, a, b):
        """Rotation hand-offs: a session of A goes quiet, B appears within
        (2s, 180s]. Deliberately session-based so two devices probing in
        lockstep (the twins) do NOT manufacture fake hand-offs: overlapping
        sessions cannot produce one."""
        n = 0
        best = None
        sa_all = [t for spans in a["sensor_spans"].values() for t in spans]
        sb_all = [t for spans in b["sensor_spans"].values() for t in spans]
        ses_a = self._sessions(sa_all)
        ses_b = self._sessions(sb_all)
        for ea_end in [s[1] for s in ses_a]:
            for sb_start in [s[0] for s in ses_b]:
                gap = sb_start - ea_end
                if 2.0 < gap <= self.HANDOFF_S:
                    n += 1
                    if best is None or gap < best[0]:
                        best = (gap,)
        return n, best

    def _overlap(self, a, b):
        """Seconds of simultaneous presence (anti-evidence), comparing
        sessions (not min/max spans, which smear multi-visit devices)."""
        sa = {s: self._sessions(spans) for s, spans in a["sensor_spans"].items()}
        sb = {s: self._sessions(spans) for s, spans in b["sensor_spans"].items()}
        same = 0.0
        for s in set(sa) | set(sb):
            for wa in sa.get(s, ()):
                for wb in sb.get(s, ()):
                    same += max(0.0, min(wa[1], wb[1]) - max(wa[0], wb[0]))
        cross = 0.0
        for s1 in sa:
            for s2 in sb:
                if s1 == s2:
                    continue
                for wa in sa[s1]:
                    for wb in sb[s2]:
                        cross += max(0.0, min(wa[1], wb[1]) - max(wa[0], wb[0]))
        return same, cross

    @staticmethod
    def _cadence(obs):
        pass

    def evidence(self, mac1, mac2):
        a, b = self.by_mac[mac1], self.by_mac[mac2]
        ev = {"pair": (mac1, mac2), "support": [], "anti": [], "score": 0.0}
        # fingerprint
        if a["fp"] and a["fp"] == b["fp"]:
            ev["support"].append(("fingerprint", 40,
                                  "identical probe-IE fingerprint "
                                  "(same driver/IE stack)"))
        else:
            ev["anti"].append(("fingerprint", -40,
                               "different IE fingerprint "
                               f"({a['fp'][:24]}… vs {b['fp'][:24]}…)"))
        # directed SSID set
        js = 0.0
        if a["ssids"] and b["ssids"]:
            inter = len(a["ssids"] & b["ssids"])
            union = len(a["ssids"] | b["ssids"])
            js = inter / union
            if inter:
                ev["support"].append(("ssid-set", 25 * js,
                                      f"probed-SSID overlap {inter}/{union} "
                                      f"({', '.join(sorted(a['ssids'] & b['ssids']))})"))
        # rotation hand-offs
        n, best = self._handoffs(a, b)
        if n:
            ev["support"].append(("handoff", 15,
                                  f"rotation hand-off x{n} — one address "
                                  f"went silent, the next appeared "
                                  f"{best[0]:.0f}s later"))
        # RSSI proximity
        if a["rssi_mean"] is not None and b["rssi_mean"] is not None:
            diff = abs(a["rssi_mean"] - b["rssi_mean"])
            if diff <= self.RSSI_CLOSE:
                ev["support"].append(("rssi", 5,
                                      f"mean RSSI within {diff:.1f} dB"))
        # burst cadence similarity
        ca = self._cadence_of(a)
        cb = self._cadence_of(b)
        if ca and cb and abs(ca - cb) / max(ca, cb) <= self.CADENCE_REL:
            ev["support"].append(("cadence", 5,
                                  f"burst cadence {ca:.1f}s vs {cb:.1f}s"))
        # randomization semantics
        r1, r2 = is_randomized(mac1), is_randomized(mac2)
        if r1 and r2:
            ev["support"].append(("rand", 5,
                                  "both MACs are randomized (rotation "
                                  "makes identity plausible)"))
        elif r1 != r2:
            ev["anti"].append(("rand", -8,
                               "one stable, one randomized MAC — a stable "
                               "MAC never 'becomes' randomized mid-dataset"))
        # simultaneity: the silver bullet AGAINST same-device
        same_sensor_overlap, cross = self._overlap(a, b)
        if cross > 1.0:
            ev["anti"].append(("simultaneous", -100,
                               f"observed at DIFFERENT sensors simultaneously "
                               f"({cross:.0f}s) — provably two devices"))
        elif same_sensor_overlap > 1.0:
            ev["anti"].append(("simultaneous", -70,
                               f"observed simultaneously at the same sensor "
                               f"({same_sensor_overlap:.0f}s) with different "
                               f"MACs — two devices"))

        hard_anti = any(w <= -70 for _, w, _ in ev["anti"])
        score = 10 + sum(w for _, w, _ in ev["support"]) \
            + sum(min(w, -5) if hard_anti else 0 * w for _, w, _ in ev["anti"])
        if not hard_anti:
            score += sum(w for _, w, _ in ev["anti"] if w > -70)
        score = max(0.0, min(99.0, score))
        # core teaching rule: a matching fingerprint WITHOUT behavioural
        # corroboration (SSID overlap, rotation hand-off) can never climb
        # past "possible" — same-model devices share fingerprints.
        has_ssid = any(s == "ssid-set" for s, _, _ in ev["support"])
        if not has_ssid and not n:
            score = min(score, 60.0)
            ev.setdefault("caution",
                          "fingerprint-only match: identical hardware stacks, "
                          "zero behavioural link. This is the classic "
                          "same-model coincidence — do not merge.")
        if hard_anti:
            verdict = "different"
        elif score >= 85:
            verdict = "high"
        elif score >= 65:
            verdict = "likely"
        elif score >= 45:
            verdict = "possible"
        else:
            verdict = "low"
        # twin-trap caution: identical fingerprint yet no handoff evidence
        if verdict in ("high", "likely") and not n and \
                any(s == "ssid-set" for s, _, _ in ev["support"]):
            ev.setdefault("caution",
                          "no rotation hand-off observed — could equally be "
                          "a same-model second device; collect more timing "
                          "before concluding")
        elif verdict == "possible" and \
                any(s == "fingerprint" for s, _, _ in ev["support"]):
            ev.setdefault("caution",
                          "fingerprint match alone is NOT identity: same "
                          "phone model → same fingerprint. Need hand-off "
                          "timing or exclusive SSIDs.")
        if hard_anti:
            ev["caution"] = "anti-evidence overrides all support"
        ev.update(score=round(score, 1), verdict=verdict, ssid_jaccard=js)
        return ev

    def _cadence_of(self, d):
        ts = sorted(d["ts_all"])
        if len(ts) < 3:
            return None
        gaps = [b - a for a, b in zip(ts, ts[1:]) if b - a > 0.5]
        if not gaps:
            return None
        gaps.sort()
        big = [g for g in gaps if g >= 5.0] or gaps
        return sum(big) / len(big)

    def matrix(self):
        pairs = []
        macs = self.macs
        for i, m1 in enumerate(macs):
            for m2 in macs[i + 1:]:
                pairs.append(self.evidence(m1, m2))
        return sorted(pairs, key=lambda e: -e["score"])

    def clusters(self, min_verdict="likely"):
        """Union-find over pairs scored >= threshold and not anti."""
        parent = {m: m for m in self.macs}
        order = {"high": 3, "likely": 2, "possible": 1}
        min_score = {"likely": 65, "possible": 45, "high": 85}[min_verdict]

        def find(x):
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x
        for ev in self.matrix():
            if ev["verdict"] == "different" or ev["score"] < min_score:
                continue
            parent[find(ev["pair"][0])] = find(ev["pair"][1])
        groups = defaultdict(list)
        for m in self.macs:
            groups[find(m)].append(m)
        out = []
        for root, members in groups.items():
            members = sorted(members,
                             key=lambda m: self.by_mac[m]["first"])
            score = min((e["score"] for e in self.matrix()
                         if e["pair"][0] in members and e["pair"][1] in members
                         and e["pair"][0] != e["pair"][1]), default=100.0)
            note = ("distinct singleton — no evidence tying it to anything"
                    if len(members) == 1 else
                    f"merge supported by {len(members) - 1} link(s); treat as "
                    f"a HYPOTHESIS, confidence collapses if any member pair "
                    f"is ever observed simultaneously")
            out.append({"members": members, "size": len(members),
                        "min_pair_score": score, "note": note})
        return sorted(out, key=lambda g: -g["size"])


# ========================================================== TRACK-LAB ENGINE

TRACK_VISIT_GAP_S = 180.0


class Tracker:
    """Presence history → visits, patterns, movement edges, tracking risk."""

    def __init__(self, obs_list, since_s: float = 0.0):
        self.obs = obs_list if not since_s else \
            [o for o in obs_list if o.ts >= time.time() - since_s]
        self.by_mac = obs_by_mac(self.obs)

    def visits(self, mac):
        """Sessionize one MAC's observations into (sensor, start, end, n)."""
        d = self.by_mac.get(mac, {})
        visits = []
        for sensor, ts_list in d.get("sensor_spans", {}).items():
            ts_list = sorted(ts_list)
            cur = [ts_list[0]]
            for t in ts_list[1:]:
                if t - cur[-1] > TRACK_VISIT_GAP_S:
                    visits.append((sensor, cur[0], cur[-1],
                                   len(cur)))
                    cur = [t]
                else:
                    cur.append(t)
            visits.append((sensor, cur[0], cur[-1], len(cur)))
        visits.sort(key=lambda v: v[1])
        return visits

    def pattern(self, mac):
        vs = self.visits(mac)
        hours = [0] * 24
        weekdays = [0] * 7
        dwell = defaultdict(float)
        days = set()
        edges = defaultdict(int)
        for i, (sensor, t0, t1, n) in enumerate(vs):
            lt = time.localtime(t0)
            hours[lt.tm_hour] += 1
            weekdays[lt.tm_wday] += 1
            days.add(time.strftime("%Y-%m-%d", time.localtime(t0)))
            dwell[sensor] += max(60.0, t1 - t0)
            if i:
                prev = vs[i - 1]
                same_day = time.strftime("%j", time.localtime(t0)) == \
                    time.strftime("%j", time.localtime(prev[2]))
                if prev[0] != sensor and same_day and \
                        0 < t0 - prev[2] <= 6 * 3600:
                    edges[(prev[0], sensor)] += 1
        return {"mac": mac, "visits": vs, "visit_count": len(vs),
                "days_present": sorted(days), "hours": hours,
                "weekdays": weekdays,
                "dwell_min": {k: round(v / 60, 1) for k, v in dwell.items()},
                "edges": dict(edges),
                "randomized": is_randomized(mac),
                "vendor": oui_lookup(mac)}

    def table(self):
        out = []
        for mac, d in sorted(self.by_mac.items(),
                             key=lambda kv: -kv[1]["frames"]):
            p = self.pattern(mac)
            out.append({"mac": mac, "vendor": p["vendor"],
                        "randomized": p["randomized"],
                        "frames": d["frames"], "visits": p["visit_count"],
                        "days": len(p["days_present"]),
                        "sensors": sorted(d["sensor_spans"]),
                        "first": d["first"], "last": d["last"]})
        return out

    def movement_edges(self, min_count=2):
        edges = defaultdict(int)
        for mac in self.by_mac:
            for (a, b), n in self.pattern(mac)["edges"].items():
                if n >= min_count:
                    edges[(a, b)] += n
        return dict(edges)

    def trackability(self, mac):
        """Explain in words how trackable this MAC is, and why."""
        p = self.pattern(mac)
        if p["randomized"]:
            verdict = ("LOW — randomized MAC observed once; tomorrow the "
                       "same person may present a different address")
            reason = "rotating-identifier defence visibly working"
        elif len(p["days_present"]) >= 5 and p["visit_count"] >= 8:
            verdict = ("HIGH — persistent identifier + multi-day routine: "
                       "identity, schedule and movement edges all emerge")
            reason = f"{len(p['days_present'])} distinct days"
        elif len(p["days_present"]) >= 2:
            verdict = "MEDIUM — repeat observations but too few for a full routine"
            reason = f"{len(p['days_present'])} days so far"
        else:
            verdict = ("LOW (for now) — a single visit reveals presence, "
                       "not lifestyle")
            reason = "one observation window: short-term view"
        return {"mac": mac, "verdict": verdict, "reason": reason,
                "pattern": p}


def heatmap_ascii(hours):
    top = max(hours) or 1
    bars = "▁▂▃▄▅▆▇█"
    return "".join(bars[min(7, int(8 * h / top) - 1 if h else 0)]
                   for h in hours) + f"   (hours 00–23, peak {top})"


# ------------------------------------------------------------------ scoring

def score_maclab(truth_rows, answer_clusters):
    """Score a student's cluster answer against instructor ground truth.

    answer_clusters: [["MAC1", "MAC2"], ...] — each inner list claims "these
    MACs are the same physical lab device".
    Returns dict with score (0-100), per-claim feedback, and the lesson each
    marker is checking. The twin trap is a first-class scoring dimension:
    merging two devices that were *simultaneously observed* is flagged as
    the specific mistake it is.
    """
    def macset(rows):
        out = {}
        for r in rows:
            macs = [m.strip().upper() for m in (r.get("macs") or "")
                    .replace(",", ";").split(";") if m.strip()
                    and "(" not in m]
            out[r["device"]] = {"macs": macs, "label": r.get("label", ""),
                                "notes": r.get("notes", ""),
                                "rotates": r.get("rotates", "")}
        return out
    gt = macset(truth_rows)
    membership = {}
    for dev, info in gt.items():
        for m in info["macs"]:
            membership[m] = dev
    feedback = []
    points = 0.0
    possible = 0.0

    # 1) Correct merges: for every device with >1 observed MACs, did the
    # student group them into one cluster?
    tagged = set()
    claim_to_dev = {}
    for cluster in answer_clusters:
        devs = {membership.get(m, "?") for m in
                [x.strip().upper() for x in cluster]}
        devs.discard("?")
        for d in devs:
            claim_to_dev.setdefault(d, set()).update(
                x.strip().upper() for x in cluster)
    for dev, info in gt.items():
        macs = info["macs"]
        if len(macs) <= 1:
            continue
        possible += 30
        got = {m for m in claim_to_dev.get(dev, set()) if m in macs}
        if got == set(macs):
            points += 30
            feedback.append(f"✅ {dev}: all {len(macs)} rotated MACs merged "
                            f"— {info['notes']}")
            tagged.add(dev)
        elif got:
            points += 10
            feedback.append(f"⚠️ {dev}: only {len(got)}/{len(macs)} MACs "
                            f"merged — partial correlation")
        else:
            feedback.append(f"❌ {dev}: rotator missed — its MACs "
                            f"({', '.join(macs)}) were never merged")

    # 2) Wrong merges: any cluster mixing MACs from ≥2 distinct devices.
    wrong = []
    for cluster in answer_clusters:
        macs = [x.strip().upper() for x in cluster]
        devs = {membership.get(m, "?") for m in macs} - {"?", None}
        if len(devs) > 1:
            wrong.append((cluster, sorted(devs)))
    possible_trap = any(len(gt[d]["macs"]) == 1 for d in gt)
    for cluster, devs in wrong:
        twins = [d for d in devs if "twin" in gt[d]["label"]]
        if twins:
            points -= 25
            feedback.append("❌ TWIN TRAP: you merged "
                            f"{' + '.join(devs)} — same fingerprint, same "
                            "SSID set... but they were observed at the same "
                            "time. Simultaneous presence is proof of two "
                            "devices; fingerprint is not identity.")
        else:
            points -= 15
            feedback.append("❌ false merge across devices "
                            f"({', '.join(devs)}): -15")
    possible += 20
    if not wrong:
        points += 20
        feedback.append("✅ no false merges — including the twin decoys")

    # 3) Singletons correctly left alone?
    solo_claims = [c for c in answer_clusters if len(c) == 1]

    score = max(0.0, min(100.0, 100.0 * points / max(possible, 1)))
    if not claim_to_dev and not solo_claims:
        score = 0.0
        feedback.insert(0, "no answer submitted")
    return {"score": round(score, 1), "points": round(points, 1),
            "possible": possible, "feedback": feedback,
            "answer_summary": [sorted(c) for c in answer_clusters]}


TRACK_QUIZ_WEIGHTS = {"q_identity": 30, "q_untrackable": 25,
                      "q_edge": 20, "q_short_window": 15,
                      "q_false_positive": 10}


def score_tracklab(truth_rows, answers):
    """Score the tracking-lab quiz against ground truth.

    answers: {"q_identity": mac, "q_untrackable": "Visitor-B",
              "q_edge": "lab-north>canteen", "q_short_window": "insufficient",
              "q_false_positive": mac_of_decoy}
    """
    gt = {r["device"]: r for r in truth_rows}
    fb = []
    pts = 0.0
    # Q1: identify Student-A's MAC (the decoy shares the OUI!)
    a = answers.get("q_identity", "").strip().upper()
    correct = gt.get("Student-A", {}).get("macs", "").upper()
    decoy = gt.get("Decoy-A'", {}).get("macs", "").upper()
    if a == correct:
        pts += TRACK_QUIZ_WEIGHTS["q_identity"]
        fb.append("✅ Q1: correct — Student-A's persistent MAC identified "
                  "from the weekday lab-north→canteen→lab-south routine")
    elif a == decoy:
        fb.append("❌ Q1 FALSE POSITIVE: that MAC shares Student-A's OUI and "
                  "morning window, but it appears ONLY in the corridor — "
                  "that's the decoy. Same-OUI ≠ same owner.")
    elif a:
        fb.append(f"❌ Q1: {a} is not Student-A")
    else:
        fb.append("○ Q1: unanswered")
    # Q2: which device defeats tracking
    u = answers.get("q_untrackable", "")
    if u == "Visitor-B":
        pts += TRACK_QUIZ_WEIGHTS["q_untrackable"]
        fb.append("✅ Q2: correct — daily MAC rotation breaks by-MAC history; "
                  "the privacy defence, observed working")
    else:
        fb.append("❌ Q2: Visitor-B is the answer — its history is "
                  "deliberately unusable (a new identifier each visit)")
    # Q3: dominant movement edge
    e = answers.get("q_edge", "")
    if e == "lab-north>canteen":
        pts += TRACK_QUIZ_WEIGHTS["q_edge"]
        fb.append("✅ Q3: correct — the lunch-hour edge dominates Student-A's "
                  "movement graph")
    else:
        fb.append("❌ Q3: look at the transition counts (lab-north→canteen "
                  "recurs every weekday)")
    # Q4: short-window honesty
    s = answers.get("q_short_window", "")
    if s == "insufficient":
        pts += TRACK_QUIZ_WEIGHTS["q_short_window"]
        fb.append("✅ Q4: correct — a 2-day window cannot support a routine "
                  "claim; longer retention is what creates the privacy "
                  "exposure")
    else:
        fb.append("❌ Q4: short windows under-support conclusions — that's "
                  "the privacy point")
    # Q5: decoy spotted
    d = answers.get("q_false_positive", "").strip().upper()
    if d == decoy:
        pts += TRACK_QUIZ_WEIGHTS["q_false_positive"]
        fb.append("✅ Q5: correct — you located the lookalike before it "
                  "poisoned the attribution")
    total = sum(TRACK_QUIZ_WEIGHTS.values())
    return {"score": round(100.0 * pts / total, 1),
            "points": round(pts, 1), "possible": total, "feedback": fb,
            "answers": answers}


# ------------------------------------------------------------------- store

class DevLabStore:
    """Attempts + events for both labs. Owner-only (0600)."""

    _SCHEMA = """
CREATE TABLE IF NOT EXISTS dl_attempts(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, lab TEXT, question TEXT,
  answer TEXT, score REAL, verdict TEXT, ip TEXT);
CREATE TABLE IF NOT EXISTS dl_events(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, lab TEXT, kind TEXT,
  detail TEXT, ip TEXT);
"""

    def __init__(self, path: str = ":memory:"):
        self.path = path
        self.memory = path == ":memory:"
        self.lock = threading.RLock()
        if not self.memory:
            os.makedirs(os.path.dirname(os.path.abspath(path)) or ".",
                        exist_ok=True)
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        with self.lock:
            self.db.executescript(self._SCHEMA)
            self.db.commit()
        if not self.memory:
            ensure_secure_storage(self.path, fix=True)

    def event(self, lab, kind, detail="", ip=""):
        with self.lock:
            self.db.execute("INSERT INTO dl_events VALUES(NULL,?,?,?,?,?)",
                            (time.time(), lab, str(kind)[:40],
                             str(detail)[:300], str(ip)[:45]))
            self.db.commit()

    def attempt(self, lab, question, answer, score, verdict, ip=""):
        with self.lock:
            cur = self.db.execute(
                "INSERT INTO dl_attempts VALUES(NULL,?,?,?,?,?,?,?)",
                (time.time(), lab, str(question)[:60], str(answer)[:500],
                 float(score), str(verdict)[:300], str(ip)[:45]))
            self.db.commit()
            return cur.lastrowid

    def _rows(self, table_path, lab, limit):
        q = ("SELECT * FROM dl_attempts WHERE lab=? ORDER BY ts DESC LIMIT ?"
             if table_path == "attempts" else
             "SELECT * FROM dl_events WHERE lab=? ORDER BY ts DESC LIMIT ?")
        with self.lock:
            rows = [dict(r) for r in self.db.execute(q, (lab, limit))]
        for r in rows:
            r["time"] = time.strftime("%H:%M:%S", time.localtime(r["ts"]))
        return rows

    def attempts(self, lab, limit=200):
        return self._rows("attempts", lab, limit)

    def events(self, lab, limit=200):
        return self._rows("events", lab, limit)

    def funnel(self, lab):
        with self.lock:
            def one(q):
                return self.db.execute(q, (lab,)).fetchone()[0]
            return {"views": one("SELECT COUNT(*) FROM dl_events WHERE "
                                 "lab=? AND kind='page-view'"),
                    "attempts": one("SELECT COUNT(*) FROM dl_attempts "
                                    "WHERE lab=?"),
                    "best_score": one("SELECT COALESCE(MAX(score),0) FROM "
                                      "dl_attempts WHERE lab=?")}

    def reset(self, lab=None):
        n = 0
        with self.lock:
            if lab:
                for t in ("dl_attempts", "dl_events"):
                    n += (self.db.execute(f"DELETE FROM {t} WHERE lab=?",
                                          (lab,)).rowcount or 0)
            else:
                for t in ("dl_attempts", "dl_events"):
                    n += self.db.execute(f"DELETE FROM {t}").rowcount or 0
            self.db.commit()
        return n

    def close(self):
        with self.lock:
            self.db.commit()
            self.db.close()


# --------------------------------------------------------- exercise sheets

def maclab_exercises() -> str:
    items = [
        ("1. See the randomization", "Run `mac-lab inventory` — which MACs "
         "are locally-administered (bit 2 set)? Why can't you read a device's "
         "identity from its MAC alone anymore?"),
        ("2. The fingerprint that leaks through", "In `mac-lab correlate`, "
         "find the column of evidence. Why do iOS and Android phones have "
         "distinct probe-request IE fingerprints even when the MAC is random? "
         "Which IE makes the strongest tell?"),
        ("3. Correctly correlate the rotator", "Using `mac-lab explain "
         "MAC1 MAC2`, assemble the evidence for Device-A's three MACs. What "
         "single observation converts 'possible' into 'high'?"),
        ("4. Fall for the twin (then catch it)", "The twins share fingerprint "
         "AND probed-SSIDs. Write down your naive verdict first, then find "
         "the anti-evidence. What principle does 'observed simultaneously' "
         "invoke?"),
        ("5. Score yourself", "`mac-lab score dataset --submit answer.json` "
         "or the web quiz. Which mistake costs most, and why is *not* "
         "merging sometimes the win?"),
        ("6. Defence review", "For each correlation signal the engine used, "
         "name the mitigation a real device could deploy. Which signal is "
         "hardest to remove, and why?"),
    ]
    return ("MAC-lab — guided exercises\n\n" + "\n\n".join(
        f"■ {t}\n{b}" for t, b in items) + "\n")


def tracklab_exercises() -> str:
    items = [
        ("1. Map the air", "`track-lab inventory` — how many MACs, visits, "
         "days? Who is most present?"),
        ("2. Build a history", "`track-lab history --mac <M>` — the visit "
         "timeline. What does dwell time say about *purpose* at a sensor?"),
        ("3. Patterns emerge", "`track-lab patterns --mac <M>` — weekday and "
         "hour heatmaps plus movement edges. Reconstruct Student-A's day."),
        ("4. Short vs long", "`track-lab compare --since -2d` then full. "
         "Which claims does the short window support? When exactly does "
         "'visited once' become 'has a routine'?"),
        ("5. The decoy", "Find the second MAC with Student-A's OUI. Assign "
         "it to Student-A first, then check the *locations*. What rule of "
         "attribution did you just violate?"),
        ("6. The ghost", "Which device defeats you entirely, and HOW? What "
         "would you need to track it (and why does the lab forbid doing "
         "that to real devices)?"),
        ("7. Privacy tebrief", "List every inference track-lab made about a "
         "synthetic device (presence, habitual times, lunch location...). "
         "Map each to a real-world abuse case and a mitigation"),
    ]
    return ("Track-lab — guided exercises\n\n" + "\n\n".join(
        f"■ {t}\n{b}" for t, b in items) + "\n")


# ---------------------------------------------------------- report helpers

_DAY0 = 86400


def timeline_rows(obs_list, bucket_s=900.0, max_rows=60):
    """Per-MAC presence matrix rows for ascii/web tables."""
    by = obs_by_mac(obs_list)
    if not by:
        return [], 0, 0
    t0 = min(d["first"] for d in by.values())
    t1 = max(d["last"] for d in by.values())
    nb = max(1, min(96, int((t1 - t0) / bucket_s) + 1))
    rows = []
    for mac, d in sorted(by.items(), key=lambda kv: kv[1]["first"]):
        cells = [""] * nb
        for sensor, spans in d["sensor_spans"].items():
            for ts in spans:
                k = int((ts - t0) / bucket_s)
                letter = sensor.split("-")[-1][:1].upper()
                cells[k] = letter if not cells[k] else cells[k] + letter
        rows.append({"mac": mac, "cells": cells, "randomized":
                     is_randomized(mac), "frames": d["frames"]})
    return rows, t0, t1


def export_rows_csv(rows, path, fields):
    import csv as _csv
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        w = _csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)
    secure_file(path)
    return path


# ------------------------------------------------------------- web (shared)

_CSS = """
:root{--bg:#0f172a;--card:#1e293b;--ink:#e2e8f0;--mut:#94a3b8;--acc:#38bdf8;
--ok:#34d399;--warn:#fbbf24;--bad:#f87171;--line:#334155}
*{box-sizing:border-box}body{margin:0;font:15px/1.55 -apple-system,Segoe UI,
Roboto,Helvetica,Arial,sans-serif;background:var(--bg);color:var(--ink)}
a{color:var(--acc)}.wrap{max-width:1080px;margin:0 auto;padding:24px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;
padding:18px;margin:14px 0}
h1{font-size:22px;margin:6px 0}h2{font-size:16px;margin:16px 0 6px}
.small{color:var(--mut);font-size:12.5px}
table{width:100%;border-collapse:collapse;font-size:12.5px;margin-top:8px}
th,td{text-align:left;padding:4px 7px;border-bottom:1px solid var(--line);
font-family:ui-monospace,monospace;vertical-align:top}
th{color:var(--mut);font-size:11px;text-transform:uppercase}
.ok{color:var(--ok)}.bad{color:var(--bad)}.warn{color:var(--warn)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
gap:10px;margin:12px 0}
.stat{background:#0b1220;border:1px solid var(--line);border-radius:10px;
padding:12px}.stat b{display:block;font-size:23px}
.btn{display:inline-block;background:var(--acc);color:#082f49;border:0;
border-radius:8px;padding:9px 15px;font-weight:600;cursor:pointer;
text-decoration:none;font-size:14px}
.btn.danger{background:var(--bad);color:#450a0a}
.btn.ghost{background:transparent;color:var(--acc);border:1px solid var(--acc)}
input[type=text]{width:100%;padding:9px 11px;margin:5px 0 12px;border-radius:8px;
border:1px solid var(--line);background:#0b1220;color:var(--ink);
font-family:ui-monospace,monospace;font-size:13px}
select{padding:8px;border-radius:8px;background:#0b1220;color:var(--ink);
border:1px solid var(--line)}
code{background:#0b1220;padding:1px 5px;border-radius:4px}
.chip{display:inline-block;padding:2px 9px;border-radius:999px;font-size:11.5px;
border:1px solid var(--line)}
.chip.high{background:#052e1b;color:var(--ok);border-color:var(--ok)}
.chip.likely{background:#0b2b22;color:var(--ok)}
.chip.possible{background:#2b220b;color:var(--warn)}
.chip.low{background:#241f1f;color:var(--mut)}
.chip.different{background:#3b0d0d;color:var(--bad)}
textarea{width:100%;height:110px;background:#0b1220;color:var(--ink);
border:1px solid var(--line);border-radius:8px;padding:8px;
font-family:ui-monospace,monospace;font-size:13px}
.tl td.hot{background:#7c2d12}.tl td.warm{background:#42370a}
.hero{background:#0b1220;border:1px dashed var(--warn);border-radius:10px;
padding:12px 14px;margin:14px 0}
"""


def _page(title, body):
    return ("<!doctype html><html lang='en'><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>{html.escape(title)}</title><style>{_CSS}</style></head>"
            f"<body>{body}</body></html>").encode()


def new_token():
    return _secrets.token_urlsafe(9)


class _BaseHandler(BaseHTTPRequestHandler):
    server_version = "wifiscanner-devlab"
    protocol_version = "HTTP/1.1"
    _MAX_POST = 65536

    def log_message(self, fmt, *args):
        pass

    @property
    def app(self):
        return self.server.app

    def _send(self, body: bytes, status: int = 200,
              ctype: str = "text/html; charset=utf-8"):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, obj, status=200):
        self._send(json.dumps(obj, indent=1, default=str).encode(), status,
                   "application/json; charset=utf-8")

    def _redirect(self, loc):
        self.send_response(303)
        self.send_header("Location", loc)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _client(self):
        return self.client_address[0]

    def _tok_ok(self, u):
        tok = parse_qs(u.query).get("token", [""])[0]
        return bool(tok) and _secrets.compare_digest(tok, self.app.token)

    def _read_form(self):
        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
        except ValueError:
            length = 0
        if length > self._MAX_POST:
            return None
        raw = self.rfile.read(length) if length else b""
        return {k: v[0] for k, v in
                parse_qs(raw.decode("utf-8", "ignore"),
                         keep_blank_values=True).items()}


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, handler, app):
        self.app = app
        super().__init__(address, handler)


# ------------------------------------------------------------- mac-lab web

class MacLabApp:
    def __init__(self, dataset, store: DevLabStore, token: str,
                 reveal_truth=False):
        self.dataset = dataset
        self.store = store
        self.token = token
        self.started = time.time()
        self.lock = threading.RLock()
        self.engine = CorrelationEngine(dataset["obs"])
        self.matrix = self.engine.matrix()
        self.clusters = self.engine.clusters()
        self.truth = dataset["truth"] if reveal_truth else dataset["truth"]

    def regenerate(self):
        """Instructor-only: fresh dataset (seed+1) in place; rebuild engine."""
        with self.lock:
            seed = int(self.dataset["manifest"].get("seed", 8)) + 1
            generate_maclab_dataset(self.dataset["dir"], seed=seed,
                                    fresh=True)
            self.dataset = load_dataset(self.dataset["dir"])
            self.engine = CorrelationEngine(self.dataset["obs"])
            self.matrix = self.engine.matrix()
            self.clusters = self.engine.clusters()
            self.truth = self.dataset["truth"]
            return seed

    def inventory(self):
        m = self.dataset["manifest"]
        return {"sensors": m["sensors"], "frames": m["frames"],
                "days_span": round((m["end"] - m["start"]) / 86400, 2),
                "macs": len(self.engine.by_mac),
                "randomized_macs": sum(1 for x in self.engine.macs
                                       if is_randomized(x))}


def _maclab_home(app: MacLabApp) -> bytes:
    inv = app.inventory()
    macs = app.engine.macs
    rows = "".join(
        f"<tr><td>{m}</td><td>{'🔀 random' if is_randomized(m) else '📌 stable'}"
        f"</td><td>{html.escape(oui_lookup(m))}</td>"
        f"<td>{app.engine.by_mac[m]['frames']}</td>"
        f"<td>{html.escape(app.engine.by_mac[m]['fp'][:34])}…</td>"
        f"<td>{html.escape(', '.join(sorted(app.engine.by_mac[m]['ssids'])) or '-')}</td></tr>"
        for m in macs)
    body = f"""
<div class='wrap'>
 <h1>🛰 MAC randomization &amp; deanonymization lab</h1>
 <p class='small'>dataset: {html.escape(os.path.basename(app.dataset['dir']))} ·
 {inv['days_span']} days · sensors {', '.join(inv['sensors'])} · synthetic
 devices only</p>
 <div class='grid'>
  <div class='stat'>frames<b>{inv['frames']}</b></div>
  <div class='stat'>MACs observed<b>{inv['macs']}</b></div>
  <div class='stat'>randomized<b>{inv['randomized_macs']}</b></div>
  <div class='stat'>sensors<b>{len(inv['sensors'])}</b></div>
 </div>
 <div class='card'><h2>Observed MACs ({len(macs)})</h2>
  <table><tr><th>MAC</th><th>Addr type</th><th>Vendor-ish</th><th>Frames</th>
  <th>IE fingerprint</th><th>Probed SSIDs</th></tr>{rows}</table>
 </div>
 <div class='hero'><b>The lab question:</b> some of these MACs are the same
 physical device with a rotated address; two others are the TWIN decoys —
 identical fingerprints, guaranteed distinct. Evidence wins; fingerprints
 alone lose. When you're ready: <a href='/matrix'>the evidence matrix</a>,
 <a href='/quiz'>📝 submit your clustering</a>,
 <a href='/exercises'>📋 exercises</a>.</div>
</div>"""
    return _page("MAC randomization lab", body)


def _maclab_matrix(app: MacLabApp, focus_a="", focus_b="") -> bytes:
    evs = app.matrix
    if focus_a and focus_b:
        evs = [app.engine.evidence(focus_a.upper(), focus_b.upper())]
    parts = []
    for e in evs[:60]:
        sup = "".join(f"<li class='ok'>+{w:g} {html.escape(txt)}</li>"
                      for name, w, txt in e["support"])
        ant = "".join(f"<li class='bad'>{w:g} {html.escape(txt)}</li>"
                      for name, w, txt in e["anti"])
        caution = (f"<p class='warn'>⚠ {html.escape(e['caution'])}</p>"
                   if e.get("caution") else "")
        parts.append(f"<div class='card'><h2>{e['pair'][0]} ⇄ {e['pair'][1]} "
                     f"<span class='chip {e['verdict']}'>{e['verdict']} "
                     f"{e['score']}</span></h2><ul>{sup}{ant}</ul>{caution}"
                     f"</div>")
    clusters = "".join(
        f"<tr><td>{', '.join(c['members'])}</td><td>{c['size']}</td>"
        f"<td>{html.escape(c['note'])}</td></tr>" for c in app.clusters)
    body = f"""
<div class='wrap'>
 <h1>🧩 Correlation evidence</h1>
 <p class='small'>the engine's reasoning, exposed pairwise — confidence is a
 hypothesis score with named support AND anti-evidence, never a bare
 "same device".</p>
 <div class='card'><h2>Engine clusters (hypotheses, not verdicts of fact)</h2>
  <table><tr><th>Candidate device</th><th>MACs</th><th>Caveat</th></tr>
  {clusters}</table></div>
 {''.join(parts)}
 <p><a href='/'>← home</a> · <a href='/quiz'>submit clustering →</a></p>
</div>"""
    return _page("Correlation matrix", body)


def _maclab_quiz(app, result=None) -> bytes:
    macs = app.engine.macs
    roster = "".join(f"<li><code>{m}</code> — {'random' if is_randomized(m) else 'stable'}, "
                     f"{app.engine.by_mac[m]['frames']} frames</li>"
                     for m in macs)
    verdict_html = ""
    if result:
        lis = "".join(f"<li>{html.escape(f)}</li>" for f in result["feedback"])
        cls = "ok" if result["score"] >= 80 else "warn" if result["score"] >= 50 else "bad"
        verdict_html = (f"<div class='card'><h2 class='{cls}'>Score: "
                        f"{result['score']}/100</h2><ul>{lis}</ul></div>")
    body = f"""
<div class='wrap'>
 <h1>📝 Correlation exercise</h1>
 {verdict_html}
 <div class='card'><h2>Observed MACs</h2><ul class='small'>{roster}</ul></div>
 <div class='card'>
  <h2>Your clustering</h2>
  <p class='small'>One line per hypothesized device: MACs comma-separated.
  Singletons may be omitted or listed alone. Wrong merges cost points —
  including the twin decoys.</p>
  <form method='POST' action='/quiz'>
   <textarea name='clusters' placeholder="AA:BB:CC:DD:EE:01, AA:BB:CC:DD:EE:02&#10;..."></textarea>
   <button class='btn'>Score my answer</button>
  </form>
  <p class='small'>Tip: open <a href='/matrix'>the evidence matrix</a> in
  another tab. Scoring happens server-side against instructor ground truth;
  attempts are logged.</p></div>
 <p><a href='/'>← home</a></p></div>"""
    return _page("Correlation exercise", body)


def _maclab_dash(app: MacLabApp) -> bytes:
    truth_rows = "".join(
        f"<tr><td>{html.escape(r['device'])}</td>"
        f"<td>{html.escape(r['label'])}</td><td>{html.escape(r['macs'])}</td>"
        f"<td>{html.escape(r['rotates'])}</td>"
        f"<td class='small'>{html.escape(r['notes'])}</td></tr>"
        for r in app.truth)
    js = """
const TOKEN="__TOKEN__";
async function tick(){try{const r=await fetch('/api/state?token='+TOKEN);
 if(!r.ok)return;const d=await r.json();
 document.getElementById('s_v').textContent=d.funnel.views;
 document.getElementById('s_a').textContent=d.funnel.attempts;
 document.getElementById('s_b').textContent=d.funnel.best_score;
 const at=document.getElementById('attempts');at.innerHTML='';
 d.attempts.forEach(a=>{const tr=document.createElement('tr');
  ['time','question','score','ip'].forEach(k=>{const td=
   document.createElement('td');td.textContent=a[k];tr.appendChild(td);});
  const vb=document.createElement('td');vb.textContent=a.verdict;
  vb.style.fontSize='11px';tr.appendChild(vb);at.appendChild(tr);});
}catch(e){}}
async function doReset(){if(!confirm('Wipe attempts+events for this lab?'))return;
 await fetch('/api/reset?token='+TOKEN,{method:'POST'});tick();}
async function doRegen(){if(!confirm('Regenerate a FRESH dataset (seed+1)? '+
 'Student answers for the old one stop making sense.'))return;
 const r=await fetch('/api/regenerate?token='+TOKEN,{method:'POST'});
 const d=await r.json();alert('New dataset: seed '+d.seed+', '+d.frames+
 ' frames, '+d.macs+' MACs');location.href='/';}
document.getElementById('rb').addEventListener('click',doReset);
document.getElementById('gb').addEventListener('click',doRegen);
tick();setInterval(tick,3000);
""".replace("__TOKEN__", app.token)
    body = f"""
<div class='wrap'>
 <h1>🎓 Instructor — deanonymization lab</h1>
 <p class='small'>dataset <code>{html.escape(app.dataset['dir'])}</code> ·
 <span id='s_v'>0</span> views · <span id='s_a'>0</span> attempts · best
 score <span id='s_b'>0</span></p>
 <div class='card'><h2>Ground truth (instructor-only)</h2>
  <table><tr><th>Device</th><th>Label</th><th>MACs</th><th>Rotates</th>
  <th>What it proves</th></tr>{truth_rows}</table></div>
 <div class='card'><h2>Student attempts (detection log)</h2>
  <table><tr><th>Time</th><th>Q</th><th>Score</th><th>IP</th>
  <th>Verdict</th></tr><tbody id='attempts'></tbody></table></div>
 <div class='card'><h2>Controls</h2>
  <button class='btn danger' id='rb'>🧹 Reset attempts</button>
  <button class='btn warn' id='gb' style='background:var(--warn);color:#422006'>
   🎲 Regenerate fresh dataset (seed+1)</button>
  <a class='btn ghost' href='/'>student view</a>
  <p class='small'>Reset wipes logged attempts; regenerate builds a brand-new
  dataset in place so each class roster gets a different rotator/twins.
  CLI equivalent: <code>wifiscanner mac-lab make-dataset DIR --fresh
  --seed N+1</code></p>
 </div></div><script>{js}</script>"""
    return _page("Instructor — deanonymization lab", body)


class MacLabHandler(_BaseHandler):
    def do_GET(self):
        u = urlparse(self.path)
        path = u.path.rstrip("/") or "/"
        app = self.app
        if path == "/health":
            return self._json({"ok": True, "lab": "mac"})
        if path == "/":
            app.store.event("mac", "page-view", "home", self._client())
            return self._send(_maclab_home(app))
        if path == "/matrix":
            qs = parse_qs(u.query)
            a = qs.get("a", [""])[0].strip().upper()
            b = qs.get("b", [""])[0].strip().upper()
            return self._send(_maclab_matrix(app, a if a and b else "",
                                             b if a and b else ""))
        if path == "/quiz":
            return self._send(_maclab_quiz(app))
        if path == "/exercises":
            return self._send(_page("MAC-lab exercises",
                                    "<div class='wrap'><pre style='white-space:"
                                    "pre-wrap'>" + html.escape(
                                        maclab_exercises()) +
                                    "</pre><p><a href='/'>← home</a></p></div>"))
        if path == "/favicon.ico":
            return self._send(b"", 204, "image/x-icon")
        if path == "/api/state":
            if not self._tok_ok(u):
                return self._json({"error": "not found"}, 404)
            return self._json({"funnel": app.store.funnel("mac"),
                               "attempts": app.store.attempts("mac"),
                               "events": app.store.events("mac")})
        if path == "/i/" + app.token:
            app.store.event("mac", "page-view", "instructor", self._client())
            return self._send(_maclab_dash(app))
        if path.startswith("/i/"):
            return self._json({"error": "not found"}, 404)
        return self._redirect("/")

    def do_POST(self):
        u = urlparse(self.path)
        path = u.path.rstrip("/") or "/"
        app = self.app
        form = self._read_form()
        if form is None:
            return self._json({"error": "payload too large"}, 413)
        if path == "/quiz":
            clusters = []
            for line in form.get("clusters", "").splitlines():
                macs = [x.strip() for x in line.split(",") if x.strip()]
                if macs:
                    clusters.append(macs)
            result = score_maclab(app.truth, clusters)
            app.store.attempt("mac", "cluster", ";".join(
                ",".join(c) for c in clusters), result["score"],
                " | ".join(result["feedback"])[:280], self._client())
            log_attempt = "mac-lab attempt score=%s" % result["score"]
            import logging as _lg
            _lg.getLogger("wifiscanner").info(log_attempt)
            return self._send(_maclab_quiz(app, result))
        if path == "/api/reset":
            if not self._tok_ok(u):
                return self._json({"error": "not found"}, 404)
            n = app.store.reset("mac")
            app.store.event("mac", "reset", f"{n} rows", self._client())
            return self._json({"ok": True, "removed": n})
        if path == "/api/regenerate":
            if not self._tok_ok(u):
                return self._json({"error": "not found"}, 404)
            seed = app.regenerate()
            app.store.event("mac", "regenerate", f"seed={seed}",
                            self._client())
            return self._json({"ok": True, "seed": seed,
                               "frames": len(app.dataset["obs"]),
                               "macs": len(app.engine.by_mac)})
        return self._json({"error": "not found"}, 404)


def make_maclab_server(bind, port, app):
    return _Server((bind, int(port)), MacLabHandler, app)


# ------------------------------------------------------------ track-lab web

class TrackLabApp:
    def __init__(self, dataset, store: DevLabStore, token: str):
        self.dataset = dataset
        self.store = store
        self.token = token
        self.started = time.time()
        self.lock = threading.RLock()
        self.full = Tracker(dataset["obs"])
        self.truth = dataset["truth"]

    def regenerate(self):
        """Instructor-only: fresh dataset (seed+1, same span) in place."""
        with self.lock:
            m = self.dataset["manifest"]
            seed = int(m.get("seed", 9)) + 1
            generate_tracklab_dataset(self.dataset["dir"], seed=seed,
                                      days=int(m.get("days", 14)),
                                      fresh=True)
            self.dataset = load_dataset(self.dataset["dir"])
            self.full = Tracker(self.dataset["obs"])
            self.truth = self.dataset["truth"]
            return seed

    def window_tracker(self, since_s):
        return Tracker(self.dataset["obs"], since_s=since_s)


_WEEK = "Mon Tue Wed Thu Fri Sat Sun".split()


def _tracklab_home(app: TrackLabApp) -> bytes:
    m = app.dataset["manifest"]
    tbl = app.full.table()
    rows = "".join(
        f"<tr><td>{t['mac']}</td><td>{html.escape(t['vendor'])}</td>"
        f"<td>{'🔀' if t['randomized'] else '📌'}</td><td>{t['frames']}</td>"
        f"<td>{t['visits']}</td><td>{t['days']}</td>"
        f"<td>{html.escape(', '.join(t['sensors']))}</td></tr>"
        for t in tbl[:25])
    body = f"""
<div class='wrap'>
 <h1>📡 Long-term device tracking lab</h1>
 <p class='small'>dataset <code>{html.escape(os.path.basename(app.dataset['dir']))}</code>
 · {m.get('days', '?')} days · sensors {', '.join(m['sensors'])} · all devices
 synthetic, all locations the authorised lab grid</p>
 <div class='grid'>
  <div class='stat'>frames<b>{m['frames']}</b></div>
  <div class='stat'>distinct MACs<b>{len(tbl)}</b></div>
  <div class='stat'>multi-day devices<b>{sum(1 for t in tbl if t['days'] > 1)}</b></div>
  <div class='stat'>days<b>{m.get('days', '?')}</b></div>
 </div>
 <div class='card'><h2>Most-observed MACs</h2>
  <table><tr><th>MAC</th><th>Vendor</th><th>Type</th><th>Frames</th>
  <th>Visits</th><th>Days</th><th>Seen at</th></tr>{rows}</table>
  <p class='small'>Visit: contiguous presence (gap ≤3 min splits). Vendor is
  the printed OUI owner — remember the decoy lesson before trusting it.
  🔀 = randomized.</p></div>
 <div class='hero'><b>The lab question:</b> how much can persistent
 identifiers + repeated observation say about a <i>person's routine</i> —
 and what breaks that? Try <a href='/history'>the timeline</a>,
 <a href='/patterns'>patterns</a>, <a href='/compare'>short-vs-long
 retention</a>, then <a href='/quiz'>📝 take the quiz</a>.
 <a href='/exercises'>📋 exercises</a></div>
</div>"""
    return _page("Tracking lab", body)


def _tracklab_history(app, mac="") -> bytes:
    tl_rows, t0, t1 = timeline_rows(app.dataset["obs"], bucket_s=1800)
    head = "".join(
        f"<tr><td>{r['mac']}</td><td>{'🔀' if r['randomized'] else '📌'}</td>"
        + "".join(f"<td class='{('hot' if len(c) > 1 else 'warm') if c else ''}'>"
                  f"{c}</td>" for c in r["cells"]) + "</tr>"
        for r in tl_rows[:40])
    body = f"""
<div class='wrap'>
 <h1>🕐 Appearance timeline</h1>
 <p class='small'>30-minute buckets, day {time.strftime('%m-%d', time.localtime(t0))}
 → {time.strftime('%m-%d', time.localtime(t1))}. Cells carry the sensor letter
 (N/S=lab, C=corridor, K=canteen); hot = several sensors at once.</p>
 <div class='card tl' style='overflow-x:auto'>
  <table style='font-size:10px'>{head}</table></div>
 <p><a href='/'>← home</a></p></div>"""
    return _page("Timeline", body)


def _tracklab_patterns(app, mac="") -> bytes:
    tbl = app.full.table()
    macs = [t["mac"] for t in tbl if t["visits"] >= 2][:12]
    mac = mac or (macs[0] if macs else "")
    alive = ""
    if mac:
        p = app.full.pattern(mac)
        track = app.full.trackability(mac)
        hrs = " ".join(
            f"<td class='{'hot' if h == max(p['hours']) and h else 'warm' if h else ''}'>"
            f"{h or '·'}</td>" for h in p["hours"])
        wd = " ".join(
            f"<td class='{'warm' if c else ''}'>{_WEEK[i]}<br>{c or '·'}</td>"
            for i, c in enumerate(p["weekdays"]))
        edges = "".join(f"<li><code>{a} → {b}</code> ×{n}</li>"
                        for (a, b), n in sorted(p["edges"].items(),
                                                key=lambda kv: -kv[1]))
        visits = "".join(
            f"<tr><td>{time.strftime('%a %m-%d %H:%M', time.localtime(s))}</td>"
            f"<td>{sens}</td><td>{max(1, round((e - s) / 60))} min</td>"
            f"<td>{n}</td></tr>" for sens, s, e, n in p["visits"][:40])
        alive = f"""
 <div class='card'><h2>{mac} — {html.escape(p['vendor'])}</h2>
  <p>Trackability: <b>{html.escape(track['verdict'])}</b>
  <span class='small'>({html.escape(track['reason'])})</span></p>
  <h2>Hour-of-day</h2><table><tr>{hrs}</tr></table>
  <h2>Weekdays</h2><table><tr>{wd}</tr></table>
  <h2>Movement edges</h2><ul>{edges or '<li>—</li>'}</ul>
  <h2>Visits ({p['visit_count']})</h2>
  <table><tr><th>From</th><th>Sensor</th><th>Dwell</th><th>Frames</th></tr>
  {visits}</table></div>"""
    opts = "".join(f"<option {'selected' if m == mac else ''}>{m}</option>"
                   for m in macs)
    body = f"""
<div class='wrap'>
 <h1>📈 Behaviour patterns</h1>
 <form method='GET' action='/patterns' class='small'>MAC:
  <select name='mac'>{opts}</select>
  <button class='btn ghost'>show</button></form>
 {alive}
 <p><a href='/'>← home</a></p></div>"""
    return _page("Patterns", body)


def _tracklab_compare(app, since_s=0.0) -> bytes:
    full = app.full
    short = app.window_tracker(since_s or 2 * 86400)
    def _side(tr):
        rows = "".join(
            f"<tr><td>{t['mac']}</td><td>{t['visits']}</td><td>{t['days']}</td>"
            f"<td>{html.escape(', '.join(t['sensors']))}</td></tr>"
            for t in tr.table()[:10])
        return rows
    days_short = (since_s or 2 * 86400) / 86400
    body = f"""
<div class='wrap'>
 <h1>⚖️ Short vs long retention</h1>
 <div class='grid'>
  <div class='card'><h2>Last {days_short:g} days only</h2>
   <table><tr><th>MAC</th><th>Visits</th><th>Days</th><th>Seen at</th></tr>
   {_side(short)}</table>
   <p class='small'>With this window alone, <i>no routine exists</i>: a visit
   is a fact, not a pattern.</p></div>
  <div class='card'><h2>Full {app.dataset['manifest'].get('days', '?')}-day history</h2>
   <table><tr><th>MAC</th><th>Visits</th><th>Days</th><th>Seen at</th></tr>
   {_side(full)}</table>
   <p class='small'>Repeat presence + schedule edges emerge — this is the
   privacy cost of keeping the data.</p></div>
 </div>
 <div class='hero'>The dataset didn't change — <b>retention</b> did. Every
 extra day stored is extra inference available. That is why the main tool
 enforces retention limits and you are asked to set them honestly.</div>
 <p><a href='/'>← home</a></p></div>"""
    return _page("Short vs long term", body)


def _tracklab_quiz(app, result=None) -> bytes:
    tbl = app.full.table()
    covered = {p.strip().upper() for r in app.truth for p in
               r.get("macs", "").split(";") if "(" not in p and p.strip()}
    candidates = sorted({t["mac"] for t in tbl})
    opts = "".join(f"<option>{m}</option>" for m in candidates)
    devs = sorted({r["device"] for r in app.truth})
    devopts = "".join(f"<option>{d}</option>" for d in devs)
    edges = app.full.movement_edges(min_count=1)
    edgeopts = "".join(f"<option>{a}>{b}</option>" for (a, b) in
                       sorted(edges, key=lambda k: -edges[k]))
    verdict_html = ""
    if result:
        lis = "".join(f"<li>{html.escape(f)}</li>" for f in result["feedback"])
        cls = "ok" if result["score"] >= 80 else "warn" if result["score"] >= 50 else "bad"
        verdict_html = (f"<div class='card'><h2 class='{cls}'>Score: "
                        f"{result['score']}/100</h2><ul>{lis}</ul></div>")
    body = f"""
<div class='wrap'>
 <h1>📝 Tracking quiz</h1>
 {verdict_html}
 <div class='card'><form method='POST' action='/quiz'>
  <h2>Q1 — Which MAC belongs to the device the exercise calls
  <i>Student-A</i>?</h2><select name='q_identity'>{opts}</select>
  <h2>Q2 — Which device defeats MAC-based tracking, and how?</h2>
  <select name='q_untrackable'><option></option>{devopts}</select>
  <p class='small'>(the trick is visible in its address, not just its
  schedule)</p>
  <h2>Q3 — Student-A's dominant daily movement edge?</h2>
  <select name='q_edge'>{edgeopts}</select>
  <h2>Q4 — A 2-day window on Student-A supports claiming their weekly
  routine?</h2>
  <select name='q_short_window'><option></option>
   <option value='insufficient'>insufficient — too little data</option>
   <option value='sufficient'>sufficient — two days is plenty</option></select>
  <h2>Q5 — Point out the decoy (false-positive candidate)</h2>
  <select name='q_false_positive'><option></option>{opts}</select>
  <p><button class='btn'>Score my answers</button></p>
 </form></div>
 <p><a href='/'>← home</a></p></div>"""
    return _page("Tracking quiz", body)


def _tracklab_dash(app: TrackLabApp) -> bytes:
    truth_rows = "".join(
        f"<tr><td>{html.escape(r['device'])}</td><td>{html.escape(r['label'])}</td>"
        f"<td>{html.escape(r['macs'])}</td><td>{html.escape(r['rotates'])}</td>"
        f"<td class='small'>{html.escape(r['notes'])}</td></tr>"
        for r in app.truth)
    js = """
const TOKEN="__TOKEN__";
async function tick(){try{const r=await fetch('/api/state?token='+TOKEN);
 if(!r.ok)return;const d=await r.json();
 document.getElementById('s_v').textContent=d.funnel.views;
 document.getElementById('s_a').textContent=d.funnel.attempts;
 document.getElementById('s_b').textContent=d.funnel.best_score;
 const at=document.getElementById('attempts');at.innerHTML='';
 d.attempts.forEach(a=>{const tr=document.createElement('tr');
  ['time','score','ip'].forEach(k=>{const td=document.createElement('td');
   td.textContent=a[k];tr.appendChild(td);});
  const vb=document.createElement('td');vb.textContent=a.verdict;
  vb.style.fontSize='11px';tr.appendChild(vb);at.appendChild(tr);});
}catch(e){}}
async function doReset(){if(!confirm('Wipe attempts+events for the tracking '
 +'lab?'))return;await fetch('/api/reset?token='+TOKEN,{method:'POST'});tick();}
async function doRegen(){if(!confirm('Regenerate a FRESH tracking dataset '+
 '(seed+1)? All histories change instantly.'))return;
 const r=await fetch('/api/regenerate?token='+TOKEN,{method:'POST'});
 const d=await r.json();alert('New dataset: seed '+d.seed+', '+d.frames+
 ' frames, '+d.macs+' MACs');location.href='/';}
document.getElementById('rb').addEventListener('click',doReset);
document.getElementById('gb').addEventListener('click',doRegen);
tick();setInterval(tick,3000);
""".replace("__TOKEN__", app.token)
    body = f"""
<div class='wrap'>
 <h1>🎓 Instructor — tracking lab</h1>
 <p class='small'>dataset <code>{html.escape(app.dataset['dir'])}</code> ·
 <span id='s_v'>0</span> views · <span id='s_a'>0</span> attempts · best
 <span id='s_b'>0</span></p>
 <div class='card'><h2>Ground truth (instructor-only)</h2>
  <table><tr><th>Device</th><th>Label</th><th>MACs</th><th>Rotates</th>
  <th>Teaching purpose</th></tr>{truth_rows}</table></div>
 <div class='card'><h2>Quiz attempts</h2>
  <table><tr><th>Time</th><th>Score</th><th>IP</th><th>Feedback</th></tr>
  <tbody id='attempts'></tbody></table></div>
 <div class='card'><h2>Controls</h2>
  <button class='btn danger' id='rb'>🧹 Reset attempts</button>
  <button class='btn warn' id='gb' style='background:var(--warn);color:#422006'>
   🎲 Regenerate fresh dataset (seed+1)</button>
  <a class='btn ghost' href='/'>student view</a>
  <p class='small'>Reset wipes logged quiz attempts; regenerate re-simulates
  the two weeks in place (new student MAC, new decoy, new timings) so the
  exercise stays honest across cohorts. CLI equivalent: <code>wifiscanner
  track-lab make-dataset DIR --fresh --seed N+1</code></p>
 </div></div><script>{js}</script>"""
    return _page("Instructor — tracking lab", body)


class TrackLabHandler(_BaseHandler):
    def do_GET(self):
        u = urlparse(self.path)
        path = u.path.rstrip("/") or "/"
        app = self.app
        if path == "/health":
            return self._json({"ok": True, "lab": "track"})
        if path == "/":
            app.store.event("track", "page-view", "home", self._client())
            return self._send(_tracklab_home(app))
        if path == "/history":
            app.store.event("track", "page-view", "history", self._client())
            return self._send(_tracklab_history(app))
        if path == "/patterns":
            mac = parse_qs(u.query).get("mac", [""])[0].strip()
            return self._send(_tracklab_patterns(app, mac))
        if path == "/compare":
            since = 0.0
            raw = parse_qs(u.query).get("days", [""])[0]
            if raw:
                try:
                    since = float(raw) * 86400
                except ValueError:
                    since = 0.0
            return self._send(_tracklab_compare(app, since))
        if path == "/quiz":
            return self._send(_tracklab_quiz(app))
        if path == "/exercises":
            return self._send(_page("Track-lab exercises",
                                    "<div class='wrap'><pre style='white-space:"
                                    "pre-wrap'>" + html.escape(
                                        tracklab_exercises()) +
                                    "</pre><p><a href='/'>← home</a></p></div>"))
        if path == "/privacy":
            return self._send(_privacy_page())
        if path == "/favicon.ico":
            return self._send(b"", 204, "image/x-icon")
        if path == "/api/state":
            if not self._tok_ok(u):
                return self._json({"error": "not found"}, 404)
            return self._json({"funnel": app.store.funnel("track"),
                               "attempts": app.store.attempts("track"),
                               "events": app.store.events("track")})
        if path == "/i/" + app.token:
            app.store.event("track", "page-view", "instructor", self._client())
            return self._send(_tracklab_dash(app))
        if path.startswith("/i/"):
            return self._json({"error": "not found"}, 404)
        return self._redirect("/")

    def do_POST(self):
        u = urlparse(self.path)
        path = u.path.rstrip("/") or "/"
        app = self.app
        form = self._read_form()
        if form is None:
            return self._json({"error": "payload too large"}, 413)
        if path == "/quiz":
            answers = {k: form.get(k, "") for k in
                       ("q_identity", "q_untrackable", "q_edge",
                        "q_short_window", "q_false_positive")}
            result = score_tracklab(app.truth, answers)
            app.store.attempt("track", "quiz", json.dumps(answers),
                              result["score"],
                              " | ".join(result["feedback"])[:280],
                              self._client())
            import logging as _lg
            _lg.getLogger("wifiscanner").info(
                "track-lab quiz score=%s", result["score"])
            return self._send(_tracklab_quiz(app, result))
        if path == "/api/reset":
            if not self._tok_ok(u):
                return self._json({"error": "not found"}, 404)
            n = app.store.reset("track")
            app.store.event("track", "reset", f"{n} rows", self._client())
            return self._json({"ok": True, "removed": n})
        if path == "/api/regenerate":
            if not self._tok_ok(u):
                return self._json({"error": "not found"}, 404)
            seed = app.regenerate()
            app.store.event("track", "regenerate", f"seed={seed}",
                            self._client())
            return self._json({"ok": True, "seed": seed,
                               "frames": len(app.dataset["obs"]),
                               "macs": len(app.full.by_mac)})
        return self._json({"error": "not found"}, 404)


def _privacy_page() -> bytes:
    cards = [
        ("Persistent identifier", "A stable MAC (or any never-changing "
         "wireless ID) is a skeleton key: every sighting attaches to the "
         "same record, forever. Rotation breaks the keychain."),
        ("Accumulation beats resolution", "One garage-band probe tells you "
         "'someone was here'. Two weeks of the same signal tells you where "
         "they work, eat, and sleep. Error shrinks; intimacy grows."),
        ("Correlation across parties", "Your MAC is visible to every AP "
         "operator, hotspot analytics vendor and storefront sensor. Two "
         "lists merge trivially when the identifier is constant."),
        ("The incorrect-attribution problem", "OUI collisions, MAC spoofing "
         "and same-model twins mean tracking databases *also* contain "
         "wrong facts about real people — with the same confidence as the "
         "right ones."),
        ("Defences that actually work", "Per-network/per-period address "
         "rotation, probe-request minimisation (directed-only bursts), "
         "randomized sequence numbers and timing jitter — and on the "
         "collector side: retention limits, hashing, and opt-outs."),
    ]
    body = "".join(f"<div class='card'><h2>{html.escape(t)}</h2>"
                   f"<p>{html.escape(d)}</p></div>" for t, d in cards)
    return _page("Why persistent tracking matters",
                 f"<div class='wrap'><h1>🔍 Privacy & security implications</h1>"
                 + body +
                 "<p><a href='/'>← home</a></p></div>")


def make_tracklab_server(bind, port, app):
    return _Server((bind, int(port)), TrackLabHandler, app)
