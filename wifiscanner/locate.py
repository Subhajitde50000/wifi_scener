"""RSSI-based positioning: range estimation, multilateration and zone dwell.

Works from your own fixed sensors (your own access points / Raspberry Pis
running ``record --sensor``). Positions are estimates derived from signal
strength and the geometry of YOUR sensor grid; they are never accurate beyond
a few metres indoors and are meant for coarse "which room / which zone"
answers, not pinpointing people.
"""
from __future__ import annotations

import csv
import math
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from .models import DEFAULT_TX_POWER_DBM, channel_to_freq
from .util import log


# ----------------------------------------------------------------- geometry

@dataclass
class Sensor:
    """A fixed receiving point with a known position (metres, local grid)."""
    name: str
    x: float
    y: float
    floor: int = 0
    rssi_offset_db: float = 0.0     # per-sensor calibration (+ = sees stronger)
    tx_power_dbm: float = DEFAULT_TX_POWER_DBM


@dataclass
class Zone:
    """A named polygon (list of (x, y) vertices) on the sensor grid."""
    name: str
    points: List[Tuple[float, float]] = field(default_factory=list)

    def contains(self, x: float, y: float) -> bool:
        pts = self.points
        inside = False
        j = len(pts) - 1
        for i in range(len(pts)):
            xi, yi = pts[i]
            xj, yj = pts[j]
            if (yi > y) != (yj > y) and x < (xj - xi) * (y - yi) / (yj - yi + 1e-12) + xi:
                inside = True
                break
            j = i
        return inside


def load_sensors(path: str) -> List[Sensor]:
    """CSV: name,x,y[,floor,rssi_offset_db,tx_power_dbm]"""
    sensors: List[Sensor] = []
    with open(path, newline="", encoding="utf-8-sig") as fh:
        for row in csv.reader(fh):
            row = [c.strip() for c in row]
            if not row or not row[0] or row[0].startswith("#") \
                    or row[0].lower() == "name":
                continue
            try:
                s = Sensor(row[0], float(row[1]), float(row[2]))
                if len(row) > 3 and row[3] != "":
                    s.floor = int(float(row[3]))
                if len(row) > 4 and row[4] != "":
                    s.rssi_offset_db = float(row[4])
                if len(row) > 5 and row[5] != "":
                    s.tx_power_dbm = float(row[5])
                sensors.append(s)
            except (ValueError, IndexError):
                log.warning("skipping malformed sensor row: %r", row)
    if not sensors:
        raise ValueError(f"no valid sensors found in {path}")
    return sensors


def load_zones(path: str) -> List[Zone]:
    """CSV: zone_name,x,y — consecutive rows with the same name form a polygon."""
    zones: Dict[str, Zone] = {}
    with open(path, newline="", encoding="utf-8-sig") as fh:
        for row in csv.reader(fh):
            row = [c.strip() for c in row]
            if not row or not row[0] or row[0].startswith("#") \
                    or row[0].lower() == "zone":
                continue
            try:
                zones.setdefault(row[0], Zone(row[0])).points.append(
                    (float(row[1]), float(row[2])))
            except (ValueError, IndexError):
                log.warning("skipping malformed zone row: %r", row)
    return [z for z in zones.values() if len(z.points) >= 3]


def zone_at(x: Optional[float], y: Optional[float],
            zones: Sequence[Zone]) -> str:
    if x is None or y is None:
        return "unknown"
    for z in zones:
        if z.contains(x, y):
            return z.name
    return "outside-zones"


# -------------------------------------------------------------- ranging

def rssi_to_range_m(rssi: Optional[int], freq_mhz: Optional[int],
                    tx_power_dbm: float = DEFAULT_TX_POWER_DBM,
                    path_loss_exponent: float = 2.7,
                    rssi_offset_db: float = 0.0) -> Optional[float]:
    """Invert the log-distance path-loss model -> estimated range [m]."""
    if rssi is None or not freq_mhz:
        return None
    corrected = rssi + rssi_offset_db
    fspl_1m = 20 * math.log10(freq_mhz) - 27.55
    d = 10 ** ((tx_power_dbm - fspl_1m - corrected) / (10 * path_loss_exponent))
    return max(0.2, min(d, 500.0))


@dataclass
class Measure:
    sensor: Sensor
    rssi: Optional[int]
    freq: Optional[int]
    range_m: Optional[float] = None

    def __post_init__(self):
        self.range_m = rssi_to_range_m(self.rssi, self.freq,
                                       self.sensor.tx_power_dbm,
                                       rssi_offset_db=self.sensor.rssi_offset_db)


@dataclass
class Fix:
    """One position estimate.

    Weakness #4 (noisy location): a fix is ALWAYS reported with its error
    radius (``uncertainty_m``), a ``confidence`` bucket, and the ``zone`` as
    the primary answer. When confidence is low, callers should present the
    zone — not the coordinates — as the result (``precise_ok`` is False and
    ``display`` renders the zone-level answer).
    """
    ts: float
    mac: str
    x: Optional[float]
    y: Optional[float]
    uncertainty_m: Optional[float]
    method: str
    sensors: str
    zone: str = "unknown"
    confidence: str = ""          # high / medium / low (filled by Tracker)
    zone_confidence: str = ""     # confidence in the ZONE answer specifically
    sensor_count: int = 0
    rssi_spread_db: Optional[float] = None

    @property
    def error_radius_m(self) -> Optional[float]:
        """Explicit error radius: 'the device is within ±X m of (x, y)'."""
        return self.uncertainty_m

    @property
    def precise_ok(self) -> bool:
        """Whether coordinates may be presented as the answer."""
        return self.confidence in ("high", "medium") and self.x is not None

    @property
    def display(self) -> str:
        """Zone-primary human rendering (weakness #4)."""
        if not self.precise_ok:
            unc = f"±{self.uncertainty_m:.0f}m" if self.uncertainty_m else "unknown error"
            return (f"zone '{self.zone}' only ({unc}, {self.confidence or 'low'} "
                    f"confidence — coordinates withheld as unreliable)")
        return (f"({self.x:.1f}, {self.y:.1f}) ±{self.uncertainty_m:.0f}m, "
                f"zone '{self.zone}' ({self.confidence} confidence)")

    def to_row(self) -> dict:
        return {"ts": self.ts, "mac": self.mac, "x": self.x, "y": self.y,
                "unc_m": self.uncertainty_m, "error_radius_m": self.error_radius_m,
                "zone": self.zone, "zone_confidence": self.zone_confidence,
                "method": self.method, "confidence": self.confidence,
                "sensors": self.sensors, "sensor_count": self.sensor_count,
                "display": self.display}


def fix_confidence(method: str, uncertainty: Optional[float],
                   sensor_count: int, grid_diag_m: float,
                   rssi_spread_db: Optional[float] = None) -> tuple[str, str]:
    """Derive (fix confidence, zone confidence) for a location fix.

    Rules (weakness #4):
    * nearest-sensor / guarded / single-sensor fixes are NEVER more than
      low confidence for coordinates — they are zone hints.
    * trilateration with >= 3 sensors and small residual error is medium,
      high only when the error is < 15% of the grid diagonal.
    * bilateration is ambiguous by construction -> low for coordinates,
      medium for zone.
    * the ZONE answer is one grade more confident than coordinates, because
      room-level is what RSSI positioning can actually deliver.
    """
    order = ["low", "medium", "high"]
    if method.startswith("nearest-sensor"):
        coord = "low"
    elif method.startswith("bilateration"):
        coord = "low"
    elif method.startswith("trilateration"):
        if sensor_count >= 4 and uncertainty and uncertainty < 0.15 * grid_diag_m:
            coord = "high"
        elif sensor_count >= 3 and uncertainty and uncertainty < 0.5 * grid_diag_m:
            coord = "medium"
        else:
            coord = "low"
    else:
        coord = "low"
    if rssi_spread_db is not None and rssi_spread_db > 25 and coord == "high":
        coord = "medium"  # wildly disagreeing sensors -> demote
    zone = order[min(2, order.index(coord) + 1)]
    return coord, zone


def multilateration(measures: List[Measure],
                    path_loss_exponent: float = 2.7) -> Optional[Tuple[float, float, float, str]]:
    """Closed-form weighted least squares (global-estimation) trilateration.

    Linearises  |p - si| = ri  by subtracting the strongest measurement's
    equation from the rest, then solves the 2x2 normal equations.
    Returns (x, y, uncertainty_m, method) or None.
    """
    ms = [m for m in measures if m.range_m]
    if len(ms) < 3:
        if len(ms) == 2:                     # bilateration -> 2 candidate points
            (x1, y1, r1), (x2, y2, r2) = [(m.sensor.x, m.sensor.y, m.range_m)
                                          for m in ms]
            d = math.hypot(x2 - x1, y2 - y1)
            if d < 1e-6:
                return None
            a = (r1 * r1 - r2 * r2 + d * d) / (2 * d)
            h2 = r1 * r1 - a * a
            xm, ym = x1 + a * (x2 - x1) / d, y1 + a * (y2 - y1) / d
            if h2 < 0:                       # circles miss: closest line point
                return (xm, ym, abs(math.sqrt(-h2)) if h2 > -1e9 else 25.0,
                        "bilateration(none)")
            h = math.sqrt(h2)
            p1 = (xm + h * (y2 - y1) / d, ym - h * (x2 - x1) / d)
            p2 = (xm - h * (y2 - y1) / d, ym + h * (x2 - x1) / d)
            cx = sum(m.sensor.x for m in ms) / len(ms)
            cy = sum(m.sensor.y for m in ms) / len(ms)
            px, py = max((p1, p2), key=lambda p: -(math.hypot(p[0] - cx, p[1] - cy)))
            return (px, py, max(4.0, d / 2), "bilateration(ambiguous)")
        return None
    ref = ms[-1]
    A, b, w = [], [], []
    rref = ref.range_m
    for m in ms[:-1]:
        s, r = m.sensor, m.range_m
        # |p-si|^2 = ri^2 ; subtract the reference equation ->
        # 2(si-sk).p = |si|^2 - |sk|^2 - ri^2 + rk^2
        A.append([2 * (s.x - ref.sensor.x), 2 * (s.y - ref.sensor.y)])
        b.append(s.x * s.x + s.y * s.y - ref.sensor.x ** 2 - ref.sensor.y ** 2
                 - r * r + rref * rref)
        w.append(1.0 / max(r, 1.0) ** 2)     # trust nearer (stronger) sensors
    ata = [[sum(w[k] * A[k][i] * A[k][j] for k in range(len(A))) for j in (0, 1)]
           for i in (0, 1)]
    atb = [sum(w[k] * A[k][i] * b[k] for k in range(len(A))) for i in (0, 1)]
    det = ata[0][0] * ata[1][1] - ata[0][1] * ata[1][0]
    if abs(det) < 1e-9:                      # sensors collinear
        return None
    x = (atb[0] * ata[1][1] - atb[1] * ata[0][1]) / det
    y = (ata[0][0] * atb[1] - ata[1][0] * atb[0]) / det
    resid = [abs(math.hypot(x - m.sensor.x, y - m.sensor.y) - m.range_m)
             for m in ms]
    rms = math.sqrt(sum(r * r for r in resid) / len(resid))
    return (round(x, 2), round(y, 2), round(max(1.5, 2 * rms), 1), "trilateration")


class Tracker:
    """Turn per-sensor observation rows into timed position fixes."""
    def _guard(self, ms, res):
        """Reject fixes that are physically inconsistent with the sensor grid.

        Contradictory RSSI readings (mis-calibrated sensors, one bad draw) can
        make the circles intersect absurdly far away. A production tool must
        degrade gracefully: such fixes collapse to 'nearest-sensor' confidence.
        """
        if res is None:
            return None
        x, y, unc, method = res
        gx = [s.sensor.x for s in ms]
        gy = [s.sensor.y for s in ms]
        diag = max(math.hypot(max(gx) - min(gx), max(gy) - min(gy)), 10.0)
        pad = 0.6 * diag
        if unc > diag or not (min(gx) - pad <= x <= max(gx) + pad
                              and min(gy) - pad <= y <= max(gy) + pad):
            best = max(ms, key=lambda m: m.rssi if m.rssi is not None else -999)
            return (best.sensor.x, best.sensor.y, None,
                    "nearest-sensor(guarded)")
        return (x, y, unc, method)


    def __init__(self, sensors: Sequence[Sensor], zones: Sequence[Zone] = (),
                 window_s: float = 3.0, path_loss_exponent: float = 2.7):
        self.by_name = {s.name: s for s in sensors}
        self.sensors = list(sensors)
        self.zones = list(zones)
        self.window_s = window_s
        self.n_exp = path_loss_exponent

    def _measures(self, rows: List[dict]) -> List[Measure]:
        """One (possibly several) observation per sensor -> best (strongest)."""
        best: Dict[str, dict] = {}
        for r in rows:
            cur = best.get(r["sensor"])
            if cur is None or (r["rssi"] or -999) > (cur["rssi"] or -999):
                best[r["sensor"]] = r
        out = []
        for name, r in best.items():
            s = self.by_name.get(name)
            if not s:
                continue
            freq = r.get("freq") or channel_to_freq(r.get("channel") or 0)
            out.append(Measure(sensor=s, rssi=r["rssi"], freq=freq))
        return out

    def grid_diagonal(self) -> float:
        xs = [s.x for s in self.sensors]
        ys = [s.y for s in self.sensors]
        return max(math.hypot(max(xs) - min(xs), max(ys) - min(ys)), 10.0)

    def _score(self, method: str, unc: Optional[float],
               ms: List[Measure]) -> tuple:
        """Attach confidence + error-radius metadata to a raw fix."""
        rssis = [m.rssi for m in ms if m.rssi is not None]
        spread = (max(rssis) - min(rssis)) if len(rssis) >= 2 else None
        coord, zone_c = fix_confidence(method, unc, len(ms),
                                       self.grid_diagonal(), spread)
        return coord, zone_c, len(ms), spread

    def fixes(self, observations: List[dict]) -> List[Fix]:
        """observations: rows with ts, sensor, mac, rssi, freq (sorted by ts)."""
        by_mac: Dict[str, List[dict]] = {}
        for o in observations:
            by_mac.setdefault(o["mac"], []).append(o)
        fixes: List[Fix] = []
        for mac, rows in by_mac.items():
            rows.sort(key=lambda r: r["ts"])
            bucket: List[dict] = []
            t0 = None

            def emit():
                if not bucket:
                    return
                ms = self._measures(bucket)
                if not ms:
                    return
                res = self._guard(ms, multilateration(ms, self.n_exp))
                ts = bucket[0]["ts"]
                names = "|".join(sorted({m.sensor.name for m in ms}))
                if res:
                    x, y, unc, method = res
                    coord, zone_c, nsen, spread = self._score(method, unc, ms)
                    fixes.append(Fix(ts, mac, x, y, unc, method,
                                     f"{len(ms)}sensors:{names}",
                                     zone_at(x, y, self.zones),
                                     confidence=coord, zone_confidence=zone_c,
                                     sensor_count=nsen, rssi_spread_db=spread))
                else:                        # single sensor: coarse zone hint
                    m = max(ms, key=lambda mm: mm.rssi or -999)
                    coord, zone_c, nsen, spread = self._score(
                        "nearest-sensor", None, ms)
                    fixes.append(Fix(ts, mac, m.sensor.x, m.sensor.y, None,
                                     "nearest-sensor",
                                     f"1sensor:{m.sensor.name}",
                                     zone_at(m.sensor.x, m.sensor.y, self.zones),
                                     confidence=coord, zone_confidence=zone_c,
                                     sensor_count=nsen, rssi_spread_db=spread))

            for r in rows:
                if t0 is None or r["ts"] - t0 <= self.window_s:
                    if t0 is None:
                        t0 = r["ts"]
                    bucket.append(r)
                else:
                    emit()
                    bucket, t0 = [r], r["ts"]
            emit()
        return fixes

    def zone_dwell(self, fixes: List[Fix]) -> Dict[str, float]:
        """Seconds spent in each zone, assuming consecutive fixes ~ uniform."""
        dwell: Dict[str, float] = {}
        for a, b in zip(fixes, fixes[1:]):
            dt = max(0.0, b.ts - a.ts)
            if a.x is not None and b.x is not None \
                    and math.hypot(a.x - b.x, a.y - b.y) > 50:
                continue                     # don't bridge teleport glitches
            dwell[a.zone] = dwell.get(a.zone, 0.0) + dt
        return {k: round(v, 1) for k, v in dwell.items()}


def ascii_map(fixes: List[Fix], sensors: Sequence[Sensor],
              zones: Sequence[Zone] = (), cols: int = 72,
              rows: int = 22) -> str:
    """Render the trail + sensors + zone boxes onto a text canvas."""
    xs = [p for f in fixes if f.x is not None for p in (f.x,)] \
        + [s.x for s in sensors] + \
        [p[0] for z in zones for p in z.points] or [0.0]
    ys = [p for f in fixes if f.y is not None for p in (f.y,)] \
        + [s.y for s in sensors] + \
        [p[1] for z in zones for p in z.points] or [0.0]
    minx, maxx = min(xs) - 1, max(xs) + 1
    miny, maxy = min(ys) - 1, max(ys) + 1
    sx = (cols - 1) / max(maxx - minx, 1e-6)
    sy = (rows - 1) / max(maxy - miny, 1e-6)
    grid = [[" "] * cols for _ in range(rows)]

    def put(x, y, ch):
        c, r = int(round((x - minx) * sx)), int(round((maxy - y) * sy))
        if 0 <= c < cols and 0 <= r < rows:
            grid[r][c] = ch

    for z in zones:
        pts = z.points + [z.points[0]]
        for (x1, y1), (x2, y2) in zip(pts, pts[1:]):
            steps = int(max(abs(x2 - x1) * sx, abs(y2 - y1) * sy, 1))
            for i in range(steps + 1):
                put(x1 + (x2 - x1) * i / steps, y1 + (y2 - y1) * i / steps, "·")
    ramp = "o.:-=+*#%@"
    fixes = [f for f in fixes if f.x is not None]
    for i, f in enumerate(fixes):
        put(f.x, f.y, ramp[min(9, i * 9 // max(len(fixes) - 1, 1))])
    for s in sensors:
        put(s.x, s.y, "S")
    lines = ["".join(r) for r in grid]
    legend = ("S=sensor   "
              + "  ".join(f"{ramp[min(9, i * 9 // max(len(fixes) - 1, 1))]}"
                          f"={time.strftime('%H:%M', time.localtime(f.ts))}"
                          for i, f in enumerate(fixes)
                          if i % max(1, len(fixes) // 4) == 0))
    return "\n".join(lines) + f"\n{legend}"


def simulate_from_ranges(x: float, y: float,
                         sensors: Sequence[Sensor],
                         freq: int = 2437,
                         noise_db: float = 0.0) -> List[Tuple[Sensor, int]]:
    """Forward model: true position -> RSSI each sensor would report.

    Used by the test-suite (and useful for calibration dry-runs): computes
    path loss from geometry, optionally adding Gaussian noise.
    """
    import random
    out = []
    for s in sensors:
        d = max(0.5, math.hypot(x - s.x, y - s.y))
        fspl = 20 * math.log10(freq) - 27.55 + 2.7 * 10 * math.log10(d)
        rssi = s.tx_power_dbm - fspl + s.rssi_offset_db
        if noise_db:
            rssi += random.gauss(0, noise_db)
        out.append((s, int(round(rssi))))
    return out
