"""SQLite persistence layer: presence sessions, per-scan history, location fixes.

Design notes
------------
* Everything is stored with epoch timestamps so presence can be queried as
  ``gap-and-island`` sessions across scans.
* Continuous recording is deliberately scoped to YOUR OWN network(s): the
  ``record`` command persists associations for the BSSIDs you monitor.
  Pass-by survey data stays ephemeral and probe requests are never written to
  history — this is a network-owner tool, not a bystander tracker.
"""
from __future__ import annotations

import os
import re
import sqlite3
import time
from typing import List, Optional

from .engine import Engine
from .privacy import (DEFAULT_RETENTION_DAYS, RetentionPolicy, anonymize_hostname,
                      coerce_mode, ensure_secure_storage, hash_mac, new_salt,
                      PrivacyMode)
from .util import log

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans(
  scan_id  TEXT PRIMARY KEY,
  ts       REAL NOT NULL,
  duration REAL,
  mode     TEXT,
  sensor   TEXT,
  networks INTEGER,
  devices  INTEGER,
  meta     TEXT);
CREATE TABLE IF NOT EXISTS networks(
  scan_id TEXT, ts REAL, sensor TEXT, bssid TEXT, ssid TEXT,
  channel INT, band TEXT, rssi INT, security TEXT, grade TEXT, clients INT);
CREATE TABLE IF NOT EXISTS devices(
  scan_id TEXT, ts REAL, sensor TEXT, mac TEXT, bssid TEXT, ssid TEXT,
  state TEXT, rssi INT, packets INT, data INT, bytes INT,
  ip TEXT, hostname TEXT, randomized INT, probed TEXT);
CREATE TABLE IF NOT EXISTS observations(
  ts REAL, sensor TEXT, mac TEXT, bssid TEXT, rssi INT, freq INT);
CREATE TABLE IF NOT EXISTS warden(
  bssid TEXT PRIMARY KEY, ssid TEXT, meta TEXT,
  first_seen REAL, last_seen REAL, seen INT);
CREATE TABLE IF NOT EXISTS fixes(
  ts REAL, mac TEXT, x REAL, y REAL, unc REAL, method TEXT, sensors TEXT);
CREATE TABLE IF NOT EXISTS policy(
  key TEXT PRIMARY KEY, value TEXT);
CREATE INDEX IF NOT EXISTS idx_dev_mac  ON devices(mac, ts);
CREATE INDEX IF NOT EXISTS idx_dev_ssid ON devices(ssid, ts);
CREATE INDEX IF NOT EXISTS idx_obs_mac  ON observations(mac, ts);
CREATE INDEX IF NOT EXISTS idx_fix_mac  ON fixes(mac, ts);
"""


def parse_when(value: str, *, end: bool = False) -> float:
    """Parse 'YYYY-MM-DD[ HH:MM[:SS]]', 'HH:MM', '-2h15m', 'now' -> epoch."""
    if not value:
        return 0.0
    v = value.strip().lower()
    if v == "now":
        return time.time()
    m = re.fullmatch(r"-(?:(\d+)d)?(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?", v)
    if m and any(m.groups()):
        d, h, mi, s = (int(g or 0) for g in m.groups())
        return time.time() - (((d * 24 + h) * 60 + mi) * 60 + s)
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d", "%H:%M:%S", "%H:%M"):
        try:
            t = time.strptime(v, fmt)
            now = time.localtime()
            if fmt.startswith("%H"):        # bare time -> today
                t = (now.tm_year, now.tm_mon, now.tm_mday,
                     t.tm_hour, t.tm_min, t.tm_sec, 0, 0, -1)
            elif fmt == "%Y-%m-%d" and end:  # date as end bound -> 23:59:59
                return time.mktime((t.tm_year, t.tm_mon, t.tm_mday,
                                    23, 59, 59, 0, 0, -1))
            return time.mktime(t)
        except ValueError:
            continue
    raise ValueError(f"cannot understand time {value!r} "
                     "(use 'YYYY-MM-DD [HH:MM]', '-2h', or 'now')")


class Store:
    """Append-only survey store + presence/location query API.

    Weaknesses #3/#10: the database is sensitive (it maps devices to places
    and times), so it is created owner-only (0600), warns when left
    world-readable, enforces a retention limit on every open, and supports
    per-device deletion plus whole-database anonymization.
    """

    def __init__(self, path: str, retention_days: float = DEFAULT_RETENTION_DAYS,
                 privacy_mode: str = PrivacyMode.STANDARD,
                 anonymize: bool = False, secure_storage: bool = True):
        if coerce_mode(privacy_mode) == PrivacyMode.EPHEMERAL:
            raise PermissionError(
                "privacy mode is EPHEMERAL: nothing may be persisted to disk")
        self.path = path
        self.privacy_mode = coerce_mode(privacy_mode)
        self.anonymize = anonymize or self.privacy_mode == PrivacyMode.MINIMAL
        self.retention = RetentionPolicy(retention_days)
        existed = os.path.exists(path)
        os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.executescript("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")
        self.db.executescript(SCHEMA)
        self.db.commit()
        if secure_storage:
            # Owner-only from birth (weakness #10: access control).
            ensure_secure_storage(path, fix=True)
            for suffix in ("-wal", "-shm"):
                if os.path.exists(path + suffix):
                    ensure_secure_storage(path + suffix, fix=True)
        else:
            warn = ensure_secure_storage(path, fix=False)
            if warn:
                log.warning(warn)
        if not existed:
            self._set_policy("created", time.strftime("%Y-%m-%d %H:%M:%S"))
            self._set_policy("salt", new_salt())
            self._set_policy("privacy_mode", self.privacy_mode)
        self._set_policy("retention_days", repr(retention_days))
        # Retention is ENFORCED, not advisory (weaknesses #3/#10).
        if self.retention.enabled:
            pruned = self.prune(self.retention.days, quiet=True)
            if pruned:
                log.info("retention: pruned %d row(s) older than %g days",
                         pruned, retention_days)

    def close(self) -> None:
        self.db.commit()
        self.db.close()

    # --------------------------------------------------------------- policy

    def _set_policy(self, key: str, value: str) -> None:
        with self.db:
            self.db.execute("INSERT OR REPLACE INTO policy VALUES(?, ?)",
                            (key, value))

    def _get_policy(self, key: str, default: str = "") -> str:
        try:
            row = self.db.execute("SELECT value FROM policy WHERE key=?",
                                  (key,)).fetchone()
        except sqlite3.OperationalError:
            return default
        return row["value"] if row else default

    @property
    def salt(self) -> str:
        s = self._get_policy("salt")
        if not s:
            s = new_salt()
            self._set_policy("salt", s)
        return s

    def _mac(self, mac: str) -> str:
        """Store the MAC, or its salted pseudonym in anonymized mode."""
        if self.anonymize:
            return hash_mac(mac, self.salt)
        return (mac or "").upper()

    # ------------------------------------------------------------- writing

    def record_engine(self, engine: Engine, mode: str = "scan",
                      sensor: str = "") -> str:
        """Persist one merged engine snapshot; returns the scan_id.

        In anonymized/minimal mode, client MACs are stored as salted
        pseudonyms and hostnames/IPs/probe lists are dropped (weakness #3):
        sessions still group correctly, but the database no longer maps to
        real devices or people. AP BSSIDs are kept (they are infrastructure
        you own, needed to scope the history to your network).
        """
        scan_id = time.strftime("%Y%m%d-%H%M%S") + f"-{os.getpid() % 1000:03d}"
        ts = time.time()
        nets = list(engine.aps.values())
        with self.db:
            self.db.execute(
                "INSERT OR REPLACE INTO scans VALUES(?,?,?,?,?,?,?,?)",
                (scan_id, ts, round(ts - engine.started, 1), mode, sensor,
                 len(nets), len(engine.all_stations()), "wifi_scener"))
            self.db.executemany(
                "INSERT INTO networks VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                [(scan_id, ts, sensor, a.bssid, a.ssid, a.channel, a.band,
                  a.rssi, a.encryption, a.security_grade, a.client_count)
                 for a in nets])
            droles, obs = [], []
            for a in nets:
                for s in a.stations.values():
                    mac = self._mac(s.mac)
                    ip = "" if self.anonymize else s.ip_address
                    host = anonymize_hostname(s.hostname) if self.anonymize \
                        else s.hostname
                    droles.append((scan_id, ts, sensor, mac, a.bssid, a.ssid,
                                   "associated", s.rssi, s.packets,
                                   s.data_packets, s.bytes_seen, ip,
                                   host, int(s.is_randomized), ""))
                    if s.rssi is not None:
                        obs.append((ts, sensor, mac, a.bssid, s.rssi,
                                    a.frequency or 0))
            for s in engine.unassociated.values():
                if s.ip_address:               # LAN hosts (own subnet only)
                    mac = self._mac(s.mac)
                    ip = "" if self.anonymize else s.ip_address
                    host = anonymize_hostname(s.hostname) if self.anonymize \
                        else s.hostname
                    droles.append((scan_id, ts, sensor, mac, "", "",
                                   "lan", s.rssi, s.packets, s.data_packets,
                                   s.bytes_seen, ip, host,
                                   int(s.is_randomized), ""))
            self.db.executemany(
                "INSERT INTO devices VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", droles)
            self.db.executemany("INSERT INTO observations VALUES(?,?,?,?,?,?)", obs)
        return scan_id

    # --------------------------------------------------------------- warden

    def learn_warden(self, engine: Engine) -> int:
        """Baseline the APs currently visible as 'known good'."""
        ts = time.time()
        n = 0
        with self.db:
            for bssid, a in engine.aps.items():
                self.db.execute(
                    "INSERT OR IGNORE INTO warden VALUES(?,?,?,?,?,0)",
                    (bssid, a.ssid, f"ch{a.channel}|{a.encryption}", ts, ts))
                self.db.execute(
                    "UPDATE warden SET last_seen=?, seen=seen+1, ssid=?, meta=? "
                    "WHERE bssid=?", (ts, a.ssid, f"ch{a.channel}|{a.encryption}",
                                      bssid))
                n += 1
        return n

    def unknown_bssids(self, engine: Engine) -> List[str]:
        known = {r["bssid"] for r in self.db.execute("SELECT bssid FROM warden")}
        if not known:
            return []
        return [b for b in engine.aps if b not in known]

    def warden_list(self) -> List[dict]:
        return [dict(r) for r in self.db.execute(
            "SELECT bssid, ssid, meta, first_seen, last_seen, seen "
            "FROM warden ORDER BY last_seen DESC").fetchall()]

    def record_fixes(self, rows: List[tuple]) -> None:
        """rows: (ts, mac, x, y, unc, method, sensor_names)"""
        with self.db:
            self.db.executemany("INSERT INTO fixes VALUES(?,?,?,?,?,?,?)", rows)

    # ------------------------------------------------------------- querying

    @staticmethod
    def _where(mac: str = "", ssid: str = "", bssid: str = "",
               since: float = 0.0, until: float = 0.0) -> (str, list):
        conds, args = [], []
        if mac:
            conds.append("mac = ?")
            args.append(mac.upper())
        if ssid:
            conds.append("ssid LIKE ?")
            args.append(f"%{ssid}%")
        if bssid:
            conds.append("bssid = ?")
            args.append(bssid.upper())
        if since:
            conds.append("ts >= ?")
            args.append(since)
        if until:
            conds.append("ts <= ?")
            args.append(until)
        return ("WHERE " + " AND ".join(conds) if conds else "", args)

    def sessions(self, mac: str = "", ssid: str = "", bssid: str = "",
                 since: float = 0.0, until: float = 0.0,
                 gap: float = 300.0) -> List[dict]:
        """Gap-and-island presence sessions per (device, network)."""
        w, args = self._where(mac, ssid, bssid, since, until)
        rows = self.db.execute(
            f"SELECT ts, mac, bssid, ssid, rssi FROM devices "
            f"{(w + ' AND' if w else 'WHERE')} state IN ('associated','lan') "
            "ORDER BY mac, bssid, ts", args).fetchall()
        out: List[dict] = []
        cur: Optional[dict] = None
        count = 0
        rsum = 0.0
        rcnt = 0

        def flush():
            if cur is not None:
                cur["sightings"] = count
                cur["duration_s"] = round(cur["last_seen"] - cur["first_seen"], 1)
                cur["avg_rssi"] = round(rsum / rcnt, 1) if rcnt else None
                out.append({k: v for k, v in cur.items() if not k.startswith("_")})

        for r in rows:
            key = (r["mac"], r["bssid"])
            if cur is None or cur["_key"] != key or r["ts"] - cur["last_seen"] > gap:
                flush()
                cur = {"_key": key, "mac": r["mac"], "bssid": r["bssid"],
                       "ssid": r["ssid"], "first_seen": r["ts"],
                       "last_seen": r["ts"], "min_rssi": r["rssi"],
                       "max_rssi": r["rssi"]}
                count, rsum, rcnt = 1, 0.0, 0
            else:
                cur["last_seen"] = r["ts"]
                if r["rssi"] is not None:
                    cur["min_rssi"] = min(cur["min_rssi"], r["rssi"]) \
                        if cur["min_rssi"] is not None else r["rssi"]
                    cur["max_rssi"] = max(cur["max_rssi"], r["rssi"]) \
                        if cur["max_rssi"] is not None else r["rssi"]
                count += 1
            if r["rssi"] is not None:
                rsum += r["rssi"]
                rcnt += 1
        flush()
        return sorted(out, key=lambda s: -s["last_seen"])

    def device_history(self, mac: str, limit: int = 500) -> List[dict]:
        return [dict(r) for r in self.db.execute(
            "SELECT ts, sensor, bssid, ssid, rssi, state, ip, hostname "
            "FROM devices WHERE mac=? ORDER BY ts DESC LIMIT ?",
            ((mac or "").upper(), limit)).fetchall()]

    def known_devices(self) -> List[dict]:
        return [dict(r) for r in self.db.execute(
            "SELECT mac, COUNT(*) n, MAX(ts) last, MIN(ts) first, "
            "COUNT(DISTINCT bssid) bssids, GROUP_CONCAT(DISTINCT ssid) ssids "
            "FROM devices GROUP BY mac ORDER BY last DESC").fetchall()]

    def get_observations(self, mac: str = "", since: float = 0.0,
                         until: float = 0.0) -> List[dict]:
        w, args = self._where(mac, "", "", since, until)
        return [dict(r) for r in self.db.execute(
            "SELECT ts, sensor, mac, bssid, rssi, freq FROM observations "
            f"{w} ORDER BY mac, ts", args).fetchall()]

    def get_fixes(self, mac: str = "", since: float = 0.0,
                  until: float = 0.0) -> List[dict]:
        w, args = self._where(mac, "", "", since, until)
        return [dict(r) for r in self.db.execute(
            "SELECT ts, mac, x, y, unc, method, sensors FROM fixes "
            f"{w} ORDER BY ts", args).fetchall()]

    def stats(self) -> dict:
        out = {}
        for t in ("scans", "networks", "devices", "observations", "fixes"):
            r = self.db.execute(
                f"SELECT COUNT(*) n, MIN(ts) a, MAX(ts) b FROM {t}").fetchone()
            out[t] = {"rows": r["n"],
                      "from": r["a"], "to": r["b"]}
        return out

    def prune(self, days: float, quiet: bool = False) -> int:
        """Delete rows older than `days`; returns rows removed."""
        cutoff = time.time() - days * 86400
        total = 0
        with self.db:
            for t in ("scans", "networks", "devices", "observations", "fixes"):
                cur = self.db.execute(f"DELETE FROM {t} WHERE ts < ?", (cutoff,))
                total += cur.rowcount or 0
        if not quiet:
            log.info("pruned %d row(s) older than %.1f days", total, days)
        return total

    # ------------------------------------------------- deletion / erasure

    def delete_device(self, mac: str) -> int:
        """Erase every row for one device (right-to-erasure, weakness #10).

        Matches the literal MAC and, when this database is anonymized, its
        salted pseudonym too. Returns rows removed.
        """
        targets = {(mac or "").upper()}
        targets.add(hash_mac(mac, self.salt))
        total = 0
        with self.db:
            for t, col in (("devices", "mac"), ("observations", "mac"),
                           ("fixes", "mac")):
                for target in targets:
                    cur = self.db.execute(f"DELETE FROM {t} WHERE {col} = ?",
                                          (target,))
                    total += cur.rowcount or 0
        log.info("erased %d row(s) for device %s", total, mac)
        return total

    def purge_all(self) -> int:
        """Delete ALL history rows (keeps warden baseline + policy)."""
        total = 0
        with self.db:
            for t in ("scans", "networks", "devices", "observations", "fixes"):
                cur = self.db.execute(f"DELETE FROM {t}")
                total += cur.rowcount or 0
        log.warning("purged entire history (%d rows) from %s", total, self.path)
        return total

    def anonymize_history(self, salt: str = "") -> int:
        """Irreversibly pseudonymise stored client MACs + drop PII columns.

        Rewrites devices/observations/fixes MACs to salted HMAC tokens and
        clears IPs/hostnames/probe lists. There is no inverse operation;
        sessions keep grouping because the mapping is deterministic.
        Returns rows rewritten.
        """
        from .privacy import is_pseudonym
        salt = salt or self.salt
        self._set_policy("salt", salt)
        self._set_policy("anonymized",
                         time.strftime("%Y-%m-%d %H:%M:%S"))
        total = 0
        with self.db:
            for t in ("devices", "observations", "fixes"):
                rows = self.db.execute(
                    f"SELECT DISTINCT mac FROM {t}").fetchall()
                for (mac,) in rows:
                    if not mac or is_pseudonym(mac):
                        continue
                    cur = self.db.execute(
                        f"UPDATE {t} SET mac = ? WHERE mac = ?",
                        (hash_mac(mac, salt), mac))
                    total += cur.rowcount or 0
            self.db.execute("UPDATE devices SET ip = '', hostname = '', "
                            "probed = ''")
        log.warning("anonymized %d history row(s) in %s (irreversible)",
                    total, self.path)
        return total

    def vacuum(self) -> None:
        """Reclaim space and wipe freed pages after prune/delete/purge."""
        with self.db:
            self.db.execute("PRAGMA secure_delete = ON")
        self.db.execute("VACUUM")
        log.info("vacuumed %s", self.path)

    def storage_report(self) -> dict:
        """Permissions + size + retention facts for `db --report` (#10)."""
        from .privacy import file_report
        rep = file_report(self.path)
        for suffix in ("-wal", "-shm"):
            if os.path.exists(self.path + suffix):
                rep[suffix.strip("-")] = file_report(self.path + suffix)
        rep["retention"] = self.retention.describe()
        rep["privacy_mode"] = self.privacy_mode
        rep["anonymized_writes"] = self.anonymize
        rep["tables"] = self.stats()
        return rep
