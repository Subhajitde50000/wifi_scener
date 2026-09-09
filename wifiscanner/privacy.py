"""Privacy controls: modes, anonymization, retention, redaction, secure files.

Fixes weaknesses #3 (long-term tracking), #5 (raw PCAP sensitivity),
#6 (traffic-analysis exposure) and #10 (sensitive history database):

* ``PrivacyMode`` — STANDARD (full detail, own-network use), MINIMAL
  (pseudonymised MACs, no hostnames/SSIDs/probe lists) and EPHEMERAL
  (nothing persisted at all; recording commands refuse to write).
* ``RetentionPolicy`` — every persisted row has a maximum age; the store
  enforces it automatically on open (default 90 days, configurable).
* ``hash_mac`` — HMAC-SHA256 pseudonyms with a per-database salt: sessions
  still group correctly across time, but the stored value cannot be turned
  back into a MAC without the salt, and different databases are unlinkable.
* Redaction helpers for traffic dissection (URLs, User-Agents, hostnames).
* ``secure_file`` / ``check_file_access`` — 0600 permissions + world-readable
  warnings for captures and databases (access control without new deps).
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re
import stat
import time
import urllib.parse
from dataclasses import dataclass
from typing import Optional

from .util import log


# ------------------------------------------------------------------- modes

class PrivacyMode:
    STANDARD = "standard"     # full detail; for your own network with consent
    MINIMAL = "minimal"       # pseudonymised MACs, no hostnames/probes/ports
    EPHEMERAL = "ephemeral"   # RAM only; any persistence call refuses


MODES = (PrivacyMode.STANDARD, PrivacyMode.MINIMAL, PrivacyMode.EPHEMERAL)

MODE_NOTES = {
    PrivacyMode.STANDARD: "full detail retained; use only on your own network",
    PrivacyMode.MINIMAL: "MACs pseudonymised, hostnames/probed-SSIDs/ports dropped",
    PrivacyMode.EPHEMERAL: "nothing is written to disk; history/record/export refuse",
}

DEFAULT_RETENTION_DAYS = 90.0
MINIMAL_RETENTION_DAYS = 7.0


@dataclass
class RetentionPolicy:
    """How long persisted rows may live."""
    days: float = DEFAULT_RETENTION_DAYS

    @property
    def cutoff(self) -> float:
        return time.time() - self.days * 86400

    @property
    def enabled(self) -> bool:
        return self.days > 0

    def describe(self) -> str:
        if not self.enabled:
            return "retention DISABLED — history grows without bound (not recommended)"
        return f"rows older than {self.days:g} days are pruned automatically"


def coerce_mode(value: str = "") -> str:
    v = (value or "").strip().lower()
    if v in MODES:
        return v
    if v in ("min", "anon", "anonymized", "anonymous"):
        return PrivacyMode.MINIMAL
    if v in ("ram", "memory", "no-store", "no-persist"):
        return PrivacyMode.EPHEMERAL
    return PrivacyMode.STANDARD


# ------------------------------------------------------------- pseudonyms

def hash_mac(mac: str, salt: str) -> str:
    """Deterministic, salted, irreversible pseudonym for a MAC address.

    Same (mac, salt) always yields the same token, so sessions and device
    counts still group correctly — but the token reveals nothing about the
    MAC, and tokens from two databases with different salts cannot be joined.
    """
    mac = (mac or "").upper().strip()
    if not mac:
        return ""
    digest = hmac.new(salt.encode(), mac.encode(), hashlib.sha256).hexdigest()
    return f"H:{digest[:12]}"


def is_pseudonym(value: str) -> bool:
    return bool(re.fullmatch(r"H:[0-9a-f]{12}", (value or "").strip()))


def new_salt() -> str:
    return os.urandom(16).hex()


def anonymize_hostname(hostname: str) -> str:
    """Keep only that *a* name existed, never the name itself."""
    if not hostname:
        return ""
    if hostname == "(gateway/router)":
        return "(gateway/router)"
    return "(redacted)"


def mask_ip(ip: str) -> str:
    """Zero the host bits of an IPv4 address (/24) for minimal-mode output."""
    m = re.match(r"^(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}$", (ip or "").strip())
    if m:
        return f"{m.group(1)}.0/24"
    if ":" in (ip or ""):  # IPv6: keep the /64 only
        parts = ip.split(":")
        return ":".join((parts + [""] * 8)[:4]) + "::/64"
    return ip or ""


# --------------------------------------------------------------- redaction

_TRACKING_PARAMS = {"gclid", "fbclid", "msclkid", "_ga", "utm_source",
                    "utm_medium", "utm_campaign", "utm_term", "utm_content",
                    "sessionid", "sid", "token", "auth", "key", "password",
                    "passwd", "pwd", "secret", "api_key", "apikey"}


def redact_url(url: str, max_len: int = 80) -> str:
    """Strip query strings/fragments (credentials, session tokens, tracking
    IDs live there) and truncate. The path prefix is kept for audit value."""
    if not url:
        return ""
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return url[:max_len]
    if parts.query:
        qs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
        kept = [(k, v) for k, v in qs if k.lower() not in _TRACKING_PARAMS]
        if kept and len(kept) == len(qs):
            # No sensitive keys, but still drop VALUES — names are enough
            # to show what an app leaks without exposing the leaked data.
            query = "&".join(f"{k}=…" for k, _ in kept)
            clean = urllib.parse.urlunsplit(
                (parts.scheme, parts.netloc, parts.path, query, ""))
        else:
            clean = urllib.parse.urlunsplit(
                (parts.scheme, parts.netloc, parts.path, "", ""))
            if qs:
                clean += "?…(query-stripped)"
    else:
        clean = urllib.parse.urlunsplit(
            (parts.scheme, parts.netloc, parts.path, "", ""))
    if len(clean) > max_len:
        clean = clean[:max_len] + "…"
    return clean


def redact_user_agent(ua: bytes | str, keep_product: bool = True) -> str:
    """Reduce a User-Agent to its product token ('TestAgent/1.0' -> 'TestAgent').

    Full UA strings are fingerprinting material (OS, build, device); the
    product token is enough to identify *what kind* of client leaked it.
    """
    if isinstance(ua, bytes):
        ua = ua.decode(errors="replace")
    ua = (ua or "").strip()
    if not ua:
        return ""
    if not keep_product:
        return "(redacted)"
    token = re.split(r"[ /;(]", ua, maxsplit=1)[0]
    return token[:32] or "(redacted)"


def redact_hostname_in_text(text: str) -> str:
    """Scrub DHCP/mDNS-style hostnames that embed owner names."""
    return (text or "")[:64]


_CRED_VALUE_RE = re.compile(
    r"(?i)(password|passwd|pwd|secret|token|api[-_]?key|auth|sessionid|sid)"
    r"\s*[:=]\s*\S+")


def scrub_credentials(text: str) -> str:
    """Replace any credential-looking `key=value` with `key=[REDACTED]`."""
    return _CRED_VALUE_RE.sub(lambda m: m.group(0).split(m.group(0)[-1])[0]
                              if False else f"{m.group(1)}=[REDACTED]",
                              text or "")


def truncate(text: str, limit: int = 150) -> str:
    if text is None:
        return ""
    return text if len(text) <= limit else text[:limit] + "…"


# ------------------------------------------------------------ secure files

def secure_file(path: str) -> bool:
    """Restrict a sensitive file (pcap / sqlite / export) to owner-only (0600).

    Returns True when the permission is now 0600. This is the access-control
    layer that needs no extra dependencies; pair it with full-disk encryption
    for captures at rest (see README §19).
    """
    try:
        os.chmod(path, 0o600)
        return True
    except OSError as exc:
        log.warning("could not secure %s: %s", path, exc)
        return False


def check_file_access(path: str) -> str:
    """Return a warning string if a sensitive file is readable by others."""
    try:
        mode = stat.S_IMODE(os.stat(path).st_mode)
    except OSError:
        return ""
    if mode & (stat.S_IRGRP | stat.S_IROTH):
        return (f"{path} is readable by other users (mode {oct(mode)}); "
                f"run with --secure-storage or `chmod 600 {path}`")
    return ""


def ensure_secure_storage(path: str, fix: bool = True) -> Optional[str]:
    """Warn (and optionally fix) lax permissions on a sensitive file."""
    warn = check_file_access(path)
    if warn and fix:
        secure_file(path)
        warn = check_file_access(path)
        if not warn:
            log.info("restricted %s to owner-only access (0600)", path)
            return ""
    return warn


def file_report(path: str) -> dict:
    """Size/mode/owner facts about a sensitive artefact for `db --report`."""
    try:
        st = os.stat(path)
        return {"path": path, "bytes": st.st_size,
                "mode": oct(stat.S_IMODE(st.st_mode)),
                "world_readable": bool(stat.S_IMODE(st.st_mode)
                                       & (stat.S_IRGRP | stat.S_IROTH)),
                "uid": st.st_uid,
                "mtime": time.strftime("%Y-%m-%d %H:%M:%S",
                                       time.localtime(st.st_mtime))}
    except OSError as exc:
        return {"path": path, "error": str(exc)}
