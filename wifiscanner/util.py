"""Shared helpers: shell execution, platform detection, logging."""
from __future__ import annotations

import logging
import os
import platform
import shutil
import subprocess
import sys

log = logging.getLogger("wifiscanner")


def setup_logging(verbose: bool = False, quiet: bool = False) -> None:
    level = logging.DEBUG if verbose else (logging.ERROR if quiet else logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-7s %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stderr,
    )


def which(cmd: str) -> str | None:
    return shutil.which(cmd)


def run(cmd, timeout: int = 25, check: bool = False) -> tuple[int, str, str]:
    """Run a command, returning (rc, stdout, stderr). Never raises on failure."""
    if isinstance(cmd, str):
        cmd = cmd.split()
    log.debug("exec: %s", " ".join(cmd))
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, errors="ignore")
        if check and p.returncode != 0:
            log.debug("cmd failed rc=%s: %s", p.returncode, p.stderr.strip()[:200])
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", f"{cmd[0]}: not found"
    except subprocess.TimeoutExpired:
        return 124, "", f"{cmd[0]}: timed out after {timeout}s"
    except Exception as exc:                                  # pragma: no cover
        return 1, "", str(exc)


def os_name() -> str:
    s = platform.system().lower()
    if s.startswith("linux"):
        return "linux"
    if s.startswith("darwin"):
        return "macos"
    if s.startswith("windows"):
        return "windows"
    return s or "unknown"


def is_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:                                    # Windows
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False


def human_bytes(n: int) -> str:
    f = float(n or 0)
    for unit in ("B", "KB", "MB", "GB"):
        if f < 1024 or unit == "GB":
            return f"{f:.0f}{unit}" if unit == "B" else f"{f:.1f}{unit}"
        f /= 1024
    return f"{f:.1f}GB"
