"""Invoke Offensive Security ``searchsploit`` CLI when installed locally.

Exploit-DB / searchsploit are distributed under GPLv2 — maintain upstream
attribution and comply with license terms when redistributing databases.

Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from typing import Optional, Tuple

logger = logging.getLogger(__name__)


def find_searchsploit(explicit: str) -> Optional[str]:
    """Resolve searchsploit from explicit path, env ``RXF_SEARCHSPLOIT``, or PATH."""
    if explicit and explicit.strip():
        w = explicit if os.path.isfile(explicit) else shutil.which(explicit)
        if w:
            return w
    env = (os.environ.get("RXF_SEARCHSPLOIT") or "").strip()
    if env and os.path.isfile(env) and os.access(env, os.X_OK):
        return env
    return shutil.which("searchsploit")


def run_searchsploit(
    binary: str,
    search_term: str,
    as_json: bool,
    timeout_s: int,
) -> Tuple[int, str, str]:
    """Run searchsploit and return (code, stdout, stderr)."""
    args = [binary]
    if as_json:
        args.append("-j")
    args.append("--disable-colour")
    args.append(search_term.strip())
    logger.info("searchsploit: %s", " ".join(args))
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=max(1, int(timeout_s)),
            check=False,
        )
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired as exc:
        return -9, "", "timeout: {}".format(exc)
    except OSError as exc:
        return -1, "", str(exc)
