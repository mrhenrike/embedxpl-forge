"""Run locally installed ``searchsploit`` (Exploit-DB CLI).

Exploit-DB code/data are GPLv2 — preserve notices if you redistribute copies.
This module only shells out to your installation.

Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""

from __future__ import annotations

from routerxpl.core.exploit import *
from routerxpl.core.integrations.searchsploit_cli import find_searchsploit, run_searchsploit


class Exploit(Exploit):
    """Query Exploit-DB via searchsploit CLI."""

    __info__ = {
        "name": "Searchsploit Bridge",
        "description": "Runs `searchsploit` against a term (optional JSON). Requires Exploit-DB package on host. "
        "Respect GPLv2 and upstream attribution for databases and scripts.",
        "authors": (
            "André Henrique (@mrhenrike)",
        ),
        "references": (
            "https://gitlab.com/exploit-database/exploitdb",
            "https://www.exploit-db.com/",
        ),
        "devices": (
            "Research / catalog",
        ),
    }

    search_term = OptString("router", "Search string (vendor, CVE, title fragment, …)")
    json_output = OptBool(True, "Pass -j to searchsploit when supported")
    searchsploit_path = OptString("", "searchsploit binary (empty = RXF_SEARCHSPLOIT or PATH)")
    timeout_s = OptInteger(120, "Subprocess timeout seconds")
    verbosity = OptBool(True, "Print raw CLI output")

    def run(self) -> None:
        """Invoke searchsploit."""
        binary = find_searchsploit(str(self.searchsploit_path))
        if not binary:
            print_error(
                "searchsploit not found. Install exploitdb package or set searchsploit_path / RXF_SEARCHSPLOIT.",
                verbose=True,
            )
            return

        print_status("Using: {}".format(binary), verbose=self.verbosity)
        code, out, err = run_searchsploit(
            binary,
            str(self.search_term),
            bool(self.json_output),
            int(self.timeout_s),
        )
        if out and self.verbosity:
            print_status(out)
        if err and self.verbosity:
            print_error(err)
        if code == 0:
            print_success("searchsploit completed", verbose=self.verbosity)
        else:
            print_error("searchsploit exit code {}".format(code))
