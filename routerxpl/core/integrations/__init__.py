"""Optional bridges to external frameworks (Metasploit, Searchsploit, etc.).

Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""

from routerxpl.core.integrations.msf_cli import find_msfconsole, run_msf_batch_commands
from routerxpl.core.integrations.searchsploit_cli import find_searchsploit, run_searchsploit

__all__ = (
    "find_msfconsole",
    "run_msf_batch_commands",
    "find_searchsploit",
    "run_searchsploit",
)
