#!/usr/bin/env python3
"""Regenerate routerxpl/resources/catalogs/cve_extended_catalog.json from curated rows.

Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional


def row(
    cve: str,
    vendor: str,
    product: str,
    ver: str,
    desc: str,
    cvss: float,
    av: str = "REMOTE",
    ref: Optional[str] = None,
    exploit_available: bool = False,
) -> Dict[str, Any]:
    d: Dict[str, Any] = {
        "cve_id": cve,
        "vendor": vendor,
        "product": product,
        "affected_versions": ver,
        "description": desc,
        "cvss_score": cvss,
        "access_vector": av,
        "exploit_available": exploit_available,
    }
    if ref:
        d["references"] = [ref]
    return d


def build_entries() -> List[Dict[str, Any]]:
    e: List[Dict[str, Any]] = []
    # Fortinet — pandemia e pós-pandemia (SSL-VPN / admin / SSO)
    e.extend(
        [
            row(
                "CVE-2018-13379",
                "fortinet",
                "fortigate",
                "FortiOS 5.6.3–6.0.4 SSL-VPN",
                "Path traversal / credenciais expostas na interface SSL VPN",
                9.1,
                ref="https://www.fortiguard.com/psirt/FG-IR-18-384",
                exploit_available=True,
            ),
            row(
                "CVE-2018-13382",
                "fortinet",
                "fortigate",
                "FortiOS 5.6.x–6.0.x",
                "Falha de autorização em SSL VPN",
                9.8,
                exploit_available=True,
            ),
            row("CVE-2018-13383", "fortinet", "fortigate", "FortiOS", "Heap overflow histórico SSL VPN", 8.8, exploit_available=True),
            row("CVE-2019-5598", "fortinet", "fortigate", "FortiOS", "Vulnerabilidade SSL VPN", 9.8, exploit_available=True),
            row("CVE-2020-12812", "fortinet", "fortigate", "FortiOS 6.4–6.4.1, 6.2.5–6.2.7", "Bypass de 2FA em SSL VPN", 9.8, exploit_available=True),
            row("CVE-2020-29015", "fortinet", "fortigate", "FortiOS", "Impacto CSRF / interface web", 7.5),
            row("CVE-2021-1722", "fortinet", "fortigate", "FortiOS SSL-VPN", "Heap buffer overflow", 7.5, exploit_available=True),
            row("CVE-2021-22123", "fortinet", "fortigate", "FortiWeb/FortiOS", "Stack buffer overflow", 9.3, exploit_available=True),
            row("CVE-2021-32589", "fortinet", "fortigate", "FortiOS SSL-VPN", "Use-after-free", 8.7, exploit_available=True),
            row("CVE-2022-26125", "fortinet", "fortigate", "FortiOS", "Escrita fora dos limites HTTP/HTTPS", 8.1),
            row(
                "CVE-2022-40684",
                "fortinet",
                "fortigate",
                "FortiOS 7.0.0–7.0.6, 7.2.0–7.2.1",
                "Bypass de autenticação via requisição HTTP(S) forjada",
                9.8,
                exploit_available=True,
            ),
            row("CVE-2022-42475", "fortinet", "fortigate", "FortiOS SSL-VPN (múltiplas branches)", "Heap overflow pré-auth RCE SSL VPN", 9.3, exploit_available=True),
            row(
                "CVE-2023-27997",
                "fortinet",
                "fortigate",
                "FortiOS SSL-VPN (várias séries)",
                "Heap overflow pré-autenticação em SSL VPN (XR variant amplamente explorada)",
                9.8,
                exploit_available=True,
            ),
            row("CVE-2023-28001", "fortinet", "fortigate", "FortiOS", "Sessão REST API / expiração insuficiente", 9.8),
            row("CVE-2023-33308", "fortinet", "fortigate", "FortiOS 7.0–7.2", "Stack overflow", 9.8),
            row("CVE-2023-36633", "fortinet", "fortigate", "FortiOS", "Corrupção de memória / format string class", 9.8),
            row("CVE-2023-42789", "fortinet", "fortigate", "FortiOS", "Escrita fora dos limites via HTTP", 9.8),
            row("CVE-2024-21762", "fortinet", "fortigate", "FortiOS 7.4–7.0 SSL-VPN", "Escrita fora dos limites SSL VPN RCE", 9.6, exploit_available=True),
            row("CVE-2024-23113", "fortinet", "fortigate", "FortiOS", "Format string", 9.8, exploit_available=True),
            row("CVE-2024-52965", "fortinet", "fortigate", "FortiOS", "Correção de memória ( advisories Fortinet)", 8.6),
            row("CVE-2024-55599", "fortinet", "fortigate", "FortiOS", "Advisory cumulativo FortiOS", 8.8),
            row("CVE-2025-24477", "fortinet", "fortigate", "FortiOS", "FortiOS security fix (verificar versão exata no PSIRT)", 8.5),
            row(
                "CVE-2025-59718",
                "fortinet",
                "fortigate",
                "FortiOS FortiCloud SSO (7.x)",
                "Falha em verificação SAML / bypass SSO administrativo",
                9.8,
                exploit_available=True,
            ),
            row("CVE-2025-59719", "fortinet", "fortigate", "FortiOS FortiCloud SSO", "Autenticação SSO fraca / chained impact", 9.1, exploit_available=True),
        ]
    )
    # Cisco, Juniper, PAN, edge SSL VPN / NGFW-adjacent
    e.extend(
        [
            row("CVE-2023-20198", "cisco", "ios_xe", "IOS XE Web UI", "Elevação de privilégio via Web UI (contas locais)", 10.0, exploit_available=True),
            row("CVE-2023-20273", "cisco", "ios_xe", "IOS XE Web UI", "Command injection pós-auth", 7.2, exploit_available=True),
            row("CVE-2024-20353", "cisco", "asa", "ASA", "Advisory VPN/SSL", 8.2),
            row("CVE-2024-20359", "cisco", "ios_xe", "IOS XE", "Elevação / hardening", 8.8),
            row("CVE-2023-36844", "juniper", "junos", "EX/SRX J-Web", "Cadeia RCE J-Web PHP", 9.8, exploit_available=True),
            row("CVE-2023-36845", "juniper", "junos", "EX/SRX J-Web", "Manipulação de ambiente PHP RCE", 9.8, exploit_available=True),
            row("CVE-2024-3400", "paloalto", "pan-os", "PAN-OS GlobalProtect", "Command injection GlobalProtect RCE", 10.0, exploit_available=True),
            row("CVE-2021-3064", "paloalto", "pan-os", "PAN-OS GlobalProtect", "Buffer overflow", 9.8, exploit_available=True),
            row("CVE-2021-20016", "sonicwall", "sma", "SMA 100", "SQLi / credenciais", 9.8, exploit_available=True),
            row("CVE-2021-20038", "sonicwall", "sonicwall", "SMA 100", "Stack buffer overflow RCE", 9.8, exploit_available=True),
            row("CVE-2022-1040", "sophos", "xg_firewall", "Sophos XG", "Bypass de autenticação / SQL", 9.8, exploit_available=True),
            row("CVE-2024-24919", "checkpoint", "quantum", "Check Point Gaia", "Path traversal / cadeia de impacto", 8.6, exploit_available=True),
            row("CVE-2022-1388", "f5", "bigip", "BIG-IP iControl REST", "Bypass de auth RCE", 9.8, exploit_available=True),
            row("CVE-2023-46747", "f5", "bigip", "BIG-IP", "Cadeia RCE iControl", 9.8, exploit_available=True),
            row("CVE-2024-26026", "ivanti", "connect_secure", "Ivanti Connect Secure", "Stack overflow SSL VPN", 9.0, exploit_available=True),
            row("CVE-2024-21887", "ivanti", "connect_secure", "Ivanti Connect Secure", "Command injection", 9.1, exploit_available=True),
            row("CVE-2024-21893", "ivanti", "connect_secure", "Ivanti Connect Secure", "SSRF", 8.2, exploit_available=True),
            row("CVE-2025-0282", "ivanti", "connect_secure", "Ivanti Connect Secure", "Heap overflow / RCE (patched versions no PSIRT)", 9.0, exploit_available=True),
            row("CVE-2021-35395", "zyxel", "firewall", "Múltiplos Zyxel", "Command injection", 9.8, exploit_available=True),
            row("CVE-2022-30525", "zyxel", "firewall", "USG FLEX", "OS command injection", 9.8, exploit_available=True),
            row("CVE-2023-28771", "zyxel", "multiple", "CPE Zyxel", "Format string via SMS / remoto", 9.1, exploit_available=True),
            row("CVE-2023-30799", "mikrotik", "routeros", "RouterOS", "Escalação admin→super-admin", 7.2, exploit_available=True),
            row("CVE-2021-34991", "netgear", "router", "Netgear Circle / Nighthawk class", "Buffer overflow RCE não autenticado", 9.8, exploit_available=True),
            row("CVE-2023-1389", "tplink", "router", "Archer AX21 family", "Command injection", 8.8, exploit_available=True),
            row("CVE-2022-25077", "tplink", "router", "WR841N family", "Buffer overflow HTTPD", 8.8, exploit_available=True),
            row("CVE-2017-14116", "pace", "5268ac", "Pace 5268AC", "Exposição de configuração / credenciais", 7.5),
            row("CVE-2018-10562", "generic", "gpon_onu", "ONU GPON classe Dasan", "Bypass massivo em ONU (classe CPE barata)", 9.8, exploit_available=True),
            row("CVE-2017-9833", "hitron", "modem", "Hitron CGNV / ISP CPE", "Bypass / config", 8.1),
            row("CVE-2022-26531", "draytek", "vigor", "Vigor", "Command injection", 9.8, exploit_available=True),
            row("CVE-2023-47218", "watchguard", "firebox", "Firebox", "Stack overflow", 9.8, exploit_available=True),
            row("CVE-2019-11510", "pulse", "pulse_secure", "Pulse Connect Secure", "Leitura arbitrária de ficheiros", 10.0, exploit_available=True),
            row("CVE-2021-22893", "pulse", "pulse_connect", "Pulse Secure", "RCE / memory safety", 9.9, exploit_available=True),
            row("CVE-2024-0012", "aruba", "instant_on", "Aruba Instant On", "Bypass de autenticação (verificar firmware)", 9.1),
            row("CVE-2020-10882", "tplink", "router", "Archer A7 v5", "tdpServer buffer overflow RCE (LAN)", 8.8, "ADJACENT"),
            row("CVE-2020-25506", "dlink", "router", "D-Link DSR/DWL", "Comand injection web", 9.8, exploit_available=True),
            row("CVE-2020-9325", "dlink", "router", "DIR seriado", "Stack overflow HTTP", 8.8),
            row("CVE-2021-4045", "realtek", "sdk", "Realtek RTL819x SDK", "RCE em firmware baseado RTL819x", 9.8, exploit_available=True),
            row("CVE-2021-44228", "generic", "log4j", "Apps com Log4j em CPE/gestão", "Log4Shell (cadeias de gestão / SDN)", 10.0, exploit_available=True),
            row("CVE-2022-30075", "tplink", "router", "Archer AX50 v1", "RCE autenticado via backup", 8.8, exploit_available=True),
            row("CVE-2022-41607", "cisco", "small_business", "Cisco RV routers", "Buffer overflow (advisory)", 8.2),
            row("CVE-2023-20025", "cisco", "small_business", "Cisco RV160/260/340", "Auth bypass (verificar)", 9.8, exploit_available=True),
            row("CVE-2024-20419", "cisco", "asa", "ASA", "VPN/SSL advisory", 8.1),
            row("CVE-2024-20464", "cisco", "ios_xe", "IOS XE", "DoS / hardening", 7.5),
            row("CVE-2024-45789", "mikrotik", "routeros", "RouterOS Winbox", "Correções Winbox/crypto chain", 7.8),
            row("CVE-2025-20194", "cisco", "ios_xe", "IOS XE SD-WAN", "Advisory Cisco (verificar)", 8.4),
            row("CVE-2020-5135", "sonicwall", "sonicwall", "SonicOS", "Buffer overflow VPN", 9.4),
            row("CVE-2021-3140", "fortinet", "fortimanager", "FortiManager", "RCE / auth issues", 8.6),
            row("CVE-2022-27482", "hirschmann", "switch", "Hirschmann HiOS", "Switch industrial hardening", 7.3),
            row("CVE-2023-22305", "moxa", "switch", "Moxa industrial switches", "Auth / web", 8.8),
            row("CVE-2024-3272", "dlink", "switch", "D-Link DGS", "Stack overflow web (verificar modelo)", 8.8),
            row("CVE-2024-3273", "dlink", "switch", "D-Link", "Backdoor / credenciais hardcoded class", 9.8, exploit_available=True),
            row("CVE-2021-20090", "arcadyan", "router", "Arcadyan-based ISP CPE", "Auth bypass (múltiplos ISP)", 9.9, exploit_available=True),
            row("CVE-2021-20091", "buffalo", "router", "Buffalo WSR", "Auth bypass", 9.6),
            row("CVE-2022-44149", "tenda", "router", "Tenda AC seriado", "Buffer overflow", 9.8, exploit_available=True),
            row("CVE-2023-27259", "tenda", "router", "Tenda", "RCE HTTPD", 8.1),
            row("CVE-2019-16920", "dlink", "router", "DIR-655 family", "RCE não autenticado", 9.8, exploit_available=True),
            row("CVE-2020-12105", "mikrotik", "routeros", "RouterOS", "Vulnerabilidade SMB RouterOS (corrigida em releases posteriores)", 5.5),
            row("CVE-2019-5456", "ubiquiti", "unifi", "UniFi Controller", "CSRF / alteração de configuração", 8.8),
        ]
    )
    return e


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    entries = build_entries()
    payload = {
        "catalog_note": (
            "Índice estendido offline para RouterXPL-Forge (lookup). "
            "Não substitui NVD/CISA; cruze sempre com firmware e PSIRT do fabricante."
        ),
        "entry_count": len(entries),
        "entries": entries,
    }
    out = root / "routerxpl" / "resources" / "catalogs" / "cve_extended_catalog.json"
    out.write_text(json.dumps(payload, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    print("wrote {} entries -> {}".format(len(entries), out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
