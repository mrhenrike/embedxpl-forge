#!/usr/bin/env python3
"""Generate a full itemized catalog of all modules, CVEs, encoders, etc.

Produces FULL_CATALOG.md and FULL_CATALOG.txt with every module, exploit,
scanner, credential module, encoder, payload, CVE and attack class listed
individually in organized sections.

Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""

from __future__ import annotations

import ast
import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

LOGGER = logging.getLogger("full_catalog")
RE_CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
DISABLED_DOMAINS: Tuple[str, ...] = ("cameras", "printers", "dvr", "dvrs")


def _configure_logging() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")


def _safe_literal_eval(node: ast.AST) -> Any:
    try:
        return ast.literal_eval(node)
    except Exception:
        return None


def _extract_info_dict(source: str) -> Dict[str, Any]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "__info__":
                    data = _safe_literal_eval(node.value)
                    if isinstance(data, dict):
                        return data
    return {}


def _collect_modules(modules_root: Path) -> List[Dict[str, Any]]:
    """Collect metadata from every module file."""
    records: List[Dict[str, Any]] = []
    for py_file in sorted(modules_root.rglob("*.py")):
        if py_file.name == "__init__.py":
            continue
        rel = py_file.relative_to(modules_root).as_posix()
        parts = rel.split("/")
        module_type = parts[0] if parts else "unknown"

        # Skip out-of-scope domains
        if any(d in rel.lower() for d in DISABLED_DOMAINS):
            continue

        source = py_file.read_text(encoding="utf-8", errors="ignore")
        info = _extract_info_dict(source)
        cves = sorted({c.upper() for c in RE_CVE.findall(source)})

        name = str(info.get("name", py_file.stem))
        description = str(info.get("description", "")).replace("\n", " ").strip()
        authors = info.get("authors", ())
        devices = info.get("devices", ())
        references = info.get("references", ())

        vendor = "multi"
        if module_type in ("exploits", "creds") and len(parts) > 2:
            vendor = parts[2]
        elif module_type in ("encoders", "payloads") and len(parts) > 1:
            vendor = parts[1]
        elif module_type == "generic" and len(parts) > 1:
            vendor = parts[1]
        elif module_type == "scanners" and len(parts) > 1:
            vendor = parts[1]

        records.append({
            "path": rel,
            "type": module_type,
            "vendor": vendor,
            "name": name,
            "description": description[:200],
            "cves": cves,
            "authors": list(authors) if isinstance(authors, (list, tuple)) else [],
            "devices": list(devices) if isinstance(devices, (list, tuple)) else [],
            "references": list(references) if isinstance(references, (list, tuple)) else [],
        })
    return records


def _build_md(records: List[Dict[str, Any]], repo_root: Path) -> str:
    """Build the full catalog in Markdown."""
    now = datetime.now(timezone.utc).isoformat()

    # Classify
    exploits = [r for r in records if r["type"] == "exploits"]
    creds = [r for r in records if r["type"] == "creds"]
    scanners = [r for r in records if r["type"] == "scanners"]
    generic = [r for r in records if r["type"] == "generic"]
    encoders = [r for r in records if r["type"] == "encoders"]
    payloads = [r for r in records if r["type"] == "payloads"]

    all_cves: Dict[str, List[str]] = {}
    for r in records:
        for cve in r["cves"]:
            all_cves.setdefault(cve, []).append(r["path"])

    lines: List[str] = [
        "# RouterXPL-Forge — Full Module Catalog",
        "",
        "> Generated: {}".format(now),
        "> Author: Andre Henrique (@mrhenrike) | Uniao Geek",
        "",
        "## Summary",
        "",
        "| Category | Count |",
        "|---|---:|",
        "| Exploits | {} |".format(len(exploits)),
        "| Credential Modules | {} |".format(len(creds)),
        "| Scanners | {} |".format(len(scanners)),
        "| Generic Modules | {} |".format(len(generic)),
        "| Encoders | {} |".format(len(encoders)),
        "| Payloads | {} |".format(len(payloads)),
        "| **Total Modules** | **{}** |".format(len(records)),
        "| Distinct CVEs | {} |".format(len(all_cves)),
        "",
        "---",
        "",
    ]

    def _section(title: str, items: List[Dict[str, Any]], show_cves: bool = True) -> List[str]:
        section_lines = ["## {} ({})".format(title, len(items)), ""]
        vendors: Dict[str, List[Dict[str, Any]]] = {}
        for item in items:
            vendors.setdefault(item["vendor"], []).append(item)

        idx = 0
        for vendor in sorted(vendors.keys()):
            section_lines.append("### {} ({})".format(vendor, len(vendors[vendor])))
            section_lines.append("")
            for item in sorted(vendors[vendor], key=lambda x: x["name"]):
                idx += 1
                section_lines.append("{}. **{}**".format(idx, item["name"]))
                section_lines.append("   - Path: `{}`".format(item["path"]))
                if item["description"]:
                    section_lines.append("   - {}".format(item["description"]))
                if show_cves and item["cves"]:
                    section_lines.append("   - CVEs: {}".format(", ".join(item["cves"])))
                if item["devices"]:
                    section_lines.append("   - Devices: {}".format(", ".join(str(d) for d in item["devices"][:10])))
                section_lines.append("")
        return section_lines

    lines.extend(_section("Exploits", exploits))
    lines.extend(_section("Credential Modules", creds))
    lines.extend(_section("Scanners", scanners))
    lines.extend(_section("Generic Modules", generic))
    lines.extend(_section("Encoders", encoders, show_cves=False))
    lines.extend(_section("Payloads", payloads, show_cves=False))

    # CVE master list
    lines.extend([
        "---",
        "",
        "## CVE Master List ({})".format(len(all_cves)),
        "",
        "| # | CVE ID | Modules |",
        "|---:|---|---|",
    ])
    for idx, (cve_id, paths) in enumerate(sorted(all_cves.items()), 1):
        modules_str = ", ".join("`{}`".format(p) for p in paths[:5])
        if len(paths) > 5:
            modules_str += " (+{})".format(len(paths) - 5)
        lines.append("| {} | {} | {} |".format(idx, cve_id, modules_str))

    # CVE by vendor
    cve_by_vendor: Dict[str, Set[str]] = {}
    for r in records:
        for cve in r["cves"]:
            cve_by_vendor.setdefault(r["vendor"], set()).add(cve)

    lines.extend([
        "",
        "## CVEs by Vendor",
        "",
        "| Vendor | CVE Count | CVE IDs |",
        "|---|---:|---|",
    ])
    for vendor in sorted(cve_by_vendor.keys()):
        cves_sorted = sorted(cve_by_vendor[vendor])
        lines.append("| {} | {} | {} |".format(vendor, len(cves_sorted), ", ".join(cves_sorted)))

    # Access vector classification from CVE DB
    try:
        from routerxpl.core.cve.cve_db import CVEDatabase
        db = CVEDatabase()
        lines.extend([
            "",
            "## CVE Access Vector Classification",
            "",
            "| CVE ID | CVSS | Access Vector | Exploitable by RXF | Module |",
            "|---|---:|---|---|---|",
        ])
        for cve_id in sorted(all_cves.keys()):
            matches = [e for e in db._entries if e.cve_id.upper() == cve_id.upper()]
            if matches:
                e = matches[0]
                lines.append("| {} | {:.1f} | {} | {} | {} |".format(
                    e.cve_id, e.cvss_score, e.access_vector,
                    "YES" if e.is_exploitable_by_rxf else "no",
                    "`{}`".format(e.rxf_module) if e.rxf_module else "-",
                ))
            else:
                mod_paths = ", ".join("`{}`".format(p) for p in all_cves[cve_id][:3])
                lines.append("| {} | - | - | mapped | {} |".format(cve_id, mod_paths))
    except Exception:
        pass

    lines.extend(["", "---", "", "> Generated by tools/generate_full_catalog.py"])
    return "\n".join(lines)


def _build_txt(records: List[Dict[str, Any]]) -> str:
    """Build the full catalog in plain text."""
    now = datetime.now(timezone.utc).isoformat()
    lines: List[str] = [
        "RouterXPL-Forge - Full Module Catalog",
        "=" * 40,
        "Generated: {}".format(now),
        "Author: Andre Henrique (@mrhenrike) | Uniao Geek",
        "",
    ]

    type_labels = {
        "exploits": "EXPLOITS",
        "creds": "CREDENTIAL MODULES",
        "scanners": "SCANNERS",
        "generic": "GENERIC MODULES",
        "encoders": "ENCODERS",
        "payloads": "PAYLOADS",
    }

    all_cves: Dict[str, List[str]] = {}
    for r in records:
        for cve in r["cves"]:
            all_cves.setdefault(cve, []).append(r["path"])

    lines.append("SUMMARY")
    lines.append("-" * 20)
    for t in type_labels:
        count = sum(1 for r in records if r["type"] == t)
        lines.append("  {}: {}".format(type_labels[t], count))
    lines.append("  TOTAL: {}".format(len(records)))
    lines.append("  DISTINCT CVEs: {}".format(len(all_cves)))
    lines.append("")

    for mod_type, label in type_labels.items():
        items = [r for r in records if r["type"] == mod_type]
        if not items:
            continue
        lines.append("{} ({})".format(label, len(items)))
        lines.append("=" * 40)

        vendors: Dict[str, List[Dict[str, Any]]] = {}
        for item in items:
            vendors.setdefault(item["vendor"], []).append(item)

        idx = 0
        for vendor in sorted(vendors.keys()):
            lines.append("")
            lines.append("[{}] ({})".format(vendor.upper(), len(vendors[vendor])))
            lines.append("-" * 30)
            for item in sorted(vendors[vendor], key=lambda x: x["name"]):
                idx += 1
                lines.append("  {}. {}".format(idx, item["name"]))
                lines.append("     Path: {}".format(item["path"]))
                if item["description"]:
                    lines.append("     {}".format(item["description"][:120]))
                if item["cves"]:
                    lines.append("     CVEs: {}".format(", ".join(item["cves"])))
                if item["devices"]:
                    lines.append("     Devices: {}".format(", ".join(str(d) for d in item["devices"][:8])))
        lines.append("")

    lines.append("CVE MASTER LIST ({})".format(len(all_cves)))
    lines.append("=" * 40)
    for idx, (cve_id, paths) in enumerate(sorted(all_cves.items()), 1):
        lines.append("  {}. {} -> {}".format(idx, cve_id, ", ".join(paths[:5])))
    lines.append("")

    # Access vector
    try:
        from routerxpl.core.cve.cve_db import CVEDatabase
        db = CVEDatabase()
        lines.append("CVE ACCESS VECTOR CLASSIFICATION")
        lines.append("=" * 40)
        for cve_id in sorted(all_cves.keys()):
            matches = [e for e in db._entries if e.cve_id.upper() == cve_id.upper()]
            if matches:
                e = matches[0]
                exploitable = "EXPLOITABLE" if e.is_exploitable_by_rxf else "no module"
                lines.append("  {} | CVSS {:.1f} | {} | {} | {}".format(
                    e.cve_id, e.cvss_score, e.access_vector, exploitable,
                    e.rxf_module or "-",
                ))
            else:
                lines.append("  {} | mapped in: {}".format(cve_id, ", ".join(all_cves[cve_id][:3])))
    except Exception:
        pass

    lines.extend(["", "--- Generated by tools/generate_full_catalog.py ---"])
    return "\n".join(lines)


def main() -> int:
    """Generate the full catalog documents."""
    _configure_logging()
    repo_root = Path(__file__).resolve().parent.parent
    modules_root = repo_root / "routerxpl" / "modules"

    records = _collect_modules(modules_root)
    docs_dir = repo_root / "docs"
    docs_dir.mkdir(parents=True, exist_ok=True)

    md_path = docs_dir / "FULL_CATALOG.md"
    txt_path = docs_dir / "FULL_CATALOG.txt"

    md_path.write_text(_build_md(records, repo_root), encoding="utf-8")
    txt_path.write_text(_build_txt(records), encoding="utf-8")

    LOGGER.info("Full catalog generated: %s and %s (%d modules, %d CVEs)",
                md_path, txt_path, len(records),
                len({c for r in records for c in r["cves"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
