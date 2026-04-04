# Catalogs and `tools/`

**Language:** English (en-US). **pt-BR:** [../pt-BR/10-catalogos-e-ferramentas.md](../pt-BR/10-catalogos-e-ferramentas.md)

## `routerxpl/resources/catalogs/`

| File | Role |
|------|------|
| `market_priority_devices_2010_2026.json` | Market device pool + yearly lists |
| `module_target_scope.json` | AutoPwn scope policy |
| `cve_extended_catalog.json` | CVE DB extension |
| `discord_requested_devices.json` | Community requests |
| `external_tool_intel_sources.json` | External intel URLs (incl. MSF / Exploit-DB bridges) |
| `external_framework_clones.json` | Curated official clone URLs + license notes; pairs with `generic/external/*` bridges |
| `deep_intel_backlog.json` | Intel backlog items |

## Architecture diagrams

Device-class attack-surface PNGs and Mermaid sources: [../../diagrams/architecture/README.md](../../diagrams/architecture/README.md).

## Generated docs

- `docs/COVERAGE_MATRIX.md`
- `docs/FULL_CATALOG.md`

```bash
python tools/generate_coverage_matrix.py
```

## Useful scripts

| Script | Role |
|--------|------|
| `tools/env_doctor.py` | Dependency smoke |
| `tools/compat_smoke.py` | Compatibility smoke |
| `tools/validate_market_priority_minimums.py` | Market catalog validation |
| `tools/report_market_priority_gaps.py` | Gap CSV |
| `tools/gen_wiki_module_index.py` | Regenerate [../ANEXO-INDICE-MODULOS.md](../ANEXO-INDICE-MODULOS.md) |
| `tools/phase6_sync_external_intel.py` | External intel snapshot (environment-dependent) |

---

[Wiki hub](../README.md)
