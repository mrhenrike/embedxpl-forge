# Scanners and AutoPwn

**Language:** English (en-US). **pt-BR:** [../pt-BR/07-scanners-e-autopwn.md](../pt-BR/07-scanners-e-autopwn.md)

## `scanners/routers/router_scan`

Broad `generic + routers` orchestration entry point.

```text
use scanners/routers/router_scan
set target 192.168.1.1
run
```

## `scanners/autopwn`

Parallel scan with credential and exploit checks; **timing templates** similar to Nmap `T0`–`T5`.

### Key options

| Option | Description |
|--------|-------------|
| `target` | IP |
| `target_device_class` | `multi`, `router`, `switch`, `tap`, `fw`, `ngfw`, `isp_cpe` — see `routerxpl/resources/catalogs/module_target_scope.json` |
| `vendor` | Filter when supported |
| `timing_template` | `t0`..`t5` or aliases `paranoid` … `insane` |
| `check_exploits` / `check_creds` | Enable/disable classes of tests |
| HTTP/FTP/SSH/SFTP/Telnet/SNMP/TCP/UDP | `*_use`, ports, SSL flags |
| `threads`, `verify_positive_twice`, `module_timeout_s` | Performance / reliability |

### Example

```text
use scanners/autopwn
set target 192.168.50.1
set timing_template polite
set target_device_class router
run
```

Use `show advanced` for the full set.

## `scanners/routers/fortigate_sslvpn_scan`

SSL-VPN / FortiGate-oriented recon (authorized testing only).

## `scanners/routers/hootoo_scan`

HooToo-focused AutoPwn-style scanner.

---

[Wiki hub](../README.md)
