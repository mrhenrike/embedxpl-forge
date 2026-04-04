# RouterXPL-Forge - Exploitation Framework for Embedded Devices

[![Python 3.8-3.13](https://img.shields.io/badge/Python-3.8--3.13-blue.svg)](https://www.python.org/downloads/)
[![CI](https://github.com/mrhenrike/RouterXPL-Forge/actions/workflows/compat-matrix.yml/badge.svg)](https://github.com/mrhenrike/RouterXPL-Forge/actions)

# Description

The RouterXPL-Forge Framework is an open-source exploitation framework dedicated to embedded devices,
focused on **routers, switches, TAPs (physical/virtual), firewalls and next-generation firewalls (NGFW)**.

It consists of various modules that aid penetration testing operations:

* **exploits** - modules that take advantage of identified vulnerabilities
* **creds** - modules designed to test credentials against network services
* **scanners** - modules that check if a target is vulnerable to any exploit (including `autopwn` with Nmap-style timing profiles)
* **payloads** - modules responsible for generating payloads for various architectures and injection points
* **generic** - modules that perform generic attacks (SNMP, SSH auth keys, HTTP oracle, etc.)
* **encoders** - modules for encoding payloads in multiple languages (Python, PHP, Perl)

# Compatibility Notice

> **Important:** Some platforms listed below have not been tested in real-world environments.
> If you encounter issues on untested platforms, please open an issue with your environment details.

| Platform | Status |
|---|---|
| Windows 10/11 | Validated locally and in CI |
| WSL / Ubuntu / Debian-based Linux | Validated locally and in CI |
| Kali Linux | Validated locally |
| macOS | Validated in CI (not field-tested) |
| RHEL / CentOS / Fedora | Compatible by design — **not validated** |
| Termux / Android / NetHunter | Compatible by design — **not validated** |

RouterXPL-Forge supports Python **3.8 through 3.13**. A compatibility shim is included for
`telnetlib` removal in Python 3.13 and `pkg_resources` deprecation.

Run `python tools/env_doctor.py` for a quick diagnostic of your environment.

# Installation

## Requirements

Required (installed via `requirements.txt`):
* requests
* paramiko
* pysnmp
* pycryptodome

Optional:
* bluepy - Bluetooth Low Energy (Linux only)

## Quick Start (all platforms)

```bash
git clone https://github.com/mrhenrike/RouterXPL-Forge.git
cd RouterXPL-Forge
python3 -m venv .venv
# Linux/macOS:
source .venv/bin/activate
# Windows:
# .venv\Scripts\activate
python3 -m pip install -r requirements.txt
python3 rxf.py
```

## Kali Linux

```bash
apt-get install python3-pip python3-venv
git clone https://github.com/mrhenrike/RouterXPL-Forge.git
cd RouterXPL-Forge
python3 -m venv .venv && source .venv/bin/activate
python3 -m pip install -r requirements.txt
python3 rxf.py
```

Bluetooth Low Energy support:
```bash
apt-get install libglib2.0-dev
python3 -m pip install bluepy
```

## Ubuntu / Debian

```bash
sudo apt-get install git python3-pip python3-venv
git clone https://github.com/mrhenrike/RouterXPL-Forge.git
cd RouterXPL-Forge
python3 -m venv .venv && source .venv/bin/activate
python3 -m pip install -r requirements.txt
python3 rxf.py
```

## macOS

```bash
git clone https://github.com/mrhenrike/RouterXPL-Forge.git
cd RouterXPL-Forge
python3 -m venv .venv && source .venv/bin/activate
python3 -m pip install -r requirements.txt
python3 rxf.py
```

## Windows

```powershell
git clone https://github.com/mrhenrike/RouterXPL-Forge.git
cd RouterXPL-Forge
python -m venv .venv
.venv\Scripts\activate
python -m pip install -r requirements.txt
python rxf.py
```

# Update

```bash
cd RouterXPL-Forge
git pull
python3 -m pip install -r requirements.txt
```

# Build Your Own

[_Riposte_](https://github.com/fwkz/riposte) allows you to easily wrap your
application inside a tailored interactive shell. Common chores regarding
building REPLs are factored out so you can focus on domain logic.

# License

The RouterXPL-Forge Framework is under a BSD license.
Please see [LICENSE](LICENSE) for more details.

# Acknowledgments

* [riposte](https://github.com/fwkz/riposte) - interactive shell framework
* Original upstream: [threat9/routersploit](https://github.com/threat9/routersploit)

---

> Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
