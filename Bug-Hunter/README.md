# Bug Hunter — Cross-Platform Router Vulnerability Scanner

A **read-only** Python tool that hunts the **physical router on your LAN** and
runs a **live security audit** of it: gateway detection, vendor fingerprinting,
port/service probing, and CVE-matched vulnerability checks against the unit in
front of you — not a simulation.

Generates a detailed report with vulnerability details, CVE references, severity ratings,
and step-by-step fix/remediation methods.

> **Real hunt vs. play.**
> `bug_hunter.py` is the real thing: every probe goes to the physical device.
> `demo_scan.py` / `test_scanner.py` are the playground — mock routers on
> localhost for learning and testing only. Nothing in them touches hardware.

## Physical Device Audit (v1.1 — the primary use)

Feed Bug Hunter the sticker off the bottom of your unit and it anchors the audit
to the physical box, cross-checks the sticker against what the device reports
about itself, saves the hunt as an audit artifact, and diffs every later run
against the last one.

```bash
# Example: auditing a PTCL D-Link DSL-226 (sticker: FW PT_1.10_J2, HW J2)
python3 bug_hunter.py 192.168.10.1 --audit \
    --model DSL-226 --firmware PT_1.10_J2 --hw J2 \
    --serial <serial on sticker> --mac <mac on sticker>
```

What audit mode does on top of a plain scan:

| Step | What happens |
|---|---|
| **1. Label load** | `--model/--firmware/--hw/--serial/--mac` are read into the audit |
| **2. Live hunt** | The physical unit is probed (ports, banner, webproc, traversal, `dnscfg.cgi`, …) |
| **3. Self-report capture** | Model/FW/HW/serial/MAC extracted from the unit's own pages |
| **4. Cross-check** | Sticker vs. unit: gaps filled from the sticker, contradictions flagged as **MISMATCH**, sticker MAC verified against the MACs the unit displayed |
| **5. Artifact** | TXT + JSON saved to `audits/` as `<model>_<ip>_<UTC-stamp>` (git-ignored — device data stays local) |
| **6. Drift** | Next `--audit` of the same IP diffs against the previous one: **NEW / RESOLVED / STILL PRESENT** findings |

All label fields are optional — `--audit` alone works; the first run simply
becomes the baseline for the unit being audited.


## Features

| Feature | Description |
|---|---|
| **Physical-device audit** | `--audit` hunts the live unit, saves model-stamped artifacts, diffs runs over time |
| **Sticker identity cross-check** | `--model/--firmware/--hw/--serial/--mac` vs. the unit's self-report; mismatches flagged |
| **Auto-detect gateway** | Finds your router automatically — works on Windows, Linux, macOS, Termux |
| **Vendor fingerprinting** | Identifies D-Link, ZTE, TP-Link, Huawei, Netgear, Linksys, FiberHome |
| **Port scanning** | Checks common router services (HTTP, SSH, Telnet, FTP, SNMP, UPnP, TR-069, ADB) |
| **D-Link checks** | webproc auth bypass, Wi-Fi key leak, file traversal, persistent session, ACME httpd banner (CVE-2014-4927), `dnscfg.cgi` exposure (CVE-2026-0625) |
| **ZTE checks** | UPnP WLAN key disclosure (CVE-2018-7357/7358), CSRF, info leaks |
| **TP-Link checks** | rom-0 config disclosure, command injection, credential disclosure, RomPager |
| **Generic checks** | Telnet, FTP, SNMP, UPnP, TR-069, ADB, missing HTTPS, info leakage |
| **Text report** | Detailed `.txt` report with CVE links, descriptions, impacts, and fixes |
| **JSON report** | Machine-readable `.json` for automation and integration |
| **Zero dependencies** | Python standard library only — runs anywhere Python 3.8+ exists |
| **Read-only** | GET/HEAD only, no POST, no credential submission, no config writes |
| **LAN-only safety** | Refuses to scan public IPs — only your own network |

## Platform Support

| Platform | Tested | Notes |
|---|---|---|
| **Windows** | ✅ | Uses `ipconfig` for gateway detection |
| **Linux** | ✅ | Uses `ip route` / `route` |
| **macOS** | ✅ | Uses `route -n get default` |
| **Termux (Android)** | ✅ | Uses `ip route`, same as Linux |
| **FreeBSD** | ✅ | Uses `route` |
| **Raspberry Pi** | ✅ | Same as Linux |

## Quick Start

```bash
# PHYSICAL HUNT — audit the live router on your LAN
python bug_hunter.py                          # auto-detect your gateway and hunt it
python bug_hunter.py 192.168.10.1 --audit     # hunt + save audit + drift diff

# Hunt with the sticker identity (anchors the audit to the physical unit)
python bug_hunter.py 192.168.10.1 --audit \
    --model DSL-226 --firmware PT_1.10_J2 --hw J2

# Save a text report / JSON report anywhere you like
python bug_hunter.py 192.168.1.1 --report scan_report.txt --json scan_report.json

# Quick scan (fewer ports, faster)
python bug_hunter.py --quick

# Enable optional deep probes
python bug_hunter.py --probe-upnp --probe-rom0

# Force vendor detection
python bug_hunter.py --vendor dlink

# Verbose output (shows every HTTP request)
python bug_hunter.py -v
```

## What Gets Checked

### D-Link (PTCL DSL-series: DSL-2750U / DSL-2730U / DSL-2750E / DSL-226 / …)

| Check | CVE | Severity | What it finds |
|---|---|---|---|
| webproc Auth Bypass | CVE-2025-34048, CVE-2019-1010155 | **CRITICAL** | Wizard pages served without login |
| Wi-Fi Key Leak | CVE-2019-1010156 | **CRITICAL** | SSID + WPA key in page source |
| File Traversal | CVE-2025-34048 | **CRITICAL** | Read any file on the router |
| Persistent Session | CVE-2019-1010155 | **HIGH** | Bypass session never expires |
| ACME httpd front door | CVE-2014-4927 | **HIGH** | `micro_httpd` banner → long-URI DoS, never patched (flagged, not probed) |
| dnscfg.cgi exposure | CVE-2026-0625 | **HIGH / INFO** | Endpoint reachable without login (actively exploited DNSChanger/RCE family on legacy DSL gateways) |

> **Detection note:** the ACME banner on real units uses the underscore spelling
> (`micro_httpd`), and these units often answer `/` with a bare `401` and no
> vendor strings. Bug Hunter matches the banner (both spellings) and probes
> `/cgi-bin/webproc` with a neutral page, so the PTCL DSL class is detected
> from the field-scan shape, not only from a full login page. If the UI does
> not self-identify at all, a sticker `--model DSL-…` also implies D-Link and
> runs the same checks.

> **dnscfg.cgi probe is reachability-only.** CVE-2026-0625 (CVSS 9.3, exploited
> since 2025-11-27; confirmed on DSL-2740R / 2640B / 2780B / 526B) is a command
> injection via DNS parameters. Bug Hunter sends a **bare GET with no DNS
> parameters and no payload** — it confirms whether the endpoint runs without a
> login, nothing more. A 404 = absent (no finding); answered + no login = HIGH;
> answered + login demanded = INFO.

> **PTCL `PT_*` firmware note:** builds like `PT_1.10_J2` (DSL-226) and `PT_2.00`
> (DSL-2750U) appear in **no public CVE affected-version list** — those lists
> name retail `IN_*`/`SEA_*`/`ME_*` builds only. The report flags such firmware
> as *untested, not clean*; the live probes above are what decides.

### ZTE (PTCL H168N)

| Check | CVE | Severity | What it finds |
|---|---|---|---|
| UPnP WLAN Disclosure | CVE-2018-7357, CVE-2018-7358 | **CRITICAL** | Wi-Fi key via UPnP SOAP |
| v3.5 Info Leak | CVE-2021-21735 | **HIGH** | Config data via wizard page |
| v3.5 CSRF | CVE-2021-21729 | **HIGH** | No CSRF token protection |

### TP-Link

| Check | CVE | Severity | What it finds |
|---|---|---|---|
| rom-0 Disclosure | RomPager class | **HIGH** | Config backup without auth |
| WR840N Unpatched | CVE-2023-50224 | **CRITICAL** | Credential disclosure (v2/v3 EOL) |
| WR840N v6 RCE | CVE-2026-3227 | **HIGH** | Command injection via config |
| W8961N DoS | CVE-2025-15606 | **MEDIUM** | HTTPD crash (EOL product) |
| W9970 RCE | CVE-2023-6437 | **HIGH** | OS command injection |
| Misfortune Cookie | CVE-2014-9222 | **MEDIUM** | Session hijacking via RomPager |

### Generic (All Routers)

| Check | Severity | What it finds |
|---|---|---|
| Telnet exposed | **HIGH** | Plaintext remote access |
| FTP exposed | **MEDIUM** | Insecure file transfer |
| TR-069 exposed | **HIGH** | ISP remote management (RCE risk) |
| SNMP exposed | **MEDIUM** | Network data leakage |
| UPnP enabled | **MEDIUM** | WAN port manipulation by LAN malware |
| HTTP only (no HTTPS) | **MEDIUM** | Plaintext admin credentials |
| SSH with defaults | **LOW** | Potential weak credentials |
| Server header leak | **INFO** | Server software disclosure |
| ADB debug port | **HIGH** | Full shell access |
| No login prompt | **HIGH** | Possible unauthenticated admin access |

## Report Format

### Text Report (`.txt`)
```
==============================================================================
  BUG HUNTER — ROUTER VULNERABILITY SCAN REPORT
  Version 1.1.0
==============================================================================

  Scan Date     : 2026-09-21 14:30:00 UTC
  Platform      : Linux (x86_64)
  Gateway IP    : 192.168.10.1
  ...

  ┌─── [DLINK-001] CRITICAL: D-Link webproc Authentication Bypass
  │
  │  CVE/Reference : CVE-2025-34048 / CVE-2019-1010155
  │  Severity      : CRITICAL
  │  Target URL    : http://192.168.10.1/cgi-bin/webproc?...
  │
  │  DESCRIPTION:
  │    The D-Link router serves setup wizard pages to unauthenticated...
  │
  │  IMPACT:
  │    Full administrative access without authentication...
  │
  │  HOW TO FIX:
  │    1. Rotate Wi-Fi PSK and admin password immediately
  │    2. Reboot the router to clear the bypass session
  │    ...
  │
  │  REFERENCE URLS:
  │    → https://nvd.nist.gov/vuln/detail/CVE-2025-34048
  │
  └──────────────────────────────────────────────────────────────────────────
```

### JSON Report
```json
{
  "tool": "Bug Hunter",
  "version": "1.1.0",
  "timestamp": "2026-09-21T14:30:00+00:00",
  "network": { "gateway": "192.168.10.1", ... },
  "device": { "vendor": "dlink", "model": "DSL-2750U", ... },
  "findings": [
    {
      "id": "DLINK-001",
      "title": "D-Link webproc Authentication Bypass",
      "severity": "CRITICAL",
      "cve": "CVE-2025-34048",
      "description": "...",
      "impact": "...",
      "fix": "...",
      "urls": ["https://nvd.nist.gov/vuln/detail/CVE-2025-34048"]
    }
  ]
}
```

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | No vulnerabilities found |
| `1` | Minor findings (LOW/INFO) |
| `2` | High-severity findings |
| `3` | Critical-severity findings |
| `130` | Interrupted by user (Ctrl+C) |

## Safety Properties

This tool is designed to be **safe by construction**:

1. **GET/HEAD only** — No POST requests, no credential submission, no config changes
2. **LAN addresses only** — Refuses to probe public IPs; only scans your own network
3. **Never prints secrets** — Wi-Fi keys, passwords, and sensitive data are detected
   but never displayed, decoded, or saved in reports
4. **No exploitation** — Does not run exploit code, brute-force, or send payloads;
   the `dnscfg.cgi` CVE-2026-0625 probe is a bare reachability GET with no
   injection parameters
5. **Audit data stays local** — `audits/` is git-ignored; device reports are never
   committed to the repository
6. **No installation** — Single Python file, standard library only, no pip packages

## Requirements

- **Python 3.8+** (any platform)
- **Network access** to the target router (must be on the same LAN)
- **No external packages** — everything uses Python's standard library

## Installation

```bash
# No installation needed! Just download and run.
git clone <this-repo>
cd Router-Os/Bug-Hunter
python3 bug_hunter.py

# Or on Termux (Android):
pkg install python
python bug_hunter.py

# Or on Windows:
python bug_hunter.py
```

## Integration with Router-Os

This tool consolidates and extends the vulnerability checks from across the
Router-Os repository:

| Source project | Checks incorporated |
|---|---|
| `ptcl-dlink/tools/ptcl_check.py` | webproc auth bypass, Wi-Fi leak, file traversal |
| `ptcl-dlink/tools/micro_httpd_probe.py` | ACME httpd banner → CVE-2014-4927 flag (the live `--dos` probe stays in that tool, deliberately not in the scanner) |
| `ptcl-zte/tools/ptcl_zte_check.py` | UPnP WLAN disclosure, version matching |
| `ptcl-tplink/tools/ptcl_tplink_check.py` | rom-0 check, model/firmware matching |
| All research docs | CVE references, fix methods, source URLs |

Bug Hunter adds:
- **Physical-device audit mode** (`--audit`) — live hunting with saved audit
  artifacts and drift tracking per unit
- **Sticker identity cross-check** — label model/FW/HW/serial/MAC vs. the
  unit's self-report (incl. `J2`-style hardware revisions and `PT_*` ISP builds)
- `dnscfg.cgi` CVE-2026-0625 reachability probe (read-only)
- Automatic gateway detection
- Automatic vendor identification
- Generic port and service scanning
- Unified report format
- Cross-platform support (Termux, Windows, macOS, Linux)

## Disclaimer

This tool is for **authorized security auditing of your own network equipment only**.
Scanning networks or devices you do not own or have permission to test may violate
local laws. The authors are not responsible for misuse.

All vulnerability data is sourced from public CVE databases, vendor advisories,
and published security research. This tool does not contain or execute exploits.
