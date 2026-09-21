# Bug Hunter — Cross-Platform Router Vulnerability Scanner

A **read-only** Python tool that detects your connected router/gateway on WiFi or LAN
and scans it for known vulnerabilities, security misconfigurations, and exposures.

Generates a detailed report with vulnerability details, CVE references, severity ratings,
and step-by-step fix/remediation methods.

## Features

| Feature | Description |
|---|---|
| **Auto-detect gateway** | Finds your router automatically — works on Windows, Linux, macOS, Termux |
| **Vendor fingerprinting** | Identifies D-Link, ZTE, TP-Link, Huawei, Netgear, Linksys, FiberHome |
| **Port scanning** | Checks common router services (HTTP, SSH, Telnet, FTP, SNMP, UPnP, TR-069, ADB) |
| **D-Link checks** | webproc auth bypass, Wi-Fi key leak, file traversal, persistent session |
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
# Auto-detect your router and run a full scan
python bug_hunter.py

# Scan a specific IP
python bug_hunter.py 192.168.1.1

# Save a text report
python bug_hunter.py --report scan_report.txt

# Save a JSON report
python bug_hunter.py --json scan_report.json

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

### D-Link (PTCL DSL-series)

| Check | CVE | Severity | What it finds |
|---|---|---|---|
| webproc Auth Bypass | CVE-2025-34048, CVE-2019-1010155 | **CRITICAL** | Wizard pages served without login |
| Wi-Fi Key Leak | CVE-2019-1010156 | **CRITICAL** | SSID + WPA key in page source |
| File Traversal | CVE-2025-34048 | **CRITICAL** | Read any file on the router |
| Persistent Session | CVE-2019-1010155 | **HIGH** | Bypass session never expires |
| micro-httpd | N/A | **MEDIUM** | Legacy insecure web server |

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
  Version 1.0.0
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
  "version": "1.0.0",
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
4. **No exploitation** — Does not run exploit code, brute-force, or send payloads
5. **No installation** — Single Python file, standard library only, no pip packages

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
| `ptcl-zte/tools/ptcl_zte_check.py` | UPnP WLAN disclosure, version matching |
| `ptcl-tplink/tools/ptcl_tplink_check.py` | rom-0 check, model/firmware matching |
| All research docs | CVE references, fix methods, source URLs |

Bug Hunter adds:
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
