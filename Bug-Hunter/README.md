# Bug Hunter — Cross-Platform Router Vulnerability Scanner

A **read-only** Python tool that detects your connected router/gateway on WiFi or LAN
and scans it for known vulnerabilities, security misconfigurations, and exposures.

**`bug_hunter.py` is always a LIVE physical-device audit** — it probes the real router
on your LAN, never a simulation. (The simulated demo is the separate `demo_scan.py`.)

Generates a detailed report with vulnerability details, CVE references, severity ratings,
and step-by-step fix/remediation methods.

## Quick start — audit your physical device

```bash
# Generic live audit: auto-detect the gateway and scan it
python3 bug_hunter.py

# Pin a specific unit by its label data and verify identity before scanning
python3 bug_hunter.py --profile dsl226

# Pinned to an explicit IP, with reports saved
python3 bug_hunter.py 192.168.1.1 --profile dsl226 \
    --report dsl226_audit.txt --json dsl226_audit.json
```

### Device profiles (`--profile`)

A profile records the **label data of a specific physical unit** so the audit can
prove it scanned the right device:

| Profile | Device | Verifies |
|---|---|---|
| `dsl226` | D-Link DSL-226 (PTCL), fw `PT_1.10_J2`, H/W `J2` | model, firmware, H/W rev, MAC (`88:76:B9:17:34:61`, via OS neighbor table), serial noted |

Identity verdicts: `VERIFIED` · `MISMATCH` (findings may belong to another unit) ·
`INCONCLUSIVE` (device didn't expose enough — e.g. MAC unavailable). The serial
number is never exposed over HTTP, so it is recorded as `NOT_OBSERVED`, not silently
passed.

Profiles also steer discovery: with `--profile dsl226` and no target given, the tool
probes the DSL-226's documented management IPs (`192.168.1.1`, `192.168.10.1`) first.

## Features

| Feature | Description |
|---|---|
| **Live physical audit** | Every `bug_hunter.py` run probes a real device — no simulation fallback |
| **Device identity** | `--profile` verifies model/firmware/H/W/MAC against the unit's label |
| **Auto-detect gateway** | Finds your router automatically — works on Windows, Linux, macOS, Termux |
| **Vendor fingerprinting** | Identifies D-Link, ZTE, TP-Link, Huawei, Netgear, Linksys, FiberHome |
| **Port scanning** | Checks common router services (HTTP, SSH, Telnet, FTP, SNMP, UPnP, TR-069, ADB) |
| **D-Link checks** | webproc auth bypass, Wi-Fi key leak, file traversal, persistent session, ACME httpd banner (CVE-2014-4927), dnscfg.cgi exposure precondition (CVE-2026-0625, GET-only) |
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
# Live audit: auto-detect your router and run a full scan
python bug_hunter.py

# Live audit of a specific physical unit (identity-verified against its label)
python bug_hunter.py --profile dsl226

# Scan a specific IP
python bug_hunter.py 192.168.1.1

# Scan a specific IP with device identity verification
python bug_hunter.py 192.168.1.1 --profile dsl226

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

> **Demo vs live:** `demo_scan.py` is a localhost simulation for previewing the
> report format. `bug_hunter.py` (this tool) always audits a physical device.

## What Gets Checked

### D-Link (PTCL DSL-series)

| Check | CVE | Severity | What it finds |
|---|---|---|---|
| webproc Auth Bypass | CVE-2025-34048, CVE-2019-1010155 | **CRITICAL** | Wizard pages served without login |
| Wi-Fi Key Leak | CVE-2019-1010156 | **CRITICAL** | SSID + WPA key in page source |
| File Traversal | CVE-2025-34048 | **CRITICAL** | Read any file on the router |
| Persistent Session | CVE-2019-1010155 | **HIGH** | Bypass session never expires |
| ACME httpd front door | CVE-2014-4927 | **HIGH** | `micro_httpd` banner → long-URI DoS, never patched (flagged, not probed) |
| dnscfg.cgi exposure | CVE-2026-0625 | **CRITICAL** | DNS config CGI served without login — the missing-auth precondition of the actively exploited command injection (GET-only; injection never sent) |

> **Detection note:** the ACME banner on real units uses the underscore spelling
> (`micro_httpd`), and these units often answer `/` with a bare `401` and no
> vendor strings. Bug Hunter matches the banner (both spellings) and probes
> `/cgi-bin/webproc` with a neutral page, so the PTCL DSL class is detected
> from the field-scan shape, not only from a full login page.

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
  BUG HUNTER — PHYSICAL DEVICE SECURITY AUDIT REPORT
  Version 1.1.0
==============================================================================

  Scan Date     : 2026-09-22 14:30:00 UTC
  Mode          : LIVE physical-device audit (read-only)
  Platform      : Linux (x86_64)
  Gateway IP    : 192.168.10.1
  ...

  ┌─── [DEVICE IDENTITY VERIFICATION]
  │  Profile  : D-Link DSL-226 (PTCL)
  │  Verdict  : VERIFIED
  │  Model    : expected DSL-226   | observed DSL-226          | MATCH
  │  Firmware : expected PT_1.10_J2 | observed PT_1.10_J2       | MATCH
  │  ...
  └──────────────────────────────────────────────────────────────────────────

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
  "mode": "physical-audit",
  "timestamp": "2026-09-22T14:30:00+00:00",
  "network": { "gateway": "192.168.10.1", ... },
  "identity": { "profile": "D-Link DSL-226 (PTCL)", "verdict": "VERIFIED", ... },
  "device": { "vendor": "dlink", "model": "DSL-226", ... },
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
| `ptcl-dlink/tools/micro_httpd_probe.py` | ACME httpd banner → CVE-2014-4927 flag (the live `--dos` probe stays in that tool, deliberately not in the scanner) |
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
