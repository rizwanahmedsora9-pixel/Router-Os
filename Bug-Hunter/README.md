# Bug Hunter — Cross-Platform Router Vulnerability Scanner

A Python tool that hunts the **physical router on your LAN** and runs a **live
security audit** of it: WiFi-aware auto-discovery, vendor fingerprinting,
port/service probing, CVE-matched vulnerability checks, **credentialed deep
audit** (HTTP login + read-only shell + MTD firmware dump with *your own*
admin password), and **offline firmware analysis** — against the unit in front
of you, not a simulation.

Generates a detailed report with vulnerability details, CVE references, severity ratings,
and step-by-step fix/remediation methods.

> **Real hunt vs. play.**
> `bug_hunter.py` is the real thing: every probe goes to the physical device.
> `demo_scan.py` / `test_scanner.py` are the playground — mock routers on
> localhost for learning and testing only. Nothing in them touches hardware.
>
> **v2.0 — the "real auditing app" release.** v1 only probed from the outside
> (and only really knew D-Link/ZTE/TP-Link). v2 adds: `--auto` WiFi/subnet
> discovery across **18 vendors**, credentialed HTTP audit
> (`--username/--password`), read-only **root-shell audit** (`--shell`),
> low-level **MTD firmware dump** (`--dump-mtd`), config-backup pull
> (`--dump-config`), offline **firmware analysis** (`--analyze-firmware`),
> SNMP/DNS low-level probes (`--probe-udp`), and CONFIRMED/LIKELY confidence
> labels so live proof is never confused with version-string guessing.

## Physical Device Audit (v1.2 — the primary use)

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
| **WiFi-aware auto-discovery** | `--auto` / `--discover`: SSID context, subnet sweep (TCP+ARP), router-candidate ranking, auto-fallback when the gateway guess is wrong |
| **Vendor fingerprinting** | 18 vendors: D-Link, ZTE, TP-Link, Huawei, Netgear, Linksys, FiberHome, Asus, Tenda, Totolink, Cisco, MikroTik, Ubiquiti, DrayTek, Belkin, TRENDnet, Xiaomi, Mercusys, OpenWrt |
| **Port scanning** | Checks common router services (HTTP, HTTPS, SSH, Telnet, FTP, SNMP, UPnP, TR-069, TCP 5555, Winbox 8291, PPTP, alt-HTTP) |
| **Credentialed HTTP audit** | `-u/--password`: Basic/Digest/form login with YOUR creds, then real firmware/WAN/DNS/WPS/remote-mgmt state |
| **Credentialed shell audit** | `--shell telnet\|ssh`: read-only enumeration (uid, kernel, SoC, MTD layout) over your own login |
| **MTD firmware dump** | `--dump-mtd all`: low-level partition dump over the shell, decoded + SHA-256'd locally |
| **Firmware analysis** | `--analyze-firmware FILE`: magic scan, entropy profile, redacted secret scan — offline |
| **Confidence labels** | Every v2 finding says CONFIRMED (live proof) or LIKELY (banner/version match) |
| **D-Link checks** | webproc auth bypass, Wi-Fi key leak, file traversal, persistent session, ACME httpd banner (CVE-2014-4927), `dnscfg.cgi` exposure (CVE-2026-0625) |
| **ZTE checks** | UPnP WLAN key disclosure (CVE-2018-7357/7358), CSRF, info leaks |
| **TP-Link checks** | rom-0 config disclosure, command injection, credential disclosure, RomPager |
| **Generic checks** | Telnet, FTP, SNMP, UPnP, TR-069, Boa banner, TCP 5555 (ADB only if the banner says so), missing HTTPS, Basic-on-HTTP |
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
| **Termux (Android)** | ✅ | `platform.system()` is often `Android`; treated as Termux and uses `ip route` |
| **FreeBSD** | ✅ | Uses `route` |
| **Raspberry Pi** | ✅ | Same as Linux |

## Quick Start

```bash
# SMOOTH AUTO FLOW — WiFi context + subnet sweep + audit the best candidate
python bug_hunter.py --auto
python bug_hunter.py --auto --audit --model DSL-226 --firmware PT_1.10_J2 --hw J2

# DISCOVER every router/ONT on the LAN, audit each (up to --max-targets)
python bug_hunter.py --discover
python bug_hunter.py --discover --audit --max-targets 6

# PHYSICAL HUNT — audit the live router on your LAN
python bug_hunter.py                          # auto-detect your gateway and hunt it
python bug_hunter.py 192.168.10.1 --audit     # hunt + save audit + drift diff

# Hunt with the sticker identity (anchors the audit to the physical unit)
python bug_hunter.py 192.168.10.1 --audit \
    --model DSL-226 --firmware PT_1.10_J2 --hw J2

# CREDENTIALED DEEP AUDIT — your own router, your own password (prompted, hidden)
python bug_hunter.py 192.168.1.1 -u admin --audit
python bug_hunter.py 192.168.1.1 -u admin --shell auto --dump-config --audit
python bug_hunter.py 192.168.1.1 --check-defaults          # well-known defaults only

# LOW-LEVEL MTD DUMP over the credentialed shell (asks to confirm w/o --yes)
python bug_hunter.py 192.168.1.1 -u admin --shell telnet --dump-mtd all --yes

# OFFLINE FIRMWARE ANALYSIS (local file, nothing uploaded)
python bug_hunter.py --analyze-firmware audits/mtd_192.168.1.1_mtd5_*.bin

# Save a text report / JSON report anywhere you like
python bug_hunter.py 192.168.1.1 --report scan_report.txt --json scan_report.json

# Quick scan (fewer ports, faster)
python bug_hunter.py --quick

# Enable optional deep probes
python bug_hunter.py --probe-upnp --probe-rom0 --probe-udp

# Force vendor detection
python bug_hunter.py --vendor mikrotik

# Verbose output (shows every HTTP request)
python bug_hunter.py -v
```

## Auto-Discovery (`--auto` / `--discover`)

v1 guessed one gateway IP and stopped. v2 reads the WiFi context (SSID/BSSID/
signal on Windows, Linux, macOS and Termux), derives the subnet, sweeps it
(TCP ping + ARP-table merge — no root, no raw sockets), fingerprints every
web host and ranks router candidates by banner/title/OUI/TR-069 signals. If
the gateway has no web port at all, the audit automatically falls over to the
best candidate instead of failing. `--discover` audits every candidate (up to
`--max-targets`, default 4) and prints a combined summary.

## Credentialed HTTP Audit (`-u` / `-p` / `--check-defaults`)

Version-string guessing ends where your admin password begins. With the
owner's credentials (prompted via `getpass`, never echoed, never stored, never
sent off-LAN) Bug Hunter tries HTTP Basic → Digest → common form logins, then
reads the unit's *real* post-login state: firmware/model, WAN IP, DNS servers,
uptime, WPS state, remote-management state, weak WiFi encryption — each
reported with a CONFIRMED/LIKELY confidence label. `--check-defaults` tries
only the short well-known-default list, one attempt per second, and stops at
the first hit (reported as AUTH-001 CRITICAL). There is no brute-forcing,
no session hijacking, no unauthenticated escalation — root is only ever
reached with credentials you supplied.

## Shell Audit + MTD Dump (`--shell` / `--dump-mtd` / `--dump-config`)

`--shell telnet` (raw-socket client, works on Termux) or `--shell ssh`
(system `ssh` binary) opens a shell with your credentials and runs a fixed
**read-only** command list: `id`, `/proc/version`, `/proc/cpuinfo`,
`/proc/mtd`, mounts, `ps`, and friends — no writes, no reboot, no kill. The
transcript is secret-redacted before display or save. `--dump-mtd all` (or
`mtd5`, `mtd0,mtd5`) then reads each MTD partition over the same shell
(base64, hexdump fallback), decodes and SHA-256-hashes it locally into
`audits/` (mode 0600). `--dump-config` pulls the config backup over the
authenticated HTTP session instead. Point `--analyze-firmware` at any of
these files for the offline workup.

## Firmware Analysis (`--analyze-firmware`)

A binwalk-lite with zero dependencies: container/filesystem magic scan
(uImage, TRX, SquashFS, JFFS2, LZMA, gzip, ELF, UBI, TP-Link IMG0 incl. the
WR720N web-store magic, SEAMA, CFE, …), a sliding-window entropy profile that
flags encrypted/compressed spans, printable-string extraction, and an
indicator scan for hardcoded passwords, default pairs, telnet backdoors,
private keys and hardcoded URLs/IPs. Secret *values* are never printed —
only type, offset and a redacted preview, plus the exact `dd|xxd` command to
inspect your own dump.

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
> `/cgi-bin/webproc` with a neutral page. A 401/404 body that only echoes that
> probe URL is **not** webproc evidence, and a `Boa/` banner is **not** ACME.
> Boa + no model is reported as an unidentified Boa CPE. A `WWW-Authenticate`
> realm (and a sticker `--model DSL-…`) can still name the unit. If the vendor
> checks run and only see 401/403/404, the report says the bypass was **not
> demonstrated** — that is inconclusive, not clean.

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
| ADB banner on TCP 5555 | **HIGH** | Confirmed only if a passive read shows ADB. No handshake is sent |
| TCP 5555, no ADB banner | **MEDIUM** | Open listener, not a shell |
| Boa/0.94.13–0.94.14 banner | **HIGH** | Abandoned httpd; CVE-2022-45956 named, not probed |
| HTTP Basic on cleartext | **MEDIUM** | Admin password is only Base64 on the LAN |
| No login prompt | **HIGH** | Possible unauthenticated admin access |
| MikroTik Winbox/API exposed | **HIGH** | Ports 8291/8728; CVE-2018-14847 class named, not probed |
| SNMP `public` answers | **MEDIUM** | `--probe-udp`: read-only sysDescr GET answered (sysDescr shown) |
| DNS version.bind leak | **INFO** | `--probe-udp`: CHAOS/TXT version string disclosed |
| Embedded httpd banner | **INFO** | GoAhead/uhttpd/lighttpd/Allegro version note for CVE matching |

### Credentialed (owner password required — v2)

| Check | Severity | What it finds |
|---|---|---|
| Default HTTP creds (AUTH-001) | **CRITICAL** | `--check-defaults`: a factory login works (password never shown) |
| Backup downloadable post-login (AUTH-002) | **INFO** | Authenticated config endpoint confirmed, ready for `--dump-config` |
| Remote management enabled (AUTH-003) | **HIGH** | Settings page says WAN-side admin is on |
| WPS enabled (AUTH-004) | **MEDIUM** | WPS state read from the real settings page |
| Weak WiFi encryption (AUTH-005) | **HIGH/MEDIUM** | WEP or WPA-TKIP-only as the active mode |
| Config backup saved (AUTH-006) | **INFO** | Local 0600 audit artifact written |
| Credentialed root shell (SHELL-001) | **INFO / HIGH** | `uid=0` over your login (HIGH only if it took defaults) |
| MTD dump saved (SHELL-002) | **INFO** | Partition bytes + SHA-256 on local disk |
| Ancient live kernel (SHELL-003) | **HIGH/MEDIUM** | `/proc/version` predates 3.10 / 4.4 |
| telnetd running (SHELL-004) | **MEDIUM** | Plaintext shell confirmed in `ps` |

## Report Format

### Text Report (`.txt`)
```
==============================================================================
  BUG HUNTER — ROUTER VULNERABILITY SCAN REPORT
  Version 1.2.0
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
  "version": "2.0.0",
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
| `0` | No findings from the checks that ran (not a guarantee) |
| `1` | Minor findings (LOW/INFO) |
| `2` | High-severity findings |
| `3` | Critical-severity findings |
| `130` | Interrupted by user (Ctrl+C) |

## Safety Properties

This tool is designed to be **safe by construction**:

1. **Unauthenticated phases are read-only** — GET/HEAD only, plus one SNMP GET
   and one DNS TXT with the explicit `--probe-udp`. No config changes, ever
2. **Credentialed phases only READ, with YOUR password** — `-u/--password`,
   `--check-defaults` (short well-known list, 1 attempt/sec), `--shell`
   (fixed read-only command list), `--dump-config`/`--dump-mtd` (local 0600
   files). No brute-forcing beyond the default list, no cracking, no
   hijacking, no unauthenticated escalation
3. **LAN addresses only** — Refuses to probe public IPs; only scans your own network
4. **Never prints secrets** — Wi-Fi keys, passwords, shell transcripts and
   firmware-indicator values are detected but redacted (`[REDACTED]`) in all
   output; dumps live as local 0600 files, never inside reports
5. **No exploitation** — Does not run exploit code or send payloads;
   the `dnscfg.cgi` CVE-2026-0625 probe is a bare reachability GET with no
   injection parameters. A Boa banner is recorded only — no HEAD auth-bypass
   and no path traversal. TCP 5555 is read passively; no ADB handshake is sent.
   Winbox/CVE-2018-14847 is exposure-flagged, never probed with the traversal
6. **Audit data stays local** — `audits/` is git-ignored; device reports, shell
   transcripts and MTD dumps are never committed to the repository
7. **No installation** — Python standard library only, no pip packages

## Requirements

- **Python 3.8+** (any platform)
- **Network access** to the target router (must be on the same LAN)
- **No external packages** — everything uses Python's standard library
- **Optional:** system `ssh` binary for `--shell ssh` (Termux: `pkg install
  openssh`; Windows: OpenSSH Client); `sshpass` only if you insist on
  password-over-SSH instead of key auth

## File layout (v2)

| File | Role |
|---|---|
| `bug_hunter.py` | Main app: scan engine, reports, CLI (still runs standalone) |
| `discovery.py` | WiFi context, subnet sweep, router-candidate ranking |
| `auth_audit.py` | Basic/Digest/form login, post-login enum, config-backup pull |
| `shell_audit.py` | Telnet/SSH read-only shell audit, MTD dump, redaction |
| `firmware.py` | Offline firmware/MTD analysis (magic, entropy, indicators) |
| `test_scanner.py` | Test suite — 14 groups incl. live localhost mocks for v2 |
| `demo_scan.py` | Mock router demo (play only — no hardware involved) |

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
- **WiFi-aware LAN discovery** (`--auto`/`--discover`) with router ranking
- **Credentialed HTTP + shell audit** with the owner's password, read-only
- **MTD firmware dump** and **offline firmware analysis**
- Automatic gateway detection with smart fallback
- 18-vendor identification + confidence-labelled findings
- Generic port and service scanning (incl. Winbox, SNMP/DNS UDP probes)
- Unified report format
- Cross-platform support (Termux, Windows, macOS, Linux)

## Disclaimer

This tool is for **authorized security auditing of your own network equipment only**.
Scanning networks or devices you do not own or have permission to test may violate
local laws. The authors are not responsible for misuse.

All vulnerability data is sourced from public CVE databases, vendor advisories,
and published security research. This tool does not contain or execute exploits.
