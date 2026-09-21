# Router-Os

A workbench for router firmware and model-scoped security research: **stock (official)
images, unpacked trees, custom-build experiments, and read-only PTCL CPE checks.**

```
Router-Os/
├── wr720n/                        ← TP-Link TL-WR720N (EU) V2
│   ├── official-os/               stock vendor firmware, exactly as shipped
│   ├── unpacked-os/               the same firmware taken apart (images + web root)
│   ├── custom-os/                 our own builds / experiments: v1, v2, v3 …
│   └── tools/                     the unpacker / inspector / repacker used for all of it
│
├── ptcl-dlink/                    ← D-Link DSL-series as shipped by PTCL
│   ├── notes/                     the webproc authentication-bypass writeup
│   ├── tools/                     read-only LAN detector + offline self-test mock
│   └── research/                  sourced findings and links
│
├── ptcl-zte/                      ← PTCL-associated ZTE DSL/VDSL research
│   ├── tools/                     LAN-only H168N checker + UPnP mock
│   └── research/                  CVE/version evidence, limits, and mitigations
│
├── ptcl-tplink/                   ← PTCL-associated TP-Link research
│   ├── tools/                     LAN-only inventory/rom-0 checker + mock
│   └── research/                  model-scoped CVE evidence and source links
│
└── Bug-Hunter/                    ← 🎯 Unified cross-platform vulnerability scanner
    ├── bug_hunter.py              main app: auto-detect → scan → report
    ├── test_scanner.py            unit tests + integration checks
    └── demo_scan.py               mock router demo with sample findings
```

> **Separate projects, one repository.** `wr720n/` is TP-Link (VxWorks, `IMG0`
> container, Wind River web store). `ptcl-dlink/` is D-Link ADSL (`webproc` CGI).
> `ptcl-zte/` focuses on the ZTE ZXHN H168N UPnP service. `ptcl-tplink/` covers several
> different TP-Link DSL and standalone-router families. Different vendor, firmware,
> hardware, and web stack means a finding or URL in one project must not be copied into
> another.

## Start here

| I want to… | go to |
|---|---|
| **🎯 scan my router for vulnerabilities (NEW)** | [`Bug-Hunter/`](Bug-Hunter/) |
| **all the PTCL D-Link bypass URLs, and how to verify a fix** | [`bug to fix.md`](bug%20to%20fix.md) |
| understand the PTCL-associated ZTE H168N findings | [`ptcl-zte/research/`](ptcl-zte/research/) |
| safely check my own ZTE H168N from the LAN | [`ptcl-zte/tools/`](ptcl-zte/tools/) |
| understand which TP-Link models may be PTCL-associated | [`ptcl-tplink/research/`](ptcl-tplink/research/) |
| safely fingerprint my own TP-Link and check `/rom-0` | [`ptcl-tplink/tools/`](ptcl-tplink/tools/) |
| see the original unrelated TL-WR720N download | [`wr720n/official-os/`](wr720n/official-os/) |
| look at the WR720N firmware's insides | [`wr720n/unpacked-os/`](wr720n/unpacked-os/) |
| build / test my own WR720N firmware experiments | [`wr720n/custom-os/`](wr720n/custom-os/) |
| unpack another TL-WR720N image | [`wr720n/tools/`](wr720n/tools/) |
| **understand the PTCL D-Link "opens without login" bug** | [`ptcl-dlink/`](ptcl-dlink/) |
| **check whether my own PTCL D-Link has it** | [`ptcl-dlink/tools/`](ptcl-dlink/tools/) |

## Bug Hunter — Unified Vulnerability Scanner

The [`Bug-Hunter/`](Bug-Hunter/) tool consolidates all research from this repository into a
single cross-platform Python application that runs on **Windows, Linux, macOS, Termux (Android),
FreeBSD — anywhere Python 3.8+ exists**.

```bash
# Auto-detect your router and scan for vulnerabilities
python Bug-Hunter/bug_hunter.py

# Scan a specific IP and save a detailed report
python Bug-Hunter/bug_hunter.py 192.168.10.1 --report scan_report.txt

# Demo mode — see it in action against a simulated vulnerable router
python Bug-Hunter/demo_scan.py
```

**What it does:**
- Auto-detects your gateway/router on WiFi or LAN
- Fingerprints the vendor (D-Link, ZTE, TP-Link, Huawei, Netgear, etc.)
- Scans for open ports and services
- Checks vendor-specific vulnerabilities (CVE-matched)
- Runs generic security checks (Telnet, UPnP, SNMP, etc.)
- Generates a detailed `.txt` or `.json` report with:
  - Vulnerability descriptions and severity ratings
  - CVE references and source URLs
  - Impact analysis
  - Step-by-step fix/remediation methods

**Safety:** Read-only (GET/HEAD only), LAN addresses only, never prints secrets, no exploits.

See [`Bug-Hunter/README.md`](Bug-Hunter/README.md) for full documentation.

## Research status

### PTCL D-Link

A D-Link DSL-series router that PTCL ships runs a web UI where the setup-wizard pages are
served without authentication, and the session that request mints is never invalidated.
The existing [`ptcl-dlink/`](ptcl-dlink/) notes document CVE-2019-1010155 /
CVE-2019-1010156 (disputed by D-Link as low-impact) and CVE-2025-34048 (**CVSS 8.7**, an
unauthenticated `getpage` file read), along with the gap between retail and PTCL firmware.
Its GET-only, LAN-only checker can be validated against an included mock before it is
pointed at a real unit.

### PTCL ZTE

The strongest public match is **ZTE ZXHN H168N v2.2** with PK firmware strings. ZTE's
CVE-2018-7357/CVE-2018-7358 advisory lists affected `V2.2.0_PK...` builds and the public
report documents unauthenticated UPnP WLAN-key disclosure/change on TCP `52869`. Later
H168N v3.5 advisories are recorded as conditional because their `EG`/`TY` firmware suffixes
are not proof of a PTCL image. See [`ptcl-zte/README.md`](ptcl-zte/README.md).

### PTCL TP-Link

The TP-Link work is intentionally split by model. PTCL's shop lists the standalone
**TL-WR840N**; public user/resale evidence points to **TD-W8951ND**, **TD-W8961N/ND**, and
**TD-W9970** in PTCL use. Current findings include the official TL-WR840N v2/v3
CVE-2023-50224 unpatched status, TL-WR840N v6 CVE-2026-3227, TD-W8961N v4
CVE-2025-15606, historical RomPager/`rom-0` and DHCP-hostname issues, and the conditional
TD-W9970 CVE-2023-6437 other-ISP lead. Retail/other-ISP firmware is not silently treated
as PTCL-custom firmware. See [`ptcl-tplink/README.md`](ptcl-tplink/README.md).

## Firmware workbench status

* **Official:** `TL-WR720N(EU)_V2_160426.zip` → `wr720nv2-eu-up.bin` (1,560,324 bytes,
  build `160426`, i.e. 2016-04-26). MD5 `c79f88e79f2735995cd91cb2a5bd0a09`.
* **Unpacked:** two decompressed VxWorks 5.5.1 MIPS images (636 KB + 3.5 MB) and the
  complete web interface — **194 files** (174 `.htm`, 6 `.js`, 2 `.css`, 6 `.jpg`, 6
  `.gif`) — plus machine-readable `MANIFEST.csv/json` and byte-map documentation.
* **Custom:** empty experiment slots `v1`, `v2`, `v3` with a documented workflow and a
  working repack tool (still experimental — see the warnings).

The WR720N firmware, extraction, and notes remain documented in
[`wr720n/unpacked-os/v2.0-160426/README.md`](wr720n/unpacked-os/v2.0-160426/README.md).
