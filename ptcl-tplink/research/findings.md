# PTCL TP-Link findings

**Research snapshot:** 2026-09-21 (UTC)
**Scope:** TP-Link models evidenced in PTCL use or the PTCL shop; retail and other-ISP
firmware is kept separate from PTCL-specific claims.
**Bottom line:** there is no single "PTCL TP-Link vulnerability." Identify the label,
hardware revision, region, and complete firmware string first.

## Executive result

There are two particularly important branches:

1. **TL-WR840N — officially sold by PTCL as a standalone router.** TP-Link's 2026
   advisory says CVE-2023-50224 is **unpatched** on TL-WR840N v2/v3 and its 2026
   advisory fixes a different, authenticated root command-injection issue
   (CVE-2026-3227) on v6 at `V6_260304`. The PTCL shop listing does not publish the
   hardware revision or PTCL firmware, so exposure must be checked against the label and
   firmware, not inferred from the shop name.
2. **DSL/VDSL modem families — TD-W8951ND, TD-W8961N/ND, and TD-W9970.** Public evidence
   connects these models to PTCL users or resale, while the security advisories mostly
   describe retail, regional, or another ISP's images. They are useful conditional leads,
   not confirmed PTCL firmware exposures.

The safe checker is intentionally less ambitious than an exploit scanner. It fingerprints,
checks the harmless endpoint shape, and tells you which public version match still needs
manual confirmation. It does not try the dangerous request bodies used by the public PoCs.

## PTCL/model evidence

| model | evidence found | confidence and boundary |
|---|---|---|
| **TL-WR840N** | [PTCL shop product page](https://ptcl.com.pk/Shop/Product/TP-Link-WR840N-Single-Band) and [PTCL device catalogue](https://ptcl.com.pk/Shop/Category/Devices) list a TP-Link WR840N | **strong product association**, but standalone router; no PTCL-custom firmware or hardware revision is published |
| **TD-W8951ND** | TP-Link community user report says `Hardware V5`, firmware `5.0.0 Build 140306 Rel.28708`, `ISP: PTCL` | **strong use evidence**, not proof that every PTCL customer has V5 or that this build remains deployed |
| **TD-W8961N/ND** | [Pakistan marketplace listing](https://www.daraz.pk/products/wifi-ptcl-router-tp-link-td-w8961n-wireless-n-adsl2-modem-router-i254708488.html) labels TD-W8961N as a PTCL Wi-Fi router; TP-Link support pages document the family | **weak/resale PTCL evidence**, not proof of an operator image |
| **TD-W9970** | [TP-Link Pakistan product/support page](https://www.tp-link.com/pk/support/download/td-w9970/) and used-router listings describe it as a PTCL VDSL2 device | **conditional / weak PTCL firmware evidence**; treat the model as a lead until the unit's label and firmware are captured |
| **TL-WR720N(EU) V2** | repository's `wr720n/` project | **explicitly unrelated** to PTCL DSL CPE; do not merge it into this table |

## Findings by model and firmware

### A. TL-WR840N: PTCL shop product

#### CVE-2023-50224 — legacy httpd credential disclosure

TP-Link's [May 2026 security advisory](https://www.tp-link.com/us/support/faq/5058/)
explicitly lists **TL-WR840N v2/v3 as unpatched**. The advisory describes an
improper-authentication flaw in the HTTPD service that lets a network-adjacent attacker
retrieve sensitive information, potentially including stored credentials, and warns that
public reporting may include active exploitation and DNS manipulation.

The NVD record for [CVE-2023-50224](https://nvd.nist.gov/vuln/detail/CVE-2023-50224)
uses the ZDI name “TP-Link TL-WR841N dropbearpwd” and its CPE rows primarily identify
WR841N. TP-Link's own later model table is the reason this report includes WR840N v2/v3;
the NVD description alone must not be read as a WR840N CPE match. CISA's KEV entry in the
NVD record is also for the WR841N authentication-bypass name, not proof that a particular
PTCL WR840N has been exploited.

**Status for PTCL:** model association is confirmed through the PTCL shop, but the
revision and firmware are unknown. If the label says v2 or v3, TP-Link currently says
**unpatched / EOL**; replacement is the reliable remediation. Do not expose its admin
HTTP service to the WAN.

#### CVE-2026-3227 — authenticated configuration-import command injection

TP-Link's [official advisory](https://www.tp-link.com/us/support/faq/5018/) lists
**TL-WR840N v6** with firmware `< V6_260304`. An authenticated adjacent attacker can
upload a crafted configuration that reaches OS command execution with root privileges
during port-trigger processing. TP-Link gives CVSS v4.0 8.5 and recommends the fixed
firmware or current supported hardware.

**Status for PTCL:** the model is sold by PTCL, but no PTCL firmware string was found.
An exact `V6_260304` or later vendor build is a good fixed-version indicator; an
operator-customized version must be confirmed with PTCL. A v6 unit with an older
`V6_...` build is at risk. The checker never imports a config or sends the command
injection request.

#### Older retail WR840N reports — do not silently apply to PTCL

The following are useful when a unit's exact label matches, but public records describe
specific EU/ES/retail revisions:

| CVE | affected example | safe conclusion |
|---|---|---|
| [CVE-2019-15060](https://nvd.nist.gov/vuln/detail/CVE-2019-15060) | TL-WR840N v4 through firmware `0.9.1 3.16`, traceroute input | retail v4 only unless the PTCL unit has that exact build |
| [CVE-2020-36178](https://nvd.nist.gov/vuln/detail/CVE-2020-36178) | TL-WR840N v6 EU `0.9.1 4.16`, command injection in bridge-isolation input | EU v6 firmware evidence, not PTCL proof |
| [CVE-2021-41653](https://nvd.nist.gov/vuln/detail/CVE-2021-41653) | TL-WR840N EU v5 through `TL-WR840N(EU)_V5_171211`, ping input | exact EU v5 boundary only; do not run the RCE PoC |
| [CVE-2022-25060](https://nvd.nist.gov/vuln/detail/CVE-2022-25060), [CVE-2022-25061](https://nvd.nist.gov/vuln/detail/CVE-2022-25061), [CVE-2022-25064](https://nvd.nist.gov/vuln/detail/CVE-2022-25064) | `TL-WR840N(ES)_V6.20_180709` command/RCE paths | ES v6.20 build-specific; no PTCL mapping found |

There are additional WR840N CVE records and disputed/emulator-only reports. The model
and revision must be matched before assigning any of them to a PTCL device.

### B. TD-W8961N / TD-W8961ND: ADSL modem families

#### CVE-2025-15606 — TD-W8961N v4 HTTPD DoS

TP-Link's [official advisory](https://www.tp-link.com/us/support/faq/5028/) identifies
**TD-W8961N v4.0** firmware below `V4_250925`. A network-adjacent, unauthenticated
crafted request can crash the HTTPD service. TP-Link gives CVSS v4.0 7.1, says the
product is EOL, and recommends updating to `V4_250925` or replacing it. NVD records the
same boundary in [CVE-2025-15606](https://nvd.nist.gov/vuln/detail/CVE-2025-15606).

**Status for PTCL:** conditional. A TD-W8961N label is not enough; confirm v4 and the
firmware branch. The checker does not send the crash-triggering request.

#### CVE-2018-20372 — TD-W8961ND DHCP-hostname stored XSS

[NVD CVE-2018-20372](https://nvd.nist.gov/vuln/detail/CVE-2018-20372) and [Exploit-DB
40837](https://www.exploit-db.com/exploits/40837) describe persistent XSS through a DHCP
client hostname on TD-W8961ND firmware `1.0.1`. It requires an input to be written and a
user/admin to view the client list; it is not an unauthenticated admin takeover.

**Status for PTCL:** conditional and revision-specific. Never test by injecting a live
hostname. Use a lab image or the exact vendor fix information.

#### ZyNOS / RomPager `rom-0` configuration disclosure

Public research and RouterSploit list **TD-W8951ND and TD-W8961ND** among ZyNOS-family
routers that historically served `/rom-0` without authentication; the returned backup can
contain administrative or ISP credentials. This is a class of firmware behaviour rather
than a clean one-CVE match for every TP-Link revision. Do not assign ZTE's
CVE-2014-4019 to TP-Link: that CVE's NVD record is specifically for the ZTE ZXV10 W300.

For the related **Misfortune Cookie** RomPager cookie flaw, [CVE-2014-9222](https://nvd.nist.gov/vuln/detail/CVE-2014-9222)
and TP-Link's [community response](https://community.tp-link.com/en/home/forum/topic/78603)
are useful historical sources. TP-Link's official firmware notes provide concrete fix
evidence:

* [TD-W8951ND V5 firmware notes](https://www.tp-link.com/pk/support/download/td-w8951nd/v5/)
  say `TD-W8951ND_V5_160113` fixed XSS and the Misfortune Cookie security issue; and
* [TD-W8961ND V3 firmware notes](https://www.tp-link.com/us/support/download/td-w8961nd/v3/)
  and the public analysis identify `V3_150707` as the security-mechanism/fix boundary
  for that branch.

**Status for PTCL:** the model family is relevant, but an ISP-customized PTCL image is
not confirmed from those retail notes. The checker uses a `HEAD /rom-0` candidate check
and an opt-in, body-discarding GET; it does not decode a backup or run a RomPager cookie
bypass.

### C. TD-W9970 / TD-W9970v3: VDSL model, other-ISP advisory

#### CVE-2023-6437 — authenticated OS command injection

[NVD CVE-2023-6437](https://nvd.nist.gov/vuln/detail/CVE-2023-6437) lists **TD-W9970 and
TD-W9970v3** among TP-Link/ISP products affected through 2024-03-28. The Turkish
national advisory [TR-24-0244](https://siberguvenlik.gov.tr/guvenlik-bildirimleri/detay/tr-24-0244)
says the issue was fixed for those two models and describes authenticated OS command
injection. This is a serious finding, but it is not an unauthenticated PTCL-specific
finding.

**Status for PTCL:** conditional. The TD-W9970 model is plausible from PTCL resale
listings, but no PTCL software build was found. Capture the full firmware string and ask
PTCL which image/fix applies. Do not test by sending a command-injection payload.

## What can be checked safely

The checker in [`tools/ptcl_tplink_check.py`](../tools/ptcl_tplink_check.py) does not claim
to prove every CVE. It performs these low-impact checks:

1. `GET /` and response headers for model, hardware, firmware, and `Server: RomPager`
   clues. It does not log in.
2. `HEAD /rom-0` to see whether the endpoint looks like a binary configuration backup.
3. With `--probe-rom0`, `GET /rom-0` once, hold the bytes only in memory, and report
   status/content type/size. The body is never decoded, printed, stored, or placed in
   JSON. This can still expose secrets to the local checker process, so use it only on
   your own unit.
4. Firmware-string comparisons for the exact version boundaries that are safe to infer
   without a crash or write operation.

It deliberately does **not**:

* send a crafted `Cookie` header for Misfortune Cookie;
* write a DHCP hostname for XSS;
* send ping/traceroute/IPv6/bridge-isolation injection values;
* upload or import a configuration file;
* brute-force a CLI or admin account; or
* attempt a WAN-side test.

### Interpreting results

* **VULNERABLE** — an exact public affected firmware match or a confirmed binary-looking
  anonymous `/rom-0` response was observed.
* **NOT VULNERABLE** — the checked branch matched a listed fixed version and the safe
  endpoint check did not find an exposure. This is limited to the tested finding.
* **UNASSESSED** — model/firmware is missing, the suffix is not recognized, the public
  record is another region/ISP, or the endpoint was not conclusive.

A closed WAN management port is good hardening, but it does not clear a LAN-adjacent
issue. Conversely, a safe local result cannot prove what a public WAN vantage would see.

## Mitigation and recovery

1. Photograph or transcribe the label, then record **model, hardware version, region,
and complete firmware/build** from the status page.
2. Use only the TP-Link regional download page for that exact hardware and purchase/ISP
region. TP-Link warns that a wrong hardware image can damage the device. PTCL-custom
firmware may not be published; request the update from PTCL rather than substituting a
retail image.
3. For TL-WR840N v2/v3, follow TP-Link's CVE-2023-50224 guidance: replace with a
supported device. For TL-WR840N v6, update to at least `V6_260304` for CVE-2026-3227.
For TD-W8961N v4, update to `V4_250925` if the image is the correct branch, otherwise
replace because the product is EOL.
4. Disable remote/WAN management, UPnP, Telnet/FTP/SNMP if present, and unnecessary
services. Limit the management UI to a trusted LAN or a management VLAN.
5. If `/rom-0` exposed a backup or a device was suspected compromised, rotate the admin
password, PPPoE/ISP credentials, and Wi-Fi PSK from a trusted client. Review DNS,
port-forwarding, and firmware/configuration state; reboot after recovery.
6. Prefer bridge mode plus a supported router/firewall when the PTCL gateway cannot be
updated. Keep the modem isolated from untrusted client networks where possible.

## Sources

### PTCL/model association

* [PTCL TP-Link WR840N shop page](https://ptcl.com.pk/Shop/Product/TP-Link-WR840N-Single-Band) — official product association; standalone router.
* [PTCL device catalogue](https://ptcl.com.pk/Shop/Category/Devices) — lists TP-Link WR840N among devices.
* [TP-Link community report: TD-W8951ND on PTCL](https://community.tp-link.com/en/home/forum/topic/76551) — user-supplied model, firmware, and ISP fields.
* [PTCL TD-W8961N resale listing](https://www.daraz.pk/products/wifi-ptcl-router-tp-link-td-w8961n-wireless-n-adsl2-modem-router-i254708488.html) — weak marketplace evidence only.
* [PTCL TD-W9970 resale listing](https://www.daraz.pk/products/ptcl-wifi-router-vdsl2-used-product-tp-link-manufactured-td-w9970-100-genuiine-product-with-adapter-box-i347292012.html) — weak marketplace evidence only.
* [TP-Link Pakistan TD-W9970 support](https://www.tp-link.com/pk/support/download/td-w9970/) — regional model/hardware branches, not PTCL firmware proof.
* [TP-Link Pakistan TD-W8961N support](https://www.tp-link.com/pk/support/download/td-w8961n/) and [TD-W8951ND support](https://www.tp-link.com/pk/support/download/td-w8951nd/) — official hardware/firmware branch pages.

### Vendor advisories and records

* [TP-Link CVE-2023-50224 advisory](https://www.tp-link.com/us/support/faq/5058/) — WR840N v2/v3 unpatched, EOL, and mitigation guidance.
* [NVD CVE-2023-50224](https://nvd.nist.gov/vuln/detail/CVE-2023-50224) — ZDI/NVD description, scoring, and CISA reference.
* [TP-Link CVE-2026-3227 advisory](https://www.tp-link.com/us/support/faq/5018/) — WR840N v6 affected below `V6_260304`.
* [TP-Link CVE-2025-15606 advisory](https://www.tp-link.com/us/support/faq/5028/) — TD-W8961N v4 HTTPD DoS, fixed `V4_250925`, EOL.
* [NVD CVE-2025-15606](https://nvd.nist.gov/vuln/detail/CVE-2025-15606) — independent record.
* [NVD CVE-2023-6437](https://nvd.nist.gov/vuln/detail/CVE-2023-6437) and [Turkish TR-24-0244](https://siberguvenlik.gov.tr/guvenlik-bildirimleri/detay/tr-24-0244) — TD-W9970/TD-W9970v3 authenticated command injection and fix status.
* [TP-Link TD-W8951ND V5 firmware notes](https://www.tp-link.com/pk/support/download/td-w8951nd/v5/) — vendor says `V5_160113` fixed XSS and Misfortune Cookie.
* [TP-Link TD-W8961ND V3 firmware page](https://www.tp-link.com/us/support/download/td-w8961nd/v3/) — retail branch and firmware history.
* [NVD CVE-2018-20372](https://nvd.nist.gov/vuln/detail/CVE-2018-20372) and [Exploit-DB 40837](https://www.exploit-db.com/exploits/40837) — TD-W8961ND DHCP-hostname XSS.
* [NVD CVE-2014-9222](https://nvd.nist.gov/vuln/detail/CVE-2014-9222) and [TP-Link community response](https://community.tp-link.com/en/home/forum/topic/78603) — Misfortune Cookie context and TP-Link's historical response.
* [RouterSploit ROM-0 module](https://github.com/threat9/routersploit/blob/master/routersploit/modules/exploits/routers/multi/rom0.py) — public device list and read path; use as historical research, not as a PTCL firmware assertion.

## Explicit non-claims

* PTCL's retail/shop association does not establish an ISP-custom firmware version.
* TD-W9970's CVE-2023-6437 report is an other-ISP/conditional lead until a PTCL build is
  identified.
* Retail EU/ES/UN firmware findings are not automatically findings on a PTCL image.
* `wr720n/` remains a separate TP-Link TL-WR720N(EU) V2 firmware project and is not
  included in this PTCL inventory.
