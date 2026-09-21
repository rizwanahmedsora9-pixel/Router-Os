# PTCL ZTE findings

**Research snapshot:** 2026-09-21 (UTC)
**Scope:** ZTE DSL/VDSL gateways publicly associated with PTCL, with the ZXHN H168N as
the primary lead.
**Confidence rule:** a CVE is not labelled PTCL-confirmed unless the public source
matches the PTCL-associated model and firmware family. A retail or another ISP build is
useful for a conditional check, but is not silently promoted to PTCL evidence.

## Executive result

The highest-confidence PTCL lead is **ZXHN H168N v2.2**, firmware
`V2.2.0_PK1.2T5` (and sibling `PK1.2T2`, `PK11T7`, `PK11T4`). ZTE's own advisory lists
those exact versions for:

* **CVE-2018-7357** — improper access control / unauthorized access; and
* **CVE-2018-7358** — improper change control / unauthorized operations.

The public proof of concept shows that an unauthenticated client can call the UPnP
WLAN service on TCP `52869` and read the wireless key. It also documents a separate
unauthenticated passphrase-change operation, but this repository's checker deliberately
never sends that operation. ZTE lists `V2.2.0_PK1.2T6` as the fixed version. A unit that
still reports one of the four affected strings should be treated as exposed even if its
WAN firewall prevents internet access: a malicious or compromised LAN client is enough.

The model was reported as a PTCL modem in a Pakistani community thread, and the `PK`
firmware family plus the public report are consistent with that association. This is
strong model/firmware evidence, not an assertion that every H168N sold in Pakistan or
every current PTCL CPE still runs `PK1.2T5`.

## Device and firmware evidence

| status | model / evidence | what it proves | what it does not prove |
|---|---|---|---|
| **strongest PTCL match** | `ZXHN H168N V2.2`; public exploit: build `20171127193202`, software `V2.2.0_PK1.2T5` | a real H168N build and the vulnerable UPnP path are documented | the current build on a particular subscriber's modem |
| **ZTE-confirmed affected siblings** | `V2.2.0_PK1.2T2`, `V2.2.0_PK11T7`, `V2.2.0_PK11T4` (the CVE/NVD prose shortens the last branch to `PK11T`) | ZTE's advisory includes these exact versions | that PTCL still distributes them today |
| **vendor fixed target** | `V2.2.0_PK1.2T6` | ZTE's listed resolution for the 2018 H168N issue | that all later PTCL images inherit every later ZTE fix |
| **weak/current-market evidence** | H168N V3.5 labelled as a PTCL modem in a marketplace listing | H168N V3.5 is seen in Pakistan's resale market | authenticity, operator firmware, or security status |

The model/firmware string is more useful than a casing photograph. Record the complete
software version, including the suffix after the underscore, before classifying a unit.

## Vulnerability table

### 1. H168N v2.2 UPnP WLAN disclosure and mutation — PTCL-linked

| item | detail |
|---|---|
| CVEs | [CVE-2018-7357](https://nvd.nist.gov/vuln/detail/CVE-2018-7357) and [CVE-2018-7358](https://nvd.nist.gov/vuln/detail/CVE-2018-7358) |
| affected versions | `V2.2.0_PK1.2T5`, `V2.2.0_PK1.2T2`, `V2.2.0_PK11T7`, `V2.2.0_PK11T4` |
| fixed version named by ZTE | `V2.2.0_PK1.2T6` |
| attack surface | unauthenticated UPnP/HTTP service on TCP `52869`; action path `/control/igd/wlanc_1_1` |
| read impact | `GetSecurityKeys` returns WLAN security material, including the pre-shared key on the reported build |
| write impact | the public report also documents `SetSecurityKeys`; it can change the passphrase, but it is intentionally not used by this project |
| score note | ZTE's CNA advisory gives 6.5 for each; NVD later shows 8.8. The difference is scoring, not two different bugs |
| status | **confirmed for the exact listed firmware family; current PTCL exposure must be measured** |

The [Exploit-DB report 45972](https://www.exploit-db.com/exploits/45972) gives the exact
request shape and says the operator pushed a patch in November 2018. It is useful for
reproducing the finding in an authorized lab, but do not use its passphrase-change
request against a live modem.

### 2. H168N v3.5 information leak — exact non-PK variant only

ZTE's [CVE-2021-21735 advisory](https://support.zte.com.cn/support/news/LoopholeInfoDetail.aspx?newsId=1015924)
lists **ZXHN H168N V3.5 Etis**, all versions through `V3.5.0_EG1T4_TE`, and resolves it
with `V3.5.0_EG1T10_ETS`. The issue is an information leak through a wizard page due to
improper permissions. NVD describes it as affecting H168N versions up to that same
`EG1T4_TE` boundary and gives an enriched score of 6.5; ZTE's bulletin displays 3.5.

**Classification:** conditional. The advisory is authoritative for the exact `EG` build,
but no public source found during this research maps that suffix to PTCL. Do not label a
PTCL unit affected from the model name alone.

### 3. H168N v3.5 CSRF — exact non-PK variant only

[CVE-2021-21729](https://nvd.nist.gov/vuln/detail/CVE-2021-21729) covers missing CSRF
random-value checks. ZTE lists `ZXHN H168N V3.5` `V3.5.0_EG1T5_TE` as affected and
`V3.5.0P1N3_TE1` as resolved. A crafted cross-site request could perform an unauthorized
action when the required browser/session conditions are present.

**Classification:** conditional, not PTCL-confirmed. The `EG1T5_TE` suffix is an ISP or
regional firmware identifier in the public advisory, not proof of a PTCL image.

### 4. H168N v3.5 CLI access control — exact non-PK variant only

[CVE-2021-21730](https://nvd.nist.gov/vuln/detail/CVE-2021-21730) covers brute-force
access to a CLI because of improper access control. ZTE lists `V3.5.0_TY.T6` as affected
and `V3.5.0P1N3_TE1` as resolved. NVD's enriched score is 9.8; ZTE's bulletin displays
6.2.

**Classification:** conditional, not PTCL-confirmed. Never test this by brute-forcing a
live device. Use only the displayed firmware string and vendor fix boundary.

## Safe local checks

The checker in [`tools/ptcl_zte_check.py`](../tools/ptcl_zte_check.py) is deliberately
narrow:

1. Resolve the target and refuse public addresses.
2. `GET /` on the management HTTP port to collect non-secret model/firmware text.
3. If `--probe-upnp` is supplied, send one `GetSecurityKeys` SOAP request to port `52869`.
4. Search only for the presence of WLAN-key fields. The response body is discarded after
   that; no key is decoded, printed, written to JSON, or sent anywhere else.
5. Never send `SetSecurityKeys`, CSRF requests, CLI guesses, malformed input, or firmware
   uploads.

A positive read-only response is enough to report **VULNERABLE**. A timeout or an absent
service is **UNASSESSED**, not proof that a device is patched. A version string matching
ZTE's exact affected list is reported as vulnerable even without the optional probe. A
fixed version plus a denied/faulted read is a good result for the 2018 check, but it does
not clear later or operator-specific bugs.

### Manual inventory checklist

From the device's own status/about page, record:

* model and hardware revision;
* complete software/firmware version and suffix;
* whether UPnP is enabled;
* whether WAN/remote management is enabled; and
* the management IP and whether it is bridged behind another router.

Do not use a WAN scanner or a public IP as a substitute for the LAN check. The router's
WAN exposure and a malicious client already on Wi-Fi are different threat models.

## Mitigation and recovery

1. **Update through PTCL or ZTE using the exact hardware and operator image.** Do not
   cross-flash a retail H168N image; a matching product name is not a matching build.
2. If no verified fix is available, **disable UPnP** and disable WAN/remote management.
   Put the DSL gateway in bridge mode and let a supported router perform routing/firewall
   duties where PTCL permits it.
3. If `GetSecurityKeys` returned data, assume the wireless secret was exposed. Change the
   Wi-Fi passphrase and administrator password from a trusted wired client, then reboot.
4. Review DNS, port-forwarding, TR-069/remote-management, and Wi-Fi settings after an
   exposure. Do not restore an old configuration backup without inspecting it.
5. Keep the modem on a separate management network where possible. A firewall helps with
   WAN exposure but cannot make an unauthenticated LAN service safe from an infected LAN
   host.

## Sources

### Primary/vendor and vulnerability records

* [ZTE advisory for CVE-2018-7357 and CVE-2018-7358](http://support.zte.com.cn/support/news/LoopholeInfoDetail.aspx?newsId=1009523) — exact PK affected versions and `V2.2.0_PK1.2T6` resolution.
* [ZTE Chinese advisory mirror](http://support.zte.com.cn/support/news/LoopholeInfoDetail.aspx?newsId=1009522) — same version table and November 2018 update record.
* [Exploit-DB 45972](https://www.exploit-db.com/exploits/45972) — H168N v2.2 build, port 52869, read/write UPnP findings, and public request shape.
* [NVD CVE-2018-7357](https://nvd.nist.gov/vuln/detail/CVE-2018-7357) and [NVD CVE-2018-7358](https://nvd.nist.gov/vuln/detail/CVE-2018-7358) — descriptions, affected versions, and enriched scoring.
* [ZTE CVE-2021-21729 advisory](https://support.zte.com.cn/support/news/LoopholeInfoDetail.aspx?newsId=1014904) — v3.5 CSRF and resolved version.
* [ZTE CVE-2021-21730 advisory](https://support.zte.com.cn/support/news/LoopholeInfoDetail.aspx?newsId=1014864) — v3.5 CLI access-control issue and resolved version.
* [ZTE CVE-2021-21735 advisory](https://support.zte.com.cn/support/news/LoopholeInfoDetail.aspx?newsId=1015924) — v3.5 wizard information leak and resolved version.
* [NVD CVE-2021-21729](https://nvd.nist.gov/vuln/detail/CVE-2021-21729), [NVD CVE-2021-21730](https://nvd.nist.gov/vuln/detail/CVE-2021-21730), and [NVD CVE-2021-21735](https://nvd.nist.gov/vuln/detail/CVE-2021-21735) — independent records and version boundaries.

### PTCL/model association evidence

* [PakGamers PTCL thread, page 473](https://www.pakgamers.com/index.php?threads/the-official-mega-ptcl-thread-a-sequel-without-drama-all-is-well.212593/page-473) — community identification of `ZXHN H168N V2.2` as a PTCL modem.
* [Marketplace listing for PTCL H168N V3.5](https://www.daraz.pk/products/ptcl-wifi-router-vdsl-2-model-no-h-168n-v35-official-ptcl-modem-brand-new-modem-i378952963.html) — weak resale evidence only; not used as firmware proof.

## What is deliberately not claimed

* A `PK` firmware string is strong evidence for the 2018 PTCL-linked finding, but it is
  not a guarantee about every PTCL-issued H168N.
* A foreign `EG`, `TY`, or `Etis` H168N advisory is not silently called a PTCL exposure.
* No ZTE web URL from the D-Link project is reused here. This checker uses the H168N's
  documented UPnP service and never treats vendor endpoints as interchangeable.
