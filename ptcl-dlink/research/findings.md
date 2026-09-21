# Findings — PTCL D-Link `webproc` auth bypass

Sourced summary as of 2026-09-21. Every claim below traces to a reference at the bottom.

---

## 1. The device class

PTCL (Pakistan Telecommunication Company Ltd) ships **D-Link DSL-series ADSL routers** as
its bundled broadband CPE. Confirmed models and revisions:

| model | H/W revisions seen | PTCL firmware |
|---|---|---|
| DSL-2750U | `D1`, `J1`, `T3` | `PT_2.00 20161209`, `DSL-2750U_K92_PTCL_R2005_20170510`, `GAN5.PT113A-B-DL-R5B015-PTB` |
| DSL-2730U | — | retail `IN_*`, `SEA_*`, `ME_*` builds documented |
| DSL-2750E | — | retail `SEA_*` builds documented |

Management address is **`192.168.10.1`** on PTCL builds (the sticker and PTCL's own docs say
so; D-Link's *generic* manual says `192.168.1.1`). `192.168.1.1` is also reported on some
units — check the sticker, and note that a factory reset can move a unit between the two.

Two things worth flagging, both sourced:

* **Hardware revisions are not cross-flashable.** `D1`/`J1`/`T3` images are distinct; flashing
  a mismatched one is rejected with `illegal image` rather than bricking — sometimes. The
  `PTCL(D1)` image reportedly failed on a genuine `D1` unit for at least one user.
* **A factory reset does not reliably restore the default credentials on these builds.**
  PTCL thread and D-Link forum thread 66266 both document a `DSL-2750U H/W D1` that refused
  both the default Wi-Fi password and the default admin login after a reset, with the SSID's
  trailing MAC-derived suffix no longer matching the label. Cause never established.

## 2. The bug

`/cgi-bin/webproc` selects its output from URL parameters (`getpage`, `errorpage`,
`var:menu`, `var:subpage`, `var:page`, `var:language`). Setting **`var:page=wizard`** routes
to the first-boot setup-wizard templates, which were written to run *before an account
exists* — so that code path does not consult the `:sessionid` cookie.

```
GET /cgi-bin/webproc?getpage=html/index.html&errorpage=html/index.html
    &var:language=en_us&var:menu=setup&var:subpage=wizentrance&var:page=wizard
```

Returns the wizard UI, HTTP 200, no credentials supplied.

### What the wizard exposes

`var:subpage=wizwl` (wizard → wireless) renders live config into page-local JavaScript:

```js
var wireless_name = "…";
var randomWPAKEY  = "…";
var randomWEPKey  = "…";
```

The public PoC is literally `curl … | grep -e 'var wireless_name' -e 'var randomW'`.
The values sit behind `<input type="password">`, which hides them on screen but not in the
document source. Author reports the leak on `ME_1.03`, `ME_1.07`, `ME_1.09`, `ME_1.11`,
`IN_1.15`, fixed in `ME_1.15`; the second report covers `DSL-2730U / ME_1.07` with the same
range and says firmware `1.0` is unaffected.

The wizard's step 2 writes Internet-connection settings. Submitting bad data there takes the
WAN link down — the DoS half of CVE-2019-1010155.

### Why it stays open

The unauthenticated wizard response carries `Set-Cookie: :sessionid=…`. That is a normal
privileged session:

* nothing invalidates it — there is no logout that removes the server-side entry;
* no idle or absolute timeout is enforced;
* the cookie itself is a session cookie with no `Max-Age`/`Expires`, so the browser keeps it
  for as long as the browser session lives;
* subsequent `var:menu=…` navigations are authorised purely by cookie lookup, so nothing
  re-prompts.

The session entry lives in the daemon's memory, so **a reboot is the one reliable way to
drop it**. This is the mechanism behind the reported "I opened the URL and then the router
page just stays open."

### The severe variant

`getpage` is not restricted to templates. **CVE-2025-34048**, CVSS v4.0 **8.7 High**,
published 2025-06-26, with exploitation observed in the wild by the Shadowserver Foundation
on **2025-02-04**:

```
GET /cgi-bin/webproc?getpage=/etc/shadow&errorpage=html/main.html
    &var:language=en_us&var:menu=setup&var:page=wizard
```

Returns `/etc/shadow`, unauthenticated, on DSL-2730U `IN_1.02` and DSL-2750U / DSL-2750E
`SEA_1.04` and `SEA_1.07`. EPSS is under 1% and it is **not** in CISA KEV, so it is not being
mass-exploited — but it is trivially automatable.

## 3. CVE status, and what is disputed

| CVE | CVSS | disposition |
|---|---|---|
| CVE-2019-1010155 | 6.4 (v2) | **DISPUTED by D-Link** — "although the wizard is accessible without authentication, it can't actually configure anything." |
| CVE-2019-1010156 | — | same finding, framed as a login-form bypass |
| CVE-2025-34048 | **8.7 (v4.0)** | accepted; no vendor fix, no workaround listed by the CNA |

D-Link's dispute is worth reading precisely, because it is **narrower than it sounds**. They
do not deny the wizard is reachable without authentication. They argue the *impact* was
overstated (no DoS, no info leak). That defence also does not touch CVE-2025-34048, which is
the file-read primitive and carries the real score.

## 4. The PTCL-specific gap — the actual open question

The CVE affected-version lists name retail builds: `IN_*`, `SEA_*`, `ME_*`.
**PTCL's ISP builds (`PT_*`, `K92_PTCL_*`, `GAN5.PT113A-*`) appear in none of them.**

Consequences:

1. PTCL builds are **neither confirmed vulnerable nor confirmed patched** by any public
   source. They are untested, not clean.
2. PTCL firmware diverges from retail (custom ACS/provisioning), so `webproc` *could* have
   been modified — but ISP images are typically forks of *older* retail code, which argues
   the other way.
3. **Neither party accepts responsibility.** D-Link's forum position is: *"D-Link does not
   support or develop for this particular modem in these cases"* — go to the ISP. PTCL
   distributes the build but does not publish CVE-tracked release notes or a security
   advisory feed.
4. No patch timeline exists on either side, so the practical planning assumption is
   **"never fixed."**

This is exactly the gap `tools/ptcl_check.py` is written to close for your specific unit.

## 5. Related D-Link auth bypasses (same family, different devices)

Useful for pattern recognition, not for this bug:

* **`xmlset_roodkcableoj28840ybtide`** — a hardcoded User-Agent in `/bin/webs` that satisfies
  `alpha_auth_check()`. Full admin access with no login on DIR-100, DI-524, DI-524UP,
  DI-604S, DI-604UP, DI-604+, TM-G5240, some DIR-615 (incl. Virgin Mobile units); requires
  source-address 192.168.0.1. Public since 2013.
* **`http://192.168.0.1/bsc_lan.php?`** — 2011, unauthenticated main admin page on
  DIR-615revD, DIR-320, DIR-300; exploited as CSRF via an `<img src>` tag.
* **CVE-2017-12943** — DIR-600 B1 v2.01, `model/__show_info.php?REQUIRE_FILE=%2Fvar%2Fetc%2Fhttpasswd`.
* **CVE-2026-0625** — missing auth on `dnscfg.cgi` across multiple DSL/DIR/DNS devices; the
  GhostDNS "DNSChanger" vector. All affected products are EOL/EOS with no patch, per D-Link
  advisories SAP10068 / SAP10118 / SAP10488.
* **CVE-2018-17777** — DVA-5592, `/ui/cbpc/login` reachable unauthenticated, then a `sid`
  cookie edit bypasses the form.

The recurring shape: a second entry point (wizard, recovery page, `bsc_lan.php`, `dnscfg.cgi`)
that predates or sidesteps the session check the main UI enforces.

## 6. Cleanup / mitigation

| # | action | why |
|---|---|---|
| 1 | Rotate Wi-Fi PSK and admin password | both may be disclosed; assume compromise, do not audit it |
| 2 | Disable remote / WAN management | removes the internet-reachable attack surface entirely |
| 3 | **Reboot the router** | only reliable way to drop a bypass-minted `:sessionid` |
| 4 | Request a current build from PTCL | D-Link will not supply one for an ISP unit |
| 5 | Bridge the unit; route with hardware you control | the only durable fix, since (1)–(4) all depend on an unresponsive vendor |

## 7. References

* [CVE-2025-34048 — OpenCVE](https://app.opencve.io/cve/CVE-2025-34048) — CVSS 8.7 v4.0, affected builds, Shadowserver exploitation date
* [CVE-2019-1010155 — OpenCVE](https://app.opencve.io/cve/CVE-2019-1010155) — disputed status and D-Link's rebuttal
* [CVE-2019-1010156 — GitHub Advisory](https://github.com/advisories/GHSA-7w64-w8mx-grwj)
* [Exploit-DB 40735 — "D-Link DSL-2730U/2750U/2750E ADSL Router Remote File Disclosure"](https://www.exploit-db.com/exploits/40735) — Todor Donev, 2016; the `/etc/shadow` read
* [Packet Storm — DSL-2750E SEA_1.07 Remote File Disclosure](https://packetstormsecurity.com/files/139637/D-Link-ADSL-Router-DSL-2750E-SEA_1.07-Remote-File-Disclosure.html) — same primitive, with the shadow output
* [Packet Storm mirror](https://www.nmmapper.com/st/exploitdetails/40735/16478/d-link-dsl-2730u2750u2750e-adsl-router-remote-file-disclosure/) — affected-build list (`IN_1.02`, `SEA_1.04`, `SEA_1.07`)
* [CXSecurity WLB-2020070098](https://cxsecurity.com/issue/WLB-2020070098) — the 2020 Wi-Fi-key PoC, `ME_1.03`–`ME_1.11` / `IN_1.15`, fixed in `ME_1.15`
* [CXSecurity WLB-2018080199](https://cxsecurity.com/issue/WLB-2018080199) — the 2018 wizard-page report, all five steps, `1.11` and older
* [Null Byte — bruteforcing a DSL-2750U](https://null-byte.wonderhowto.com/forum/bruteforcing-dlink-dsl2750u-adsl-router-with-hydra-0175621/) — confirms the cookie is `%3Asessionid`, i.e. `:sessionid`
* [D-Link forum topic 66266](http://forums.dlink.com/index.php?topic=66266.0) — PTCL `DSL-2750U H/W D1`, `PT_2.00 20161209`, `192.168.10.1`, and D-Link declining ISP-firmware support
* [Dark Reading — D-Link auth bypass, 2013](https://www.darkreading.com/vulnerabilities-and-threats/d-link-router-vulnerable-to-authentication-bypass/d/d-id/1111927) — the `xmlset_roodkcableoj28840ybtide` User-Agent backdoor
* [D-Link forum topic 23161](http://forums.dlink.com/index.php?topic=23161.0) — the 2011 `bsc_lan.php` family, and the WPS/CSRF attack chain
* [SentinelOne — CVE-2026-0625](https://www.sentinelone.com/vulnerability-database/cve-2026-0625/) — `dnscfg.cgi` missing auth, GhostDNS, D-Link advisories SAP10068 / SAP10118 / SAP10488
* [PakGamers — PTCL DSL-2750U firmwares](https://pakgamers.com/index.php?threads%2Fptcl-dsl-2750u-firmwares.275428=) — PTCL vs retail image names, and the `illegal image` mismatch on `D1`
