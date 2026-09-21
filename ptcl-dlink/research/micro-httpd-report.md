# PTCL D-Link — ACME `micro_httpd`: what it is, how it got there, and its vulnerability surface

> **Date:** 2026-09-21
> **Scope:** ACME Labs `micro_httpd` as found in PTCL D-Link DSL-series ADSL firmware
> (DSL-2750U and relatives), and how to verify whether *your* unit is exposed to it.
> **Companion docs:** [`../README.md`](../README.md) (the `webproc` bypass),
> [`findings.md`](./findings.md) (sourced summary of the device-class bugs),
> [`../tools/ptcl_check.py`](../tools/ptcl_check.py) (read-only LAN detector).

---

## 1. Executive summary

* `micro_httpd` is a **~200-line C web server** from ACME Labs (the XAMPP/thttpd/mini_httpd
  vendor). It runs from **inetd** — it wakes up per connection, so it costs almost no RAM when
  idle. It is a classic **embedded-device** server: tiny binary, zero dependencies.
* It is **not installed by the user** — it is compiled into the vendor firmware image.
  **D-Link DSL-2750U / DSL-2740U are explicitly named** in the public CVE for it
  ([CVE-2014-4927](https://nvd.nist.gov/vuln/detail/CVE-2014-4927)), which is the same
  hardware family PTCL ships.
* It exists on the router to serve the web layer with minimal footprint; on this D-Link/Conexant
  stack the heavy lifting (admin UI) is done by the `/cgi-bin/webproc` CGI, while the plain
  HTTPd binary handles the static/root layer.
* **There is no fixed version of `micro_httpd`.** The last public build is
  [`14Aug2014`](http://www.acme.com/software/micro_httpd/micro_httpd_14Aug2014.tar.gz) and the
  DoS CVE (2014) was never patched. The practical planning assumption — the same one used in
  [`findings.md`](./findings.md) for the PTCL builds — is **"never fixed"**.
* Risk is therefore driven by **exposure**, not by a patch: who can reach the device's port 80.
  LAN-only = nuisance-grade DoS at worst. Internet-reachable (remote management / port-forward)
  = remote crash plus whatever else that entry point touches — on this device class, a lot.
* Verification is a 4-step read-only procedure (Section 6): fingerprint the binary and version,
  compare against the CVE table (Section 5), run safe probes, and use the existing
  `tools/ptcl_check.py` for the `webproc` half of the stack.

---

## 2. What `micro_httpd` is

Official page: [http://www.acme.com/software/micro_httpd/](http://www.acme.com/software/micro_httpd/)

Facts from the project page and the source (the maintained fork with the same code is at
[https://codeberg.org/mandragora/micro-httpd](https://codeberg.org/mandragora/micro-httpd)):

| property | value |
|---|---|
| author / vendor | Jef Poskanzer, **ACME Labs** (`http://www.acme.com/jef/`) |
| size | **about 200 lines of C**, single file (`micro_httpd.c`) |
| compile deps | libc only — no external libraries, no threads |
| runtime model | **inetd-spawned**: one process per request; "performance is poor, but for low-traffic sites it's quite adequate" (vendor's own words) |
| features | serves files, `index.html`, directory listings, common MIME types, trailing-slash redirect, `".."` filename-snoop protection |
| HTTPS | not built in; vendor suggests wrapping with `stunnel` |
| last public build | **14 Aug 2014** ([tarball](http://www.acme.com/software/micro_httpd/micro_httpd_14Aug2014.tar.gz)) |
| license posture | free to use, donation-supported project — which is exactly why nobody patches it |

### 2.1 Don't confuse the ACME family

ACME Labs publishes several near-homonym servers, and they are constantly conflated in
fingerprinting output and CVE databases:

| server | page | character | typical CVEs |
|---|---|---|---|
| **micro_httpd** | [acme.com/software/micro_httpd/](http://www.acme.com/software/micro_httpd/) | ~200 lines, **inetd**, read-only file serving | CVE-2014-4927, CVE-2010-1544 (both DoS) |
| **thttpd** | [acme.com/software/thttpd/](https://acme.com/software/thttpd/) | small, threaded, long-lived | CVE-2009-4490 (command injection), CVE-2017-17663 (overflow) |
| **mini_httpd** | [acme.com/software/mini_httpd/](https://acme.com/software/mini_httpd/) | most full-featured of the three, with `htpasswd` | CVE-2017-17663, CVE-2018-18778 (file read), CVE-2026-68005 (DoS, 2026, unpatched) |
| js_httpd | [acme.com/software/js_httpd/](https://acme.com/software/js_httpd/) | tiny, JS-based, curiosities list | — |

**If you saw the literal string `http://www.acme.com/software/micro_httpd/`** (e.g. in
`strings` of the binary, in `ps`, or in a banner), then the tiny inetd one is on the box.
If the banner instead says `thttpd/2.xx` or `mini_httpd/1.xx`, use the family table in
Section 5.3 to look up *that* version.

---

## 3. How it got onto the router

### 3.1 On the PTCL unit: it is in the firmware, not "installed"

The chain is:

```
D-Link/Conexant ADSL firmware design
  → vendor compiles micro_httpd (static binary, few KB) into the image
    → PTCL rebrands/re-images for ISP provisioning (PT_*, K92_PTCL_*, GAN5.PT113A-*)
      → the binary ships with the box and starts from the init scripts / inetd
```

Evidence it is specifically on this hardware family:

* **CVE-2014-4927** — *"Buffer overflow in ACME micro_httpd, **as used in D-Link DSL2750U
  and DSL2740U** and NetGear WGR614 and MR-ADSL-DG834 routers allows remote attackers to
  cause a denial of service (crash) via a long string in the URI in a GET request"* —
  [NVD](https://nvd.nist.gov/vuln/detail/CVE-2014-4927),
  [GitHub Advisory GHSA-rfw9-259h-m9m6](https://github.com/advisories/GHSA-rfw9-259h-m9m6),
  [CVE Details product page](https://www.cvedetails.com/vulnerability-list/vendor_id-10442/product_id-19167/Acme-Micro-Httpd.html).
* Exploit/PoC references for the same CVE: [Exploit-DB 34102](http://www.exploit-db.com/exploits/34102),
  [Packet Storm 127544](http://packetstormsecurity.com/files/127544/ACME-micro_httpd-Denial-Of-Service.html),
  [OSVDB 109356](http://osvdb.org/show/osvdb/109356), [BID 68746](http://www.securityfocus.com/bid/68746).

Typical placement on these images: a small statically-linked binary
(e.g. `/usr/sbin/micro_httpd` or a renamed `httpd`) that serves the root/static web layer,
while the **admin UI is the separate `/cgi-bin/webproc` CGI** documented in
[`../README.md`](../README.md). The split matters for the risk model: even if the plain
httpd is only a file server, the *same port 80* front-doors the whole `webproc` stack.

### 3.2 For reference: what "installing" it would look like on plain Linux

(Useful if you ever build it for the `wr720n` custom OS, not for the PTCL box.)

1. Download [`micro_httpd_14Aug2014.tar.gz`](http://www.acme.com/software/micro_httpd/micro_httpd_14Aug2014.tar.gz)
2. `make` — nothing but a C compiler is needed (the fork's README notes a `SYSVLIBS` line for
   old SysV systems)
3. install the resulting ~few-KB binary, and either run it from `inetd` (`/etc/inetd.conf`
   entry) or, on modern distros where nobody runs inetd anymore, point a light init at it

On an embedded MIPS/ARM router you would cross-compile for the target CPU. On the PTCL unit
you do **not** do any of this — you inherit whatever the image shipped.

---

## 4. Why it's there

1. **Footprint.** A router has a few MB of RAM and flash. Apache = several MB plus a dozen
   libraries. `micro_httpd` = ~200 lines → a few KB, no dependencies.
2. **Inetd model = near-zero idle cost.** It occupies no memory at all until a request
   arrives; the request process dies when the request ends. Fine for "one human with a
   browser opens the admin page occasionally."
3. **Simplicity is a feature in a 2009-era firmware pipeline.** One file, no config format
   beyond the document root, no modules, nothing to misconfigure — the vendor's own pitch is
   "for low-traffic sites, it's quite adequate."
4. **Division of labor.** Static files / root page: the tiny httpd. Configuration UI +
   session/cookie logic: the `webproc` CGI. The two together are the device's whole web stack.

---

## 5. Vulnerability landscape

### 5.1 Direct hits on `micro_httpd`

| CVE | Impact | Affected | Fixed in | Status |
|---|---|---|---|---|
| [**CVE-2014-4927**](https://nvd.nist.gov/vuln/detail/CVE-2014-4927) | DoS — crash via **long URI in a GET request**. **Names D-Link DSL2750U/DSL2740U explicitly** | micro_httpd as used in D-Link DSL2750U/DSL2740U, NetGear WGR614, MR-ADSL-DG834 | **none — never fixed** | [PoC: EDB 34102](http://www.exploit-db.com/exploits/34102), [Packet Storm](http://packetstormsecurity.com/files/127544/ACME-micro_httpd-Denial-Of-Service.html), [OSVDB](http://osvdb.org/show/osvdb/109356), [BID](http://www.securityfocus.com/bid/68746), [GHSA](https://github.com/advisories/GHSA-rfw9-259h-m9m6) |
| [**CVE-2010-1544**](https://nvd.nist.gov/vuln/detail/CVE-2010-1544) | DoS — **device reboot** via long string to TCP port 80 (reported on RCA DCM425 cable modem, same server) | micro_httpd (cable-modem build) | **none** | listed on [CVE Details](https://www.cvedetails.com/vulnerability-list/vendor_id-10442/product_id-19167/Acme-Micro-Httpd.html) (CVSS 5.0, EPSS ≈ 6.2%) |

**Consequence:** every known public build of `micro_httpd` — including the 2014 one PTCL-era
images ship — is **known-DoSable and unpatchable by design** (the project is dormant). The
only question is who can send it the long GET.

### 5.2 Same port, same box: the `webproc` stack (don't skip this)

The httpd binary is only the front door. The router's actual admin CGI (`/cgi-bin/webproc`)
has its own CVE record — see the full sourced writeup in [`findings.md`](./findings.md):

| CVE | Impact | Affected builds (public) | Notes |
|---|---|---|---|
| [**CVE-2025-34048**](https://app.opencve.io/cve/CVE-2025-34048) | **Path traversal → unauthenticated arbitrary file read** (`getpage=/etc/shadow`), CVSS v4.0 **8.7** | DSL-2730U `IN_1.02`, DSL-2750U/E `SEA_1.04`/`SEA_1.07` | [EDB 40735 PoC](https://www.exploit-db.com/exploits/40735); [Packet Storm 139637](https://packetstormsecurity.com/files/139637/D-Link-ADSL-Router-DSL-2750E-SEA_1.07-Remote-File-Disclosure.html); exploitation **observed in the wild 2025-02-04** (Shadowserver) |
| [**CVE-2019-1010155**](https://app.opencve.io/cve/CVE-2019-1010155) | Setup wizard reachable unauthenticated (info leak / DoS) | DSL-2750U `1.11` | **disputed by D-Link**; see [CXSecurity WLB-2018080199](https://cxsecurity.com/issue/WLB-2018080199) |
| [**CVE-2019-1010156**](https://github.com/advisories/GHSA-7w64-w8mx-grwj) | same finding, framed as login-form auth bypass | DSL-2750U `1.11` | — |
| (2020 Wi-Fi-key leak) | wizard wireless step renders `var wireless_name` / `var randomWPAKEY` cleartext in JS | `ME_1.03`–`ME_1.11`, `IN_1.15`; fixed `ME_1.15` | [CXSecurity WLB-2020070098](https://cxsecurity.com/issue/WLB-2020070098) |

**PTCL-specific gap:** PTCL ISP builds (`PT_*`, `K92_PTCL_*`, `GAN5.PT113A-*`) appear in
*none* of the affected-version lists — they are **untested, not clean** (Section 4 of
[`findings.md`](./findings.md)). The same gap applies to `micro_httpd` itself: nobody has
published the exact build string inside a PTCL image, so you fingerprint your own unit
(Section 6).

### 5.3 Family context (if your fingerprint says `thttpd`/`mini_httpd` instead)

| CVE | Server | Impact | Fixed in | Refs |
|---|---|---|---|---|
| [CVE-2009-4490](https://www.exploit-db.com/exploits/33500) | thttpd 2.25b / mini_httpd ≤ 1.19 | **command injection** via terminal escape sequences written to log files | thttpd 2.26 / mini_httpd 1.20 | [EDB 33500](https://www.exploit-db.com/exploits/33500), [BID 37714](http://www.securityfocus.com/bid/37714) |
| [CVE-2017-17663](https://www.cybersecurity-help.cz/vdb/SB2018020704) | mini_httpd 1.20–1.27 / thttpd 2.24–2.27 | **buffer overflow → RCE** via crafted input (htpasswd path) | mini_httpd 1.28 / thttpd 2.28 | [vendor update note](http://acme.com/updates/archive/199.html) |
| [CVE-2018-18778](https://www.acunetix.com/vulnerabilities/web/acme-mini_httpd-arbitrary-file-read/) | mini_httpd < 1.30 | **arbitrary file read** (e.g. `/etc/passwd`) | 1.30 | [Invicti entry](https://www.invicti.com/web-application-vulnerabilities/acme-mini-httpd-arbitrary-file-read) |
| [CVE-2026-68005](https://www.sentinelone.com/vulnerability-database/cve-2026-68005/) | mini_httpd ≤ 1.30 (2026) | **DoS** via crafted HTTP headers | **none yet** | [SentinelOne DB](https://www.sentinelone.com/vulnerability-database/cve-2026-68005/) |

Takeaway for the family: **even the newest `mini_httpd` (1.30) now has an unpatched DoS** —
there is no version of this server family that is safe to expose to the internet.

---

## 6. Verification procedure (read-only, LAN-only)

Run these against **your own router only**. Default PTCL address: `192.168.10.1`
(some units `192.168.1.1` — check the sticker).

### 6.1 Passive fingerprinting (zero risk)

```sh
# from your phone/laptop — does the banner identify the server?
curl -sI http://192.168.10.1/ | grep -i server

# version banner + server identity, more thorough
nmap -sV -p 80,8080,8090 192.168.10.1
```

If you have a shell on the unit:

```sh
ps | grep -i http                                   # what process, what binary
file  <httpd-binary-path>                           # arch / static?
strings <httpd-binary-path> | grep -iE 'micro_httpd|thttpd|mini_httpd|version|acme'
netstat -tln 2>/dev/null || netstat -an             # which IP is port 80 bound to?
```

`netstat` is the exposure answer: bound to the LAN IP only = LAN attack surface;
`0.0.0.0` + any WAN-side rule = internet attack surface.

### 6.2 Match version → CVE table

| fingerprint says | verdict |
|---|---|
| `micro_httpd` (any/unknown version) | CVE-2014-4927 DoS applies, unpatchable → exposure-controlled only |
| `thttpd` 2.25b or older | CVE-2009-4490 command injection applies |
| `mini_httpd` < 1.28 | CVE-2017-17663 RCE applies |
| `mini_httpd` 1.28–1.29 | CVE-2018-18778 file read applies |
| `mini_httpd` ≤ 1.30 | CVE-2026-68005 DoS applies |

Cross-reference any version string you find on
[NVD](https://nvd.nist.gov/vuln/search) / [CVE Details product page](https://www.cvedetails.com/vulnerability-list/vendor_id-10442/product_id-19167/Acme-Micro-Httpd.html).

### 6.3 Safe active probes (your own device; accept possible reboot)

1. **Long-URI DoS — CVE-2014-4927 confirmation.** Warning: if the device crashes, the admin
   page is gone until power-cycle. Do this last, not first.

   ```sh
   curl -s "http://192.168.10.1/$(printf 'A%.0s' {1..50000})" -o /dev/null -w "%{http_code}\n"
   ```

   Admin page dead afterwards → confirmed. Public PoC for comparison:
   [Exploit-DB 34102](http://www.exploit-db.com/exploits/34102).

2. **Log-injection marker — CVE-2009-4490 class (only meaningful for thttpd/mini_httpd).**
   Send a unique string, then grep the device logs; **if the marker appears in the log, the
   log channel is injectable** (the original exploit escalated this to command execution via
   terminal escapes):

   ```sh
   curl -s 'http://192.168.10.1/%1b%5d2%3bTESTMARK%0a'
   # on the router: grep -r TESTMARK /var/log/ /tmp/
   ```

3. **`webproc` half — use the existing tool, not hand-rolled requests.** It covers baseline,
   wizard bypass, Wi-Fi-key leak presence, session persistence, and `getpage=/proc/version`
   traversal reachability (see [`findings.md`](./findings.md) §4 for the PTCL gap it closes):

   ```bash
   cd ptcl-dlink
   python3 tools/ptcl_check.py 192.168.10.1 --urls     # print URLs only, no traffic
   python3 tools/ptcl_check.py 192.168.10.1            # full read-only check
   python3 tools/selftest_mock.py --port 8099 &        # validate the detector offline first
   python3 tools/ptcl_check.py 127.0.0.1 --port 8099
   ```

   The tool is GET-only, LAN-only, and refuses non-private IPs by design.

4. **Internet-exposure check (from outside, no shell needed).** On your phone using
   **mobile data**, open your public IP. If the admin UI or any router page loads, the box
   is internet-reachable and every row of Section 5 is live for any scanner. (Behind typical
   PTCL CGNAT this usually fails — but if you have a static IP / port-forwards / remote
   management, it may not.)

---

## 7. Risk assessment

| exposure scenario | what an attacker gets | severity driver |
|---|---|---|
| **LAN only** (normal home setup) | DoS of the admin UI (long-URI GET); session-creation + whatever `webproc` allows on this exact build (untested PTCL builds — see gap note) | low–medium; mainly a nuisance until combined with the `webproc` bypass |
| **LAN + the `webproc` bypass on this unit** | unauthenticated privileged `:sessionid` that **never expires** (reboot is the only drop, per [`../README.md`](../README.md)); Wi-Fi PSK potentially in cleartext JS | **high** — the httpd is just the door |
| **Internet-reachable** | remote DoS for free; everything above, from anywhere; the 2025 in-the-wild exploitation of the file-read primitive shows scanners look for exactly this | **high/critical** — assume it gets found within days |

Aggravating factor specific to this device class: the unauthenticated session
(`:sessionid`) has **no idle timeout and no server-side invalidation** — one successful
request pins a privileged session open until a reboot
([`../README.md`](../README.md) §1, symptom b).

---

## 8. Recommendations (in order of effort)

1. **Rotate the Wi-Fi PSK and the admin password** — anything the wizard/admin layer could
   render was readable by anyone who could reach the box; assume compromise, don't audit it.
2. **Disable remote/WAN management and any port-forward to `192.168.10.1:80`.** This is the
   single highest-value action: it converts an internet-exposed CVE stack into a LAN one,
   which is what `micro_httpd` was designed to survive.
3. **Reboot the router** — the only reliable way to drop a bypass-minted `:sessionid`.
4. **Close all tabs on the UI and clear cookies for the router IP**, then reopen `/`; if you
   still get in without a password, the bypass is live on your unit.
5. **Ask PTCL for a current firmware build** for your exact H/W revision
   (`D1`/`J1`/`T3` are **not** cross-flashable — a mismatched image is rejected
   `illegal image`; [D-Link forum 66266](http://forums.dlink.com/index.php?topic=66266.0),
   [PakGamers firmware thread](https://pakgamers.com/index.php?threads%2Fptcl-dsl-2750u-firmwares.275428=)).
   D-Link will not supply one for an ISP unit.
6. **Do not expect `micro_httpd` to ever be patched.** The project's last build is
   [14 Aug 2014](http://www.acme.com/software/micro_httpd/micro_httpd_14Aug2014.tar.gz) and
   its CVE was never fixed. The durable fix for the whole box is to **bridge the PTCL unit
   and route with hardware you control** (which is the separate `../wr720n/` project's purpose).
7. **Re-run `tools/ptcl_check.py` after any firmware update or config change** to re-baseline
   the unit.

---

## 9. Open questions (to close on your own unit)

| # | question | how to close it |
|---|---|---|
| 1 | Exact httpd binary path + version string inside the PTCL image | `strings` on the binary (6.1) or firmware image extraction |
| 2 | Does the PTCL build answer the long-URI GET (CVE-2014-4927 live?) | probe 6.3.1 (accept reboot) |
| 3 | Is `getpage=` traversal live on the PTCL build (CVE-2025-34048 class)? | `ptcl_check.py` probe 5 (reachability only, contents masked) |
| 4 | Is the box reachable from the internet today? | 6.3.4 mobile-data check |
| 5 | What does PTCL say about a firmware update? | ask them with your serial + H/W revision; keep the ticket number for this repo |

---

## 10. References

**The server itself**

* [micro_httpd — official project page (ACME Labs)](http://www.acme.com/software/micro_httpd/)
* [micro_httpd 14Aug2014 — last public tarball](http://www.acme.com/software/micro_httpd/micro_httpd_14Aug2014.tar.gz)
* [mandragora/micro-httpd — maintained source fork (Codeberg)](https://codeberg.org/mandragora/micro-httpd)
* [mini_httpd project page](https://acme.com/software/mini_httpd/) · [thttpd project page](https://acme.com/software/thttpd/) · [js_httpd project page](https://acme.com/software/js_httpd/)
* [CVE Details — Acme Micro Httpd product page](https://www.cvedetails.com/vulnerability-list/vendor_id-10442/product_id-19167/Acme-Micro-Httpd.html)

**micro_httpd CVEs**

* [CVE-2014-4927 — NVD](https://nvd.nist.gov/vuln/detail/CVE-2014-4927) (names D-Link DSL2750U/DSL2740U)
* [CVE-2014-4927 — GitHub Advisory GHSA-rfw9-259h-m9m6](https://github.com/advisories/GHSA-rfw9-259h-m9m6)
* [Exploit-DB 34102 — ACME micro_httpd DoS PoC](http://www.exploit-db.com/exploits/34102)
* [Packet Storm 127544 — ACME micro_httpd Denial Of Service](http://packetstormsecurity.com/files/127544/ACME-micro_httpd-Denial-Of-Service.html)
* [OSVDB 109356](http://osvdb.org/show/osvdb/109356) · [SecurityFocus BID 68746](http://www.securityfocus.com/bid/68746)
* [CVE-2010-1544 — NVD](https://nvd.nist.gov/vuln/detail/CVE-2010-1544) (RCA DCM425, same server)

**ACME family CVEs (thttpd / mini_httpd)**

* [Exploit-DB 33500 — thttpd/mini_httpd log command injection (CVE-2009-4490)](https://www.exploit-db.com/exploits/33500) · [BID 37714](http://www.securityfocus.com/bid/37714)
* [CVE-2017-17663 — cybersecurity-help.cz advisory](https://www.cybersecurity-help.cz/vdb/SB2018020704) · [ACME vendor update note](http://acme.com/updates/archive/199.html)
* [CVE-2018-18778 — Acunetix](https://www.acunetix.com/vulnerabilities/web/acme-mini_httpd-arbitrary-file-read/) · [Invicti](https://www.invicti.com/web-application-vulnerabilities/acme-mini-httpd-arbitrary-file-read)
* [CVE-2026-68005 — SentinelOne vulnerability DB](https://www.sentinelone.com/vulnerability-database/cve-2026-68005/)

**The device class (PTCL D-Link, `webproc` stack)**

* [`../README.md`](../README.md) — the bypass, the URLs, the session behavior
* [`findings.md`](./findings.md) — sourced device-class findings
* [CVE-2025-34048 — OpenCVE](https://app.opencve.io/cve/CVE-2025-34048) (CVSS 8.7, file read, in-the-wild 2025-02-04)
* [CVE-2019-1010155 — OpenCVE](https://app.opencve.io/cve/CVE-2019-1010155) (disputed)
* [CVE-2019-1010156 — GitHub Advisory GHSA-7w64-w8mx-grwj](https://github.com/advisories/GHSA-7w64-w8mx-grwj)
* [Exploit-DB 40735 — D-Link DSL-2730U/2750U/2750E remote file disclosure](https://www.exploit-db.com/exploits/40735)
* [Packet Storm 139637 — DSL-2750E SEA_1.07 remote file disclosure](https://packetstormsecurity.com/files/139637/D-Link-ADSL-Router-DSL-2750E-SEA_1.07-Remote-File-Disclosure.html)
* [CXSecurity WLB-2020070098 — Wi-Fi key leak PoC](https://cxsecurity.com/issue/WLB-2020070098) · [WLB-2018080199 — wizard page report](https://cxsecurity.com/issue/WLB-2018080199)
* [D-Link forum topic 66266 — PTCL DSL-2750U H/W D1 thread](http://forums.dlink.com/index.php?topic=66266.0)
* [PakGamers — PTCL DSL-2750U firmwares thread](https://pakgamers.com/index.php?threads%2Fptcl-dsl-2750u-firmwares.275428=)

**Tooling (this repo)**

* [`tools/ptcl_check.py`](../tools/ptcl_check.py) — read-only, GET-only, LAN-only detector
* [`tools/selftest_mock.py`](../tools/selftest_mock.py) — offline mock router for testing the detector
* [`tools/README.md`](../tools/README.md) — tool reference
