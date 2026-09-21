# PTCL D-Link `webproc` — auth bypass, and why the page stays open

Scope: D-Link DSL-series ADSL routers **as shipped by PTCL** (most commonly `DSL-2750U`,
also `DSL-2730U` / `DSL-2750E`), whose web UI is the Conexant `webproc` CGI.

---

## 1. The web stack

* Web server: small embedded HTTP daemon, CGI at **`/cgi-bin/webproc`**.
* A single CGI serves the whole UI. The URL tells it what to build:

  | parameter | meaning |
  |---|---|
  | `getpage` | the HTML template to load, e.g. `html/index.html` |
  | `errorpage` | template to render on failure |
  | `var:menu` | top-level nav section — `setup`, `status`, `advanced`, … |
  | `var:subpage` | page inside that section — `wizwl`, `wizentrance`, … |
  | `var:page` | renderer — `wizard` selects the wizard code path |
  | `var:language` | `en_us` etc. |

* Auth is a cookie named **`:sessionid`** (leading colon — not RFC-6265-legal, which is why
  cookie jars and some proxies mishandle it).
* Login itself is a `POST` to the same CGI carrying `:username`, `:password`, `:action=Login`.

## 2. Mechanism A — the wizard path skips the session check

`var:page=wizard` renders the setup-wizard templates. Those templates were written for
first-boot provisioning, i.e. **before any account exists**, so the handler does not consult
the session before rendering them — and it emits a `Set-Cookie: :sessionid=…` so the wizard
can continue across its five steps.

```
GET /cgi-bin/webproc?getpage=html/index.html&errorpage=html/index.html&var:language=en_us&var:menu=setup&var:subpage=wizentrance&var:page=wizard
```

Result: HTTP 200, wizard UI, `:sessionid` set, **no credentials ever supplied or checked.**

`var:subpage=wizwl` (wizard → wireless) is the more damaging variant, because the template is
populated from live config and emits the real values as page-local JS:

```js
var wireless_name = "…";
var randomWPAKEY  = "…";     // the actual WPA pre-shared key
```

They are then placed in `<input type="password">`, which hides them from the screen but not
from the document source, the DOM, or `view-source:`. A one-line `grep` over the response
(that is literally what the public PoC does) recovers the Wi-Fi password.

The five wizard steps are reachable too, and step 2 (Internet connection) writes config —
submit garbage there and you can knock the WAN link out. That is the denial-of-service half
of CVE-2019-1010155.

## 3. Mechanism B — why the page "keeps open"

Three things compound:

1. **A session is minted without authentication.** Mechanism A's `Set-Cookie: :sessionid=…`
   is a normal, fully-privileged session. Whoever triggered the request now holds one.
2. **It is never invalidated.** The CGI has no logout that removes the server-side entry, and
   no idle/absolute timeout is enforced on it. The entry lives in the daemon's memory until
   the router reboots.
3. **Nothing re-checks on navigation.** Subsequent `var:menu=…` requests are validated purely
   by cookie lookup. `index.html` does not re-prompt, and the browser keeps sending `:sessionid`
   because it has no `Max-Age`/`Expires` boundary either — it is a session cookie that outlives
   everything that should have ended it.

Net effect, matching what you observed: **open the URL once → the router UI is open, and it
stays open.** Closing the tab does not end it. Opening a new tab to `/` goes straight to the
dashboard because the cookie is still presented and still accepted.

> Diagnostic worth knowing: this is why "log in normally in a private window, then the normal
> window is *still* logged in, without ever having typed the password" happens. The session was
> never created by a login, so there is nothing to log out of.

## 4. Mechanism C — `getpage` traversal (the severe one)

`getpage` is not restricted to templates. `CVE-2025-34048` (CVSS 8.7, published 2025-06-26,
exploitation observed by Shadowserver on 2025-02-04) documents that a path in `getpage` is
served from the filesystem:

```
GET /cgi-bin/webproc?getpage=/etc/shadow&errorpage=html/main.html&var:menu=setup&var:page=wizard
```

This returns `/etc/shadow` — with **no authentication at all** — for DSL-2730U `IN_1.02` and
DSL-2750U / DSL-2750E `SEA_1.04` / `SEA_1.07`. The same primitive reads the config partition,
which contains the admin hash and, in plaintext on many builds, the ISP PPPoE credentials.

This is the mechanism that makes the bug stop being "a LAN annoyance".

## 5. Why PTCL units are a separate question

Retail firmware versions in the CVE lists (`IN_*`, `SEA_*`, `ME_*`) do **not** include PTCL's
ISP builds (`PT_2.00`, `K92_PTCL_R2005_20170510`, `GAN5.PT113A-B-DL-R5B015-PTB`). PTCL
customises the build for its own ACS/provisioning. That gives three possibilities, and only a
probe distinguishes them:

* PTCL build inherits the bug → likely, since the wizard code is upstream and these builds are
  older than the fixed retail ones;
* PTCL build removed/guarded the wizard → possible, they do customise `webproc`;
* PTCL rewrote the session handling → unlikely, there is no evidence of it.

D-Link's own position (their support forum) is that ISP firmware is out of scope and the
customer must go to the ISP. So no patch guarantee exists on either side.

## 6. What the checker does *not* do

`tools/ptcl_check.py` deliberately stops at **reachability**:

* no credential guessing, no brute force
* no config writes, no wizard submissions
* no dumping of `/etc/shadow` or of Wi-Fi keys — the Wi-Fi field is reported as
  `present/absent` with the value masked, and the traversal probe asks only for
  `/proc/version`
* no target outside RFC1918 / link-local

Verifying your own equipment and exfiltrating a neighbour's credentials are different acts;
this tool is built to be the first one.

## 7. Mitigation, in the order that actually helps

| Priority | Action |
|---|---|
| 1 | **Rotate the Wi-Fi PSK and the admin password.** Assume both are disclosed. |
| 2 | **Disable remote/WAN management** so the endpoint is not internet-reachable. |
| 3 | **Reboot the router** after any exposure — sessions live in memory only, so this is the one reliable way to kill a bypass-minted `:sessionid`. |
| 4 | **Ask PTCL for a current build** for your H/W revision. `D1`/`J1`/`T3` are not interchangeable; a mismatched image is rejected as `illegal image`. Keep offline copies of both PTCL and retail images before flashing anything. |
| 5 | **Take the unit out of the gateway role.** Bridge it, put a router you control behind it, and treat the PTCL box as hostile infrastructure. This is the only durable fix, and it is where the `../wr720n/` work would slot in. |

## 8. References

* CVE-2019-1010155 / CVE-2019-1010156 — DSL-2750U 1.11 wizard auth bypass (both **disputed**
  by D-Link; they argue the wizard cannot persist configuration)
* CVE-2025-34048 — DSL-2730U / DSL-2750U / DSL-2750E `getpage` path traversal, CVSS 8.7
* Exploit-DB 40735 — "D-Link DSL-2730U/2750U/2750E ADSL Router — Remote File Disclosure"
* Routersploit `dlink/dsl_2730_2750_path_traversal` — the module referenced by NVD for CVE-2025-34048
* CXSecurity WLB-2020070098 and WLB-2018080199 — the public wizard/Wi-Fi-key PoCs covering
  `ME_1.03`–`ME_1.11` and `IN_1.15`
* D-Link community forum, topic 23161 — earlier (2011) D-Link unauthenticated admin-page family:
  `http://192.168.0.1/bsc_lan.php?` on DIR-615revD / DIR-320 / DIR-300 — same class, same era
* D-Link support forum topic 66266 — DSL-2750U H/W `D1` PTCL, firmware `PT_2.00 20161209`,
  management IP `192.168.10.1`, and D-Link declining ISP-firmware support
