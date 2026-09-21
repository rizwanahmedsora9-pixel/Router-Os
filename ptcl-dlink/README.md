# PTCL D-Link — "router opens without login, and the page keeps staying open"

> **This folder has nothing to do with `../wr720n/`.**
> `wr720n/` is a TP-Link TL-WR720N (VxWorks, `IMG0` container, Wind River web store).
> Everything here is **D-Link DSL-series on Conexant/`bcm` ADSL firmware, managed by the
> `/cgi-bin/webproc` CGI** — a different vendor, different SoC, different web stack,
> different bug. The two projects only share this git repository.

---

## 1. What was reported

Two symptoms, one root cause:

| # | What you see | What it actually is |
|---|---|---|
| **a** | You paste a URL into the browser and land **inside the router admin UI with no login prompt** | `/cgi-bin/webproc` serves "setup wizard" pages to **unauthenticated** requests. The session check is missing on that code path. |
| **b** | After that, **the router page "keeps open"** — you can navigate around and come back later without logging in | The bypassed request makes the router mint a `:sessionid` cookie **without ever validating a username/password**. That session is never invalidated and has no idle timeout, so the browser stays "logged in" indefinitely. |

(b) is not a second bug — it is the *consequence* of (a). The router hands out a fully
privileged session to anyone who asks for the wizard URL.

**Credibility note:** you do not need to guess the admin password. The router never checks it.

---

## 2. The URL

The management endpoint is `/cgi-bin/webproc`. It takes its page to render from the
`getpage` parameter and its navigation state from `var:` parameters.

**Minimal form — lands in the wizard, not the login page:**

```
http://<router-ip>/cgi-bin/webproc?getpage=html/index.html&var:menu=setup&var:page=wizard
```

**Full form — used in the published PoCs, drops you straight into the wizard entrance:**

```
http://<router-ip>/cgi-bin/webproc?getpage=html/index.html&errorpage=html/index.html&var:language=en_us&var:menu=setup&var:subpage=wizentrance&var:page=wizard
```

**Wireless-page form — this is the one that leaks the Wi-Fi name + WPA key as cleartext
JavaScript variables (`var wireless_name`, `var randomWPAKEY`) that the page then hides
behind an `<input type="password">`:**

```
http://<router-ip>/cgi-bin/webproc?getpage=html/index.html&errorpage=html/index.html&var:language=en_us&var:menu=setup&var:subpage=wizwl&var:page=wizard
```

`<router-ip>` is whatever your PTCL unit answers on — PTCL-shipped builds commonly use
**`192.168.10.1`** (also seen: `192.168.1.1`). Check the sticker on the bottom of the unit.

> ⚠️ **I could not see a URL in your message.** Your note said *"check that url"*, but the
> message you sent contained no link or address — only the description. The URLs above are
> the known PTCL/D-Link bypass URLs from published research. **If you meant one specific URL
> you had in your clipboard, paste it and I'll check it against this analysis.**

---

## 3. Is *your* unit affected?

Published CVEs against this web stack list **retail** firmware builds:

| CVE | What | Affected builds |
|---|---|---|
| **CVE-2019-1010155** | DSL-2750U — wizard reachable without auth (info leak / DoS) | `1.11` |
| **CVE-2019-1010156** | DSL-2750U — same, framed as auth bypass in the login form | `1.11` |
| **CVE-2025-34048** | `getpage` **path traversal** → unauthenticated arbitrary file read (e.g. `/etc/shadow`). CVSS 8.7 | DSL-2730U `IN_1.02`, DSL-2750U / DSL-2750E `SEA_1.04`, `SEA_1.07` |
| CVE-2019-1010155 (disputed) | D-Link argues the wizard "can't actually configure anything" | — |

**PTCL does not ship retail D-Link firmware.** PTCL units run ISP builds (`PT_2.00`,
`K92_PTCL_R2005_20170510`, `GAN5.PT113A-B-DL-R5B015-PTB`, …) on H/W revisions `D1`, `J1`, `T3`.
Those build strings appear in **none** of the CVE affected-version lists, so:

* PTCL builds are **not confirmed vulnerable and not confirmed patched** — they are simply
  never tested by the researchers. The upstream code is the same Conexant web stack, and in
  practice these ISP builds are *older*, not newer.
* D-Link explicitly refuses support for ISP-branded firmware and points you back at PTCL.

**The only way to know is to probe your own unit.** That is what the tool below does.

---

## 4. Tool — `tools/ptcl_check.py`

Read-only, **GET-only**, **LAN-only** checker. It does not log in, does not change a single
setting, and does not dump secrets — it tells you which of the symptoms above your unit has.

```bash
cd ptcl-dlink

python3 tools/ptcl_check.py 192.168.10.1
python3 tools/ptcl_check.py 192.168.1.1 --json research/check-$(date +%F).json
```

What it probes, in order:

1. **baseline** — `GET /`, records whether you get the login form (expected) or a redirect
2. **wizard bypass** — the `var:menu=setup&var:page=wizard` URL, classified as *served* vs *bounced to login*
3. **wifi leak** — looks for `var wireless_name` / `var randomWPAKEY` in the response and reports
   **whether the field exists**, masking the value (first/last char only)
4. **session persistence** — takes whatever `:sessionid` the unauthenticated response set, replays
   it against a protected page, and reports whether the device treats you as logged in
   → this is the machine-checkable form of **"the page keeps open"**
5. **traversal reachability** — requests `getpage=/proc/version` only, reporting *whether the read
   succeeds*, not the contents of anything sensitive

It refuses targets outside `10/8`, `172.16/12`, `192.168/16`, `169.254/16` by design — this is a
tool for checking the box in your own house, not someone else's.

**Verdicts:** `VULNERABLE` · `PARTIAL` · `NOT VULNERABLE` · `UNREACHABLE`

### Proving the tool works without touching hardware

`tools/selftest_mock.py` is a local stand-in that imitates a PTCL D-Link webproc: it serves the
login page normally, but leaks the wizard + Wi-Fi key and mints a session when the bypass URL is
used. Point the checker at it to confirm the detection logic before you point it at the router:

```bash
python3 tools/selftest_mock.py --port 8099 &     # local mock, no hardware
python3 tools/ptcl_check.py 127.0.0.1 --port 8099
```

---

## 5. What to do about it

Nothing here needs the router to be reflashed. In order of effort:

1. **Change the Wi-Fi PSK and the admin password** — anything the wizard page rendered was
   readable by anyone on your LAN (or by any web page your browser loaded, via CSRF).
2. **Disable WAN-side / remote management.** If the admin UI is reachable from the internet,
   this stops being a LAN problem. Check *Advanced → Remote Management* and disable it.
3. **Update the firmware — from PTCL, not D-Link.** D-Link will not support a PTCL unit. Ask
   PTCL for the current build for your H/W revision (`D1`/`J1`/`T3` are *not* cross-flashable;
   flashing the wrong revision returns `illegal image`).
4. **Treat the router as untrusted infrastructure.** A device that ships unauthenticated admin
   endpoints is not going to be fixed by PTCL. The durable fix is to put your own router behind
   it (bridge/modem mode) and stop using the PTCL unit as a gateway — which is also what makes
   the separate `../wr720n/` work relevant to you.
5. **Make the "keeps open" symptom stop right now:** close *all* tabs on the router UI, clear
   cookies for the router's IP, then reopen `/`. If the UI still lets you in without a password,
   you are looking at the bug, not a cached page.

---

## 6. Layout

```
ptcl-dlink/
├── README.md                  ← you are here
├── notes/
│   └── auth-bypass.md         technical writeup: the two mechanisms, evidence, why it persists
├── tools/
│   ├── ptcl_check.py          read-only LAN detector  (stdlib only)
│   ├── selftest_mock.py       local mock router, so the detector can be tested offline
│   └── README.md              tool reference
└── research/
    └── findings.md            sourced one-page summary + links
```
