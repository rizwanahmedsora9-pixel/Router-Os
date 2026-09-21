# tools

Two standard-library-only Python 3 scripts. Nothing here writes to a router.

## `ptcl_check.py`

Read-only detector for the PTCL D-Link `webproc` authentication bypass, on the unit in
front of you.

```bash
python3 ptcl_check.py 192.168.10.1
python3 ptcl_check.py 192.168.1.1 --json ../research/check-2026-09-21.json
python3 ptcl_check.py 192.168.10.1 -v          # log every request
```

| flag | meaning |
|---|---|
| `--port N` | management port, default `80` |
| `--timeout S` | per-request timeout, default `6.0` |
| `--json PATH` | also write the raw result as JSON |
| `-v`, `--verbose` | print every request and response code |

**Exit codes:** `0` = not vulnerable · `1` = **vulnerable** (so it drops straight into a
script or cron job) · `2` = refused, the target is not on your LAN.

### What it checks

| # | check | symptom it maps to |
|---|---|---|
| 1 | baseline `GET /` returns a login form | sanity — the UI is where you think it is |
| 2 | wizard URL with no credentials | **"opens without login"** |
| 3 | `var wireless_name` / `var randomWPAKEY` in the source | credential disclosure |
| 4 | captured `:sessionid` replayed on protected pages | **"the page keeps open"** |
| 5 | `getpage=/proc/version` reachable unauthenticated | CVE-2025-34048 reachability |

### Design constraints (deliberate, not oversights)

* **GET only.** There is no code path in the file that issues a `POST`, submits a credential,
  or writes configuration. Check 5 asks for `/proc/version` and nothing else; a real file
  disclosure is *reported*, not *exploited*.
* **LAN only.** `resolve_private()` refuses any target that does not resolve into
  `10/8`, `172.16/12`, `192.168/16`, `169.254/16`, `fc00::/7`, `fe80::/10`, or loopback.
  A hostname is resolved first and judged on the resulting address, so DNS cannot be used
  to sneak past it.  `8.8.8.8` and `example.com` are both refused, with exit `2`.
* **Credentials are never printed.** SSID and WPA key are reported as
  `first_char***last_char (len=N)` in both console and JSON output. Verified by test: the
  literal key present in the mock's page does not appear anywhere in the JSON report.
* **Cookie names are handled verbatim.** The router's session cookie is `:sessionid` — a
  leading colon, which is not a legal RFC-6265 cookie name. Anything that routes cookies
  through a strict cookie jar silently drops it, which is why the raw `Set-Cookie` header is
  parsed by hand here.
* **Query strings are not percent-encoded.** The CGI expects the literal `var:menu=setup`
  form; encoding the colon to `var%3Amenu` changes the request and can make a vulnerable
  device look patched. The URLs are assembled to match the published PoCs exactly.

### Interpreting the output

* **`VULNERABLE`** — the wizard rendered with no credentials *and* the session it minted
  was still accepted on later requests. Both halves of the bug are present.
* **`PARTIAL`** — the wizard rendered, but the session was not honoured afterwards. The
  disclosure in check 3 still applies; treat the Wi-Fi key as exposed.
* **`NOT VULNERABLE`** — the wizard path demanded a login. This is the good outcome. It is
  a statement about *this build*, so re-run after any firmware change.
* **`UNREACHABLE`** — nothing was probed. Wrong IP, not on that network, or UI disabled.

Heads-up on check 3: it reports whether the *page source contains* the values. A device can
score `NOT VULNERABLE` on check 2 and still leak on check 3 if its wizard template is
populated but gated differently. Read the five checks individually rather than only the
headline verdict.

## `selftest_mock.py`

A local HTTP server that imitates a vulnerable PTCL D-Link `webproc` so the detector can be
validated without hardware. **It is a test fixture, not a router, and not an exploit** — it
binds to `127.0.0.1` and imitates *behaviour*, not a device.

```bash
python3 selftest_mock.py --port 8099 &          # vulnerable unit
python3 ptcl_check.py 127.0.0.1 --port 8099     # -> VERDICT: VULNERABLE, exit 1

python3 selftest_mock.py --port 8098 --secure & # patched unit
python3 ptcl_check.py 127.0.0.1 --port 8098     # -> VERDICT: NOT VULNERABLE, exit 0
```

Both directions are part of the test: a detector that can only ever answer "vulnerable" is
worthless, so `--secure` exists specifically to prove the negative path.

## Verified behaviour

Run against the mock on 2026-09-21 (`PT_2.00 20161209` / `DSL-2750U` fabricated by the fixture):

| case | result |
|---|---|
| vulnerable mock | `VULNERABLE`, exit `1`, all five checks positive |
| `--secure` mock | `NOT VULNERABLE`, exit `0`, session not minted, traversal refused |
| `8.8.8.8` | refused, exit `2`, before any socket is opened |
| `example.com` | resolved to a public IP, refused, exit `2` |
| `--json` report on a vulnerable target | real SSID and WPA key **absent** from the file |
| `py_compile` | both scripts clean on Python 3.11 |
