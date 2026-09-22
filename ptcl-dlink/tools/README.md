# tools

Three standard-library-only Python 3 scripts. Nothing here writes to a router.

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
| `--urls` | print every URL variant and **exit without probing anything** |
| `-v`, `--verbose` | print every request and response code |

**Exit codes:** `0` = not vulnerable · `1` = **vulnerable** (so it drops straight into a
script or cron job) · `2` = refused, the target is not on your LAN.

### Just want the URLs?

```bash
python3 ptcl_check.py 192.168.10.1 --urls
```

Prints the seven URL variants with your host substituted and exits. Makes **no network
requests at all** — verified against a dead port (`--port 1 --urls` exits `0` without a
connection attempt), so it is a safe quick reference to copy from.

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

## `micro_httpd_probe.py`

Read-only fingerprint of the **httpd front door on port 80** — the ACME Labs
`micro_httpd` / `thttpd` / `mini_httpd` family that serves the static layer in
front of `/cgi-bin/webproc` on the same port. This is the half of the web stack
that `ptcl_check.py` does not touch; the full write-up is in
[`../research/micro-httpd-report.md`](../research/micro-httpd-report.md).

```bash
python3 micro_httpd_probe.py 192.168.10.1                    # fingerprint only - zero risk
python3 micro_httpd_probe.py 192.168.10.1 --json report.json
python3 micro_httpd_probe.py 127.0.0.1 --port 8099           # against selftest_mock.py
python3 micro_httpd_probe.py 192.168.10.1 --dos              # LAST: long-URI DoS probe
```

| flag | meaning |
|---|---|
| `--port N` | management port, default `80` |
| `--timeout S` | per-request timeout, default `6.0` |
| `--json PATH` | also write the raw result as JSON |
| `--dos` | **also** run the staged long-URI probe (CVE-2014-4927 shape). Off by default because it can crash the admin UI on an unpatched ACME build. Refused, and not sent, when the banner is Boa |
| `-v`, `--verbose` | log every request |

**Exit codes:** `0` = not exposed / inconclusive · `1` = **exposed** (a known-vulnerable
ACME banner, or the DoS probe took the UI down) · `2` = refused, the target is not on your LAN.

### What it does

1. `GET /` — records the `Server:` banner (following one redirect if the build 302s to a
   login page) and confirms the UI is alive
2. `GET /cgi-bin/webproc` (a neutral device-info page) — confirms the CGI shares the port,
   without minting a session (the wizard URL is deliberately *not* used)
3. matches the banner against the ACME family table and lists the CVEs that apply to the
   reported version (`micro_httpd` any → CVE-2014-4927; `thttpd` → CVE-2009-4490 /
   CVE-2017-17663; `mini_httpd` → CVE-2017-17663 / CVE-2018-18778 / CVE-2026-68005)
4. **only with `--dos`:** staged long-URI GETs (`/` + 10 000 → 64 000 × `'A'`, each on a
   fresh connection), then a health check (`GET /`, twice) of whether the admin UI still
   answers

### Interpreting the output

* **`EXPOSED: … banner with applicable CVEs`** — the banner maps to a CVE in the table.
  Exposure is the only real control: keep port 80 off the WAN.
* **`EXPOSED: DoS confirmed`** — the long-URI probe stopped the UI answering. Power-cycle
  the router, then re-run to confirm it is back.
* **`NOT ACME` / Boa** — a `Boa/` banner is not micro_httpd. `--dos` is refused
  and must not be used; CVE-2014-4927 does not apply. Bug Hunter names
  CVE-2022-45956 from the banner only (no HEAD bypass is sent).
* **`BANNER UNKNOWN`** — the banner is not an ACME-family string. That is *inconclusive*,
  not clean: the banner simply cannot be mapped to the table. Only `--dos` tests that
  question directly.
* **`NO EXPOSURE FOUND: … survived the long-URI probe`** — surviving 64 000 chars is not
  proof of a patch (the crash length varies by build); it just means this box did not die
  at these lengths.

### Safety

* GET only, LAN only, same target policy as `ptcl_check.py` — public IPs are refused
  before any socket is opened.
* The long-URI probe is opt-in (`--dos` must be typed) because on an unpatched
  build it is the documented crash (CVE-2014-4927), not a read-only check.
* A mock never crashes, so `--dos` against `selftest_mock.py` just validates the plumbing.

### Verified behaviour

Run against `selftest_mock.py` on 2026-09-22:

| case | result |
|---|---|
| mock default banner (`Conexant/1.0`) | `BANNER UNKNOWN`, exit `0` |
| mock `--server "micro_httpd"` | `EXPOSED: micro_httpd banner…` (CVE-2014-4927), exit `1` |
| mock `--server "thttpd/2.25b"` | CVE-2009-4490 + CVE-2017-17663 listed, exit `1` |
| mock `--server "thttpd/2.30"` | `NO EXPOSURE FOUND` (version past the table), exit `0` |
| mock `--server "mini_httpd/1.29"` | CVE-2018-18778 + CVE-2026-68005 listed, exit `1` |
| `--dos` against mock | all four stages answered, health check `UP`, exit per banner verdict |
| `8.8.8.8` | refused, exit `2`, before any socket is opened |
| redirecting root (`302 → /login`) | history reported as `302 -> 200` |

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

`--server BANNER` overrides the `Server:` header the mock sends (default
`Conexant/1.0`), so the banner classification in `micro_httpd_probe.py` can be exercised
offline against every ACME family:

```bash
python3 selftest_mock.py --port 8099 --server "thttpd/2.25b" &
python3 micro_httpd_probe.py 127.0.0.1 --port 8099   # -> CVE-2009-4490 + CVE-2017-17663, exit 1
```

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
