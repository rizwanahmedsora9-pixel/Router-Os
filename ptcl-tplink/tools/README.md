# PTCL TP-Link tools

These are standard-library-only Python 3 scripts for an authorized device on the local
network. They are inventory/read-only checks, not exploit implementations.

## `ptcl_tplink_check.py`

```bash
python3 ptcl_tplink_check.py 192.168.1.1
python3 ptcl_tplink_check.py 192.168.1.1 --probe-rom0
python3 ptcl_tplink_check.py 192.168.1.1 --model TL-WR840N --hardware V6 --firmware V6_260304
python3 ptcl_tplink_check.py 192.168.1.1 --json report.json
python3 ptcl_tplink_check.py 192.168.1.1 --urls
```

| flag | meaning |
|---|---|
| `--port N` | management HTTP port, default `80` |
| `--model TEXT` | optional label when the UI does not expose the model |
| `--hardware TEXT` | optional hardware revision from the sticker/status page |
| `--firmware TEXT` | optional complete firmware string from the status page |
| `--probe-rom0` | GET `/rom-0` once after the HEAD check; body is discarded and never decoded |
| `--timeout S` | per-request timeout, default `6.0` |
| `--json PATH` | write a sanitized report without response bodies |
| `--urls` | print safe endpoint references and make no network request |
| `-v`, `--verbose` | print method/path and status, never response bodies |

### Exit codes

* `0` — no confirmed vulnerable result, including `UNASSESSED` and unreachable devices;
* `1` — a confirmed exact match or binary-looking `/rom-0` exposure;
* `2` — target refused because it is not private/LAN-local.

The tool is intentionally conservative. `UNASSESSED` is more honest than turning a
retail/other-ISP advisory into a PTCL claim.

### Requests and safety boundaries

The default network requests are:

1. `GET /` to read the normal root page and headers; and
2. `HEAD /rom-0` to see whether an obvious backup endpoint exists.

`--probe-rom0` adds `GET /rom-0`. This may return an administrator/ISP configuration
backup. The checker holds it only long enough to determine status, content type, and size;
it never decodes, prints, stores, or serializes the body. Use that option only on your own
router. No request writes configuration.

The checker never sends:

* Misfortune Cookie crafted cookies;
* a DHCP hostname or XSS marker;
* ping/traceroute/IPv6/bridge-isolation inputs;
* a configuration import;
* a CLI brute-force attempt; or
* a WAN-side request.

Only RFC1918, link-local, unique-local, and loopback targets are accepted. A public
hostname or mixed public/private DNS answer is refused before a socket is opened.

## Findings the script can classify

The optional `--model`, `--hardware`, and `--firmware` values are labels supplied by the
operator; they are not sent to the device. The script recognizes these narrow boundaries:

* TL-WR840N v2/v3: TP-Link's CVE-2023-50224 advisory says unpatched;
* TL-WR840N v6 with an explicit older `V6_...` build: CVE-2026-3227 at risk; `V6_260304`
  is the listed fixed target;
* TD-W8961N v4 with an explicit pre-`V4_250925` branch: CVE-2025-15606 at risk;
* TD-W8961ND firmware `1.0.1`: the public DHCP-hostname XSS finding is reported as a
  conditional match, not actively tested; and
* TD-W9970/TD-W9970v3: the CVE-2023-6437 lead is left conditional unless an exact
  firmware/date match is visible.

A positive `/rom-0` response is always recorded as a sensitive configuration exposure,
regardless of model, because it is a direct observation rather than a CPE inference.

## `selftest_mock.py`

The mock binds to loopback by default and serves a fabricated root page and optional
`/rom-0` body. It is not a router and does not contact a device.

```bash
# vulnerable legacy-style fixture
python3 selftest_mock.py --port 8099 &
python3 ptcl_tplink_check.py 127.0.0.1 --port 8099 --probe-rom0
# expected: VERDICT: VULNERABLE, exit 1

# fixed-version fixture
python3 selftest_mock.py --port 8098 --secure \
  --model TL-WR840N --hardware V6 --firmware V6_260304 &
python3 ptcl_tplink_check.py 127.0.0.1 --port 8098
# expected: VERDICT: NOT VULNERABLE or UNASSESSED, exit 0
```

The mock's secret marker is `FAKE_ROM0_SECRET_DO_NOT_PRINT`; a correct checker must not
place it in terminal or JSON output.

## `--urls` reference

```text
http://ROUTER-IP/
http://ROUTER-IP/rom-0              (read-only backup endpoint; never decode blindly)
Server header: RomPager/...          (fingerprint only, not a proof by itself)
```

`--urls` does no DNS lookup and opens no socket.
