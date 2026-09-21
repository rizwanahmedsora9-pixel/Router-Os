# PTCL ZTE tools

The tools are standard-library-only Python 3 scripts. They are for an authorized device
on the local network; they are not exploit code.

## `ptcl_zte_check.py`

```bash
python3 ptcl_zte_check.py 192.168.1.1
python3 ptcl_zte_check.py 192.168.1.1 --probe-upnp
python3 ptcl_zte_check.py 192.168.1.1 --probe-upnp --json zte-report.json
python3 ptcl_zte_check.py 192.168.1.1 --urls
```

| flag | meaning |
|---|---|
| `--port N` | management HTTP port, default `80` |
| `--upnp-port N` | H168N UPnP HTTP port, default `52869` |
| `--probe-upnp` | make one read-only `GetSecurityKeys` request; without it no SOAP request is sent |
| `--timeout S` | per-request timeout, default `6.0` |
| `--json PATH` | write a sanitized JSON report; no response body or key is written |
| `--urls` | print the model-specific endpoints and exit without a network request |
| `-v`, `--verbose` | print request method/path and status, never response bodies |

### Exit codes

* `0` — no confirmed finding by the checks that ran, or the target was unreachable;
* `1` — a confirmed vulnerable firmware match or an anonymous WLAN-key response;
* `2` — target refused because it is not private/LAN-local.

Exit `0` is not a universal security guarantee. An unrecognized firmware suffix,
closed UPnP port, timeout, or an untested operator image is reported as `UNASSESSED` in
the report.

### Exactly what is sent

The default mode sends only `GET /` to the HTTP management port. `--probe-upnp` adds a
single `POST /control/igd/wlanc_1_1` containing the documented `GetSecurityKeys` SOAP
action. That action is read-only from the router's configuration perspective, but a
vulnerable response contains WLAN security material. The checker:

* does not print the response body;
* does not save the response body or a key in JSON;
* only records status, response length, and whether known key-field tags were present;
* never sends `SetSecurityKeys`; and
* never sends brute-force, CSRF, malformed-input, firmware-upload, or configuration-write
  requests.

Only RFC1918, link-local, unique-local, and loopback targets are accepted. This is a
local safety boundary, not permission to probe someone else's network.

## `selftest_mock.py`

The fixture binds to loopback by default and starts a web server plus a separate UPnP
server. It contains a fabricated key only to prove that the checker masks/discards it.

```bash
# vulnerable fixture
python3 selftest_mock.py --port 8099 --upnp-port 8100 &
python3 ptcl_zte_check.py 127.0.0.1 --port 8099 --upnp-port 8100 --probe-upnp
# expected: VERDICT: VULNERABLE, exit 1

# fixed/denied fixture
python3 selftest_mock.py --port 8098 --upnp-port 8101 --secure &
python3 ptcl_zte_check.py 127.0.0.1 --port 8098 --upnp-port 8101 --probe-upnp
# expected: VERDICT: NOT VULNERABLE or UNASSESSED, exit 0
```

The mock's vulnerable root reports `V2.2.0_PK1.2T5`; its secure root reports
`V2.2.0_PK1.2T6`. The mock rejects `SetSecurityKeys` so the fixture itself cannot change
a setting.

## `--urls` reference

This is a no-network quick reference:

```text
http://ROUTER-IP/
http://ROUTER-IP:52869/control/igd/wlanc_1_1
SOAP action: dslforum-org:service:WLANConfiguration:1#GetSecurityKeys
```

The second line is an endpoint reference, not a browser URL that will perform the SOAP
request by itself.
