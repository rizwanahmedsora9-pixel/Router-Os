#!/usr/bin/env python3
"""
Bug Hunter v2.0 — Cross-Platform Router Vulnerability Scanner
=============================================================

Detects connected router/gateway on WiFi/LAN and scans for known vulnerabilities,
security misconfigurations, and exposures.  Generates a detailed report with:
  - Discovered vulnerabilities and their severity
  - CVE references and source URLs
  - Detailed descriptions of each finding
  - Step-by-step fix/remediation methods

v2.0 adds the real-audit layers on top of the v1 read-only hunt:
  * WiFi/LAN auto-discovery  (--auto, --discover): SSID context, subnet sweep,
    router-candidate ranking, automatic fallback when the gateway guess is wrong
  * Credentialed HTTP audit  (--username/--password): Basic/Digest/form login
    with the OWNER's creds, then post-login enumeration (real firmware, WAN,
    DNS, WPS, remote-mgmt state) — no guessing, no brute force
  * Credentialed shell audit (--shell telnet|ssh): read-only enumeration over
    an owner-credentialed shell (uid/kernel/MTD), optional low-level MTD dump
    (--dump-mtd) decoded + hashed locally
  * Offline firmware analysis (--analyze-firmware FILE): magic scan, entropy
    profile, redacted secret/indicator scan of a local .bin/MTD dump
  * 18-vendor fingerprinting, confidence labels (CONFIRMED/LIKELY), SNMP/DNS
    UDP probes, Winbox exposure check

PHYSICAL AUDIT MODE (the real hunt — this is the primary use):
  The scanner always probes the live, physical device on your LAN.
  `--audit` runs the full hunt and files it like an audit: the report is
  saved to `audits/` stamped with the unit's model and the UTC time, and
  the next run automatically diffs against the previous audit (new /
  resolved / persistent findings).  Feed it the sticker off the bottom of
  the unit so the audit is anchored to the physical box:

    python3 bug_hunter.py 192.168.10.1 --audit \\
        --model DSL-226 --firmware PT_1.10_J2 --hw J2 \\
        --serial <serial on sticker> --mac <mac on sticker>

  The label identity is cross-checked against what the device reports about
  itself; mismatches are flagged in the report.  Secrets are never printed.

PLATFORMS:  Windows, Linux, macOS, Termux (Android), FreeBSD — any device
            with Python 3.8+ and a network connection.

NO EXTERNAL DEPENDENCIES — uses Python standard library only.

SAFETY PROPERTIES:
  * GET/HEAD only — no POST, no config writes, no credential submission
  * Private/LAN addresses only — refuses public IPs
  * Never prints recovered secrets (WiFi keys, passwords)
  * Read-only fingerprinting — does not brute-force or exploit
  * dnscfg.cgi probe (CVE-2026-0625) is reachability-only: a bare GET,
    no DNS parameters, no injection payload is ever sent
  * A Boa/0.94.x banner is recorded as exposure only. No HEAD auth-bypass
    and no path-traversal request is ever sent
  * TCP 5555 is not reported as a confirmed ADB shell unless a service
    banner says so. No ADB handshake is sent

USAGE:
  python bug_hunter.py                    # auto-detect gateway, scan, report
  python bug_hunter.py 192.168.1.1        # scan specific IP
  python bug_hunter.py --audit            # physical audit, saved + drift diff
  python bug_hunter.py --report out.txt   # save report to file
  python bug_hunter.py --quick            # fast scan (skip slow probes)
  python bug_hunter.py --probe-upnp       # enable UPnP probes
  python bug_hunter.py --probe-rom0       # enable rom-0 config backup check
  python bug_hunter.py --json out.json    # save JSON report
  python bug_hunter.py --vendor dlink     # force vendor detection
"""

from __future__ import annotations

import argparse
import getpass
import http.client
import ipaddress
import json
import os
import platform
import re
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# --------------------------------------------------------------------------- #
# Version & Banner
# --------------------------------------------------------------------------- #

VERSION = "2.0.0"
BANNER = r"""
 ____              _   _       _   _             _
| __ )  ___  __ _ | | | |_   _| |__ | |_ ___  _ __| |_
|  _ \ / _ \/ _` || |_| | | | | '_ \| __/ _ \| '__| __|
| |_) |  __/ (_| ||  _  | |_| | |_) | || (_) | |  | |_
|____/ \___|\__, ||_| |_|\__,_|_.__/ \__\___/|_|   \__|
            |___/
 Router Vulnerability Scanner v{version}
 Physical-Device Audit | Auto-Discovery | Credentialed Deep Audit
""".format(version=VERSION)

# v2 companion modules (same directory). The core scanner still runs
# standalone if they are missing; deep-audit flags then print guidance.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import discovery as _discovery_mod  # noqa: F401
except ImportError:
    _discovery_mod = None  # type: ignore
try:
    import auth_audit as _auth_mod  # noqa: F401
except ImportError:
    _auth_mod = None  # type: ignore
try:
    import shell_audit as _shell_mod  # noqa: F401
except ImportError:
    _shell_mod = None  # type: ignore
try:
    import firmware as _fw_mod  # noqa: F401
except ImportError:
    _fw_mod = None  # type: ignore

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

ALLOWED_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
]

COMMON_GATEWAY_IPS = [
    "192.168.1.1", "192.168.0.1", "192.168.10.1", "192.168.100.1",
    "192.168.2.1", "192.168.0.254", "192.168.1.254", "10.0.0.1",
    "10.0.0.138", "172.16.0.1", "192.168.50.1",
]

COMMON_PORTS = [
    (21, "FTP"),
    (22, "SSH"),
    (23, "Telnet"),
    (53, "DNS"),
    (80, "HTTP"),
    (443, "HTTPS"),
    (8080, "HTTP-Alt"),
    (8443, "HTTPS-Alt"),
    (161, "SNMP"),
    (162, "SNMP-Trap"),
    (554, "RTSP"),
    (1900, "UPnP/SSDP"),
    (52869, "UPnP-WLAN"),
    (34567, "DDNS"),
    (7547, "TR-069/CWMP"),
    # 5555 is ADB on some Android boxes and an unrelated debug/management
    # port on many DSL CPEs. The label stays neutral; the finding decides.
    (5555, "TCP 5555"),
    # v2: extra management planes seen across vendors.
    (8000, "HTTP-Alt2"),
    (8081, "HTTP-Alt3"),
    (1723, "PPTP-VPN"),
    (8291, "MikroTik-Winbox"),
    (8728, "MikroTik-API"),
    (8089, "HTTP-Alt4"),
]

# Severity levels
SEV_CRITICAL = "CRITICAL"
SEV_HIGH = "HIGH"
SEV_MEDIUM = "MEDIUM"
SEV_LOW = "LOW"
SEV_INFO = "INFO"

# --------------------------------------------------------------------------- #
# Platform Detection
# --------------------------------------------------------------------------- #

def describe_platform(system: str, machine: str,
                      env: Optional[Dict[str, str]] = None,
                      android_fs: bool = False) -> str:
    """Format a platform string.

    Termux's Python often reports ``platform.system() == 'Android'`` rather
    than ``'Linux'``. A field run on 2026-09-22 printed ``android (aarch64)``
    and then skipped the Linux ``ip route`` lookup. Both the label and the
    route lookup treat Android as Termux.
    """
    system_l = (system or "").lower()
    machine_l = (machine or "unknown").lower()
    env = os.environ if env is None else env
    if system_l in ("linux", "android"):
        if (system_l == "android" or android_fs
                or "ANDROID_ROOT" in env or "TERMUX_VERSION" in env):
            return f"Termux/Android ({machine_l})"
        return f"Linux ({machine_l})"
    if system_l == "freebsd":
        return f"FreeBSD ({machine_l})"
    return f"{system_l or 'unknown'} ({machine_l})"


def detect_platform() -> str:
    """Return a human-readable platform string."""
    system = platform.system()
    system_l = system.lower()
    machine = platform.machine().lower()
    if system_l == "windows":
        return f"Windows {platform.version()}"
    if system_l == "darwin":
        return f"macOS {platform.mac_ver()[0]} ({machine})"
    return describe_platform(
        system, machine,
        env=os.environ,
        android_fs=os.path.isdir("/data/data"),
    )


# --------------------------------------------------------------------------- #
# Gateway Detection
# --------------------------------------------------------------------------- #

def get_default_gateway() -> Optional[str]:
    """Detect the default gateway IP across platforms."""
    system = platform.system().lower()

    # Termux/Android Python reports system == "android", but `ip route` is
    # the same tool. Falling through here used to skip the route table and
    # guess "<local-subnet>.1" instead.
    if system in ("linux", "android", "darwin", "freebsd"):
        try:
            output = subprocess.check_output(
                ["ip", "route", "show", "default"],
                stderr=subprocess.DEVNULL,
                timeout=5
            ).decode("utf-8", "replace")
            # Parse: default via 192.168.1.1 dev wlan0 ...
            match = re.search(r"default\s+via\s+(\S+)", output)
            if match:
                return match.group(1)
        except (subprocess.SubprocessError, FileNotFoundError):
            pass

        # Fallback: route command (macOS, older Linux)
        try:
            output = subprocess.check_output(
                ["route", "-n", "get", "default"],
                stderr=subprocess.DEVNULL,
                timeout=5
            ).decode("utf-8", "replace")
            match = re.search(r"gateway:\s*(\S+)", output)
            if match:
                return match.group(1)
        except (subprocess.SubprocessError, FileNotFoundError):
            pass

        # Termux/Android: ip route
        try:
            output = subprocess.check_output(
                ["ip", "route"],
                stderr=subprocess.DEVNULL,
                timeout=5
            ).decode("utf-8", "replace")
            match = re.search(r"default\s+via\s+(\S+)", output)
            if match:
                return match.group(1)
        except (subprocess.SubprocessError, FileNotFoundError):
            pass

    elif system == "windows":
        try:
            output = subprocess.check_output(
                ["ipconfig"],
                stderr=subprocess.DEVNULL,
                timeout=5
            ).decode("utf-8", errors="replace")
            match = re.search(r"Default Gateway[.:]\s*(\S+)", output, re.I)
            if match:
                return match.group(1)
        except (subprocess.SubprocessError, FileNotFoundError):
            pass

        # Fallback: netstat
        try:
            output = subprocess.check_output(
                ["netstat", "-r"],
                stderr=subprocess.DEVNULL,
                timeout=5
            ).decode("utf-8", errors="replace")
            match = re.search(r"0\.0\.0\.0\s+0\.0\.0\.0\s+(\S+)", output)
            if match:
                return match.group(1)
        except (subprocess.SubprocessError, FileNotFoundError):
            pass

    return None


def get_local_ip() -> Optional[str]:
    """Get this device's local IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        # Doesn't actually send data — just gets the local address for routing
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None


def get_network_info() -> Dict[str, Any]:
    """Gather information about the current network connection."""
    info: Dict[str, Any] = {
        "platform": detect_platform(),
        "local_ip": None,
        "gateway": None,
        "hostname": None,
    }

    info["local_ip"] = get_local_ip()
    info["gateway"] = get_default_gateway()
    try:
        info["hostname"] = platform.node() or socket.gethostname()
    except Exception:
        info["hostname"] = "unknown"

    # If gateway detection failed, try common IPs
    if not info["gateway"]:
        if info["local_ip"]:
            # Try the .1 address of our subnet
            parts = info["local_ip"].split(".")
            if len(parts) == 4:
                parts[3] = "1"
                candidate = ".".join(parts)
                if is_port_open(candidate, 80, timeout=2):
                    info["gateway"] = candidate
                    return info

        # Brute-force common gateway addresses
        for ip in COMMON_GATEWAY_IPS:
            if is_port_open(ip, 80, timeout=1):
                info["gateway"] = ip
                return info

    return info


# --------------------------------------------------------------------------- #
# Low-Level Network Utilities
# --------------------------------------------------------------------------- #

def resolve_private(host: str) -> Optional[str]:
    """Resolve host to a LAN-local address; return None if public."""
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return None
    if not infos:
        return None

    for info in infos:
        raw = info[4][0]
        try:
            addr = ipaddress.ip_address(raw.split("%", 1)[0])
        except ValueError:
            continue
        if any(addr in net for net in ALLOWED_NETS):
            return str(addr)
    return None


def is_port_open(host: str, port: int, timeout: float = 3.0) -> bool:
    """Check if a TCP port is open."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((host, port))
        s.close()
        return result == 0
    except (socket.error, OSError):
        return False


def scan_ports(host: str, ports: List[Tuple[int, str]], timeout: float = 2.0) -> List[Dict]:
    """Scan multiple ports concurrently. Returns list of open ports."""
    open_ports: List[Dict] = []

    def _check(port: int, name: str):
        if is_port_open(host, port, timeout):
            open_ports.append({"port": port, "service": name})

    threads = []
    for port, name in ports:
        t = threading.Thread(target=_check, args=(port, name))
        t.daemon = True
        threads.append(t)
        t.start()

    for t in threads:
        t.join(timeout + 2)

    open_ports.sort(key=lambda x: x["port"])
    return open_ports


# --------------------------------------------------------------------------- #
# HTTP Client (minimal, transparent)
# --------------------------------------------------------------------------- #

class HttpResponse:
    def __init__(self, status: int, headers: list, body: bytes):
        self.status = status
        self.headers = headers
        self.body = body

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")

    def header(self, name: str) -> Optional[str]:
        for k, v in self.headers:
            if k.lower() == name.lower():
                return v
        return None

    def set_cookies(self) -> Dict[str, str]:
        jar = {}
        for k, v in self.headers:
            if k.lower() != "set-cookie":
                continue
            pair = v.split(";", 1)[0].strip()
            if "=" in pair:
                name, _, value = pair.partition("=")
                jar[name.strip()] = value.strip()
        return jar


def router_ssl_context() -> "ssl.SSLContext":
    """TLS context for fingerprinting a router that ships a self-signed cert.

    Hostname and certificate are not verified — CPE admin ports almost never
    present a publicly trusted cert. No credentials are attached to the context.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1
    except (AttributeError, ValueError):
        # OpenSSL build has TLS 1.0 compiled out. Default minimum still works
        # for anything modern; ancient CPE will just fail the fingerprint.
        pass
    return ctx


class HttpClient:
    def __init__(self, host: str, port: int = 80, timeout: float = 8.0,
                 verbose: bool = False, tls: bool = False):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.verbose = verbose
        self.tls = tls
        self.cookies: Dict[str, str] = {}
        self.server_header: Optional[str] = None
        self.www_authenticate: Optional[str] = None
        self.response_body_max = 64 * 1024  # 64KB max body read
        self._ssl_context = router_ssl_context() if tls else None

    def origin(self) -> str:
        """Scheme/host/port for report URLs. Default ports are omitted."""
        scheme = "https" if self.tls else "http"
        if (self.tls and self.port == 443) or (not self.tls and self.port == 80):
            return f"{scheme}://{self.host}"
        return f"{scheme}://{self.host}:{self.port}"

    def _connect(self):
        if self.tls:
            return http.client.HTTPSConnection(
                self.host, self.port, timeout=self.timeout,
                context=self._ssl_context,
            )
        return http.client.HTTPConnection(self.host, self.port,
                                           timeout=self.timeout)

    def _note_headers(self, resp: HttpResponse) -> None:
        if not self.server_header:
            server = resp.header("Server")
            if server:
                self.server_header = server
        if not self.www_authenticate:
            auth = resp.header("WWW-Authenticate")
            if auth:
                self.www_authenticate = auth

    def get(self, path: str, use_cookies: bool = True,
            extra_headers: Optional[Dict] = None) -> Optional[HttpResponse]:
        """Send a GET request. Returns None on connection failure."""
        conn = None
        try:
            conn = self._connect()
            headers = {
                "User-Agent": f"BugHunter/{VERSION} (read-only LAN audit)",
                "Accept": "text/html,application/xhtml+xml,*/*",
                "Connection": "close",
            }
            if use_cookies and self.cookies:
                headers["Cookie"] = "; ".join(
                    f"{k}={v}" for k, v in self.cookies.items())
            if extra_headers:
                headers.update(extra_headers)

            if self.verbose:
                print(f"    -> GET {self.origin()}{path}")

            conn.request("GET", path, headers=headers)
            raw = conn.getresponse()
            body = raw.read(self.response_body_max)

            if not self.server_header:
                for k, v in raw.getheaders():
                    if k.lower() == "server":
                        self.server_header = v
                        break

            resp = HttpResponse(raw.status, raw.getheaders(), body)
            self._note_headers(resp)
            # Collect cookies
            new_cookies = resp.set_cookies()
            if new_cookies:
                self.cookies.update(new_cookies)
            return resp
        except (OSError, http.client.HTTPException) as exc:
            if self.verbose:
                print(f"    !! {type(exc).__name__}: {exc}")
            return None
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass

    def head(self, path: str) -> Optional[HttpResponse]:
        """Send a HEAD request.

        Not used to test Boa CVE-2022-45956. That CVE is a Basic-auth bypass
        on HEAD; sending it against a protected path would be the bypass.
        The only caller is the TP-Link ``/rom-0`` existence check.
        """
        conn = None
        try:
            conn = self._connect()
            headers = {
                "User-Agent": f"BugHunter/{VERSION} (read-only LAN audit)",
                "Accept": "*/*",
                "Connection": "close",
            }
            conn.request("HEAD", path, headers=headers)
            raw = conn.getresponse()
            raw.read()  # drain
            return HttpResponse(raw.status, raw.getheaders(), b"")
        except (OSError, http.client.HTTPException):
            return None
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass


# --------------------------------------------------------------------------- #
# Vendor Fingerprinting
# --------------------------------------------------------------------------- #

TAG_RE = re.compile(r"<[^>]*>")


def strip_tags(html: str) -> str:
    return re.sub(r"\s+", " ", TAG_RE.sub(" ", html))


LOGIN_FORM_RE = re.compile(
    r'name\s*=\s*["\']?:password'
    r'|:action\s*=\s*["\']?Login'
    r'|Username\s+or\s+Password'
    r'|pwdLogin'
    r'|login_password',
    re.I,
)


def looks_like_login(text: str) -> bool:
    return bool(LOGIN_FORM_RE.search(text))



# Neutral device-info request. Login is demanded; no wizard session is minted.
NEUTRAL_WEBPROC = (
    "/cgi-bin/webproc?getpage=html/index.html&errorpage=html/index.html"
    "&var:language=en_us&var:menu=status&var:page=deviceinfo"
)

ACME_BANNER_RE = re.compile(r"micro[-_]?httpd|thttpd|mini[-_]?httpd", re.I)
# Group 1 is the version when the banner is "Boa/0.94.13".
BOA_BANNER_RE = re.compile(r"\bBoa(?:/([0-9][0-9A-Za-z.]*))?", re.I)
AUTH_REALM_RE = re.compile(
    r"""realm\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s,]+))""",
    re.I,
)


def parse_www_authenticate(header: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    """Split a WWW-Authenticate header into (scheme, realm). No credentials."""
    if not header or not str(header).strip():
        return None, None
    raw = str(header).strip()
    scheme = raw.split(None, 1)[0]
    match = AUTH_REALM_RE.search(raw)
    realm = None
    if match:
        realm = next((group for group in match.groups() if group), None)
    return scheme, realm


def strip_probe_echo(text: str, paths: List[str]) -> str:
    """Remove this scanner's own request URLs from an error page.

    Boa and many tiny httpds echo the request line into a 401/404 body.
    That echo contains ``webproc`` because we asked for it — it is not
    evidence the CGI exists.
    """
    cleaned = text or ""
    for path in paths:
        if not path:
            continue
        cleaned = cleaned.replace(path, " ")
        cleaned = cleaned.replace(path.replace("&", "&amp;"), " ")
    return cleaned


def response_signal(resp: Optional["HttpResponse"], path: str) -> str:
    """Body text that is safe to feed to vendor detection."""
    if resp is None:
        return ""
    raw = resp.text or ""
    cleaned = strip_probe_echo(raw, [path])
    # A stock reject that only echoed the probe is not a vendor page.
    if resp.status in (400, 401, 403, 404, 500, 501) and not looks_like_login(raw):
        cleaned = re.sub(r"/cgi-bin/webproc|\bwebproc\b", " ", cleaned, flags=re.I)
    return cleaned


def webproc_evidence_from(resp: Optional["HttpResponse"], path: str) -> bool:
    """True only when /cgi-bin/webproc looks like the Conexant CGI.

    A 401/403/404 whose body is a stock error page — or that body with the
    probe URL removed — is not evidence. A login form, a 200 page, or a
    residual ``webproc`` / ``:sessionid`` / ``Conexant`` string is.
    """
    if resp is None or resp.status == 404:
        return False
    raw = resp.text or ""
    if resp.status in (400, 401, 403, 500, 501) and not looks_like_login(raw):
        return False
    residual = strip_probe_echo(raw, [path])
    if re.search(r"\bwebproc\b|conexant|:sessionid", residual, re.I):
        return True
    if (resp.status == 200 and "not found" not in residual.lower()
            and len(residual.strip()) > 80):
        return True
    return False


def classify_http_identity(base_resp: Optional["HttpResponse"],
                           wp_resp: Optional["HttpResponse"],
                           wp_path: str,
                           server_header: Optional[str]) -> Dict[str, Any]:
    """Vendor + auth facts from one origin, with probe-echo stripped."""
    scheme = realm = None
    for resp in (base_resp, wp_resp):
        if resp is None:
            continue
        got_scheme, got_realm = parse_www_authenticate(
            resp.header("WWW-Authenticate"))
        if got_scheme and not scheme:
            scheme = got_scheme
        if got_realm and not realm:
            realm = got_realm
    evidence = (webproc_evidence_from(wp_resp, wp_path)
                or webproc_evidence_from(base_resp, "/"))
    text = (response_signal(base_resp, "/") + "\n"
            + response_signal(wp_resp, wp_path))
    if realm:
        # Realm is the one vendor string a 401 page is allowed to contribute.
        text += "\n" + realm
    vendor = detect_vendor(text, server_header, webproc_reachable=evidence)
    return {
        "vendor": vendor,
        "text": text,
        "webproc_evidence": evidence,
        "auth_scheme": scheme,
        "auth_realm": realm,
        "http_status": base_resp.status if base_resp else None,
    }


def annotate_missing_model(fingerprint: Dict, vendor: str) -> None:
    """Fill a model note without inventing an ACME/D-Link stack.

    The 2026-09-22 field scan printed "D-Link DSL-series (inferred)" and a
    note about /cgi-bin/webproc + ACME httpd while the Server banner was
    Boa/0.94.13 and the body was a 401. That inference is only valid when
    both the CGI and the ACME banner were actually seen.
    """
    if fingerprint.get("model"):
        return
    server = fingerprint.get("server_header") or ""
    webproc = bool(fingerprint.get("webproc_evidence"))
    if vendor == "dlink" and ACME_BANNER_RE.search(server) and webproc:
        fingerprint["model"] = "D-Link DSL-series (inferred)"
        fingerprint["model_note"] = (
            "no model string visible in the UI; inferred from a real "
            "/cgi-bin/webproc response plus an ACME httpd banner (the "
            "Conexant DSL stack some PTCL D-Link units ship with). Pass "
            "--model/--firmware/--hw from the sticker to anchor the audit."
        )
        return
    if vendor == "dlink" and webproc:
        fingerprint["model"] = "D-Link/Conexant webproc (inferred)"
        fingerprint["model_note"] = (
            "webproc answered, but the UI showed no model string and the "
            f"Server banner is '{server or 'absent'}' — not ACME micro_httpd. "
            "Pass --model/--firmware/--hw from the sticker."
        )
        return
    if vendor == "dlink":
        fingerprint["model_note"] = (
            "vendor matched (page text or auth realm) but no model string "
            "was visible. Pass --model from the sticker."
        )
        return
    if BOA_BANNER_RE.search(server):
        fingerprint["model"] = "unidentified Boa-fronted CPE"
        fingerprint["model_note"] = (
            "Server banner is Boa, not the Conexant/ACME stack. A 401/404 "
            "page that mentions /cgi-bin/webproc is this scanner's own probe "
            "URL echoed by the error page — not proof of the D-Link webproc "
            "CGI. Read the sticker (or the WWW-Authenticate realm) and re-run "
            "with --model/--firmware/--hw."
        )


def boa_version_in_cve_range(version: Optional[str]) -> bool:
    """CVE-2022-45956 names Boa 0.94.13 through 0.94.14, not every Boa build."""
    if not version:
        return False
    match = re.match(r"(\d+)\.(\d+)\.(\d+)", version)
    if not match:
        return False
    major, minor, patch = (int(match.group(1)), int(match.group(2)),
                           int(match.group(3)))
    return (major, minor) == (0, 94) and 13 <= patch <= 14


def boa_banner_finding(host: str, banner: str) -> Dict[str, Any]:
    """Banner-only Boa finding. Does not send a HEAD bypass or a ../ request.

    CVE-2017-9833 is disputed and scoped to an integrator CGI
    (/cgi-bin/wapopen FILECAMERA), not the Boa binary. It is named so the
    report does not treat a Boa banner as that bug.
    """
    match = BOA_BANNER_RE.search(banner or "")
    version = match.group(1) if match and match.group(1) else None
    in_range = bool(version) and boa_version_in_cve_range(version)
    if in_range:
        cve = "CVE-2022-45956 (banner match, not live-confirmed)"
        cvss = "5.3 (CVE); the binary itself has had no upstream release since 2005"
        extra = (
            "CVE-2022-45956 names Boa 0.94.13 through 0.94.14: Basic "
            "authentication is not applied to HEAD. This scanner does not "
            "send that request — doing so would be the bypass. The finding "
            "is the banner, plus the fact that upstream stopped in 2005."
        )
    else:
        cve = "abandoned Boa httpd (banner match)"
        cvss = None
        extra = (
            "The version in the banner is outside the CVE-2022-45956 range "
            "or could not be parsed, so that CVE is not asserted. The "
            "project is still abandoned (last upstream release, 2005)."
        )
    finding: Dict[str, Any] = {
        "id": "GEN-011",
        "title": "Abandoned Boa web server on the admin port",
        "severity": SEV_HIGH if in_range else SEV_MEDIUM,
        "cve": cve,
        "description": (
            f"The HTTP Server banner is '{banner}'. Boa's last upstream "
            "release was in 2005; this binary will not be patched. "
            + extra + " "
            "CVE-2017-9833 is often cited next to Boa banners, but NVD marks "
            "it disputed and attributes it to an integrator CGI, not the Boa "
            "binary — a banner alone does not prove that bug. Model-specific "
            "CVEs on images that embed this banner can only be matched once "
            "the sticker model is known."
        ),
        "url": f"http://{host}/",
        "impact": (
            "An unmaintained admin front door. Internet scanners key off this "
            "banner. If management is reachable from the WAN, the box stays "
            "on those lists. LAN-only exposure is smaller, but there is no "
            "Boa patch to apply."
        ),
        "fix": (
            "1. Disable remote/WAN management so ports 80 and 443 are not internet-reachable\n"
            "2. Read model and firmware off the sticker and re-run with --model/--firmware/--hw\n"
            "3. Do not expect a Boa update — the project is dead\n"
            "4. Durable fix: bridge the ISP unit and route with hardware you control\n"
            "5. Rotate the admin password; treat the management plane as old"
        ),
        "urls": [
            "https://nvd.nist.gov/vuln/detail/CVE-2022-45956",
            "https://www.microsoft.com/en-us/security/blog/2022/11/22/vulnerable-sdk-components-lead-to-supply-chain-risks-in-iot-and-ot-environments/",
        ],
    }
    if cvss:
        finding["cvss"] = cvss
    return finding


def classify_tcp_5555(banner: bytes) -> str:
    """Classify a passive read of TCP 5555.

    Returns ``adb`` only when the banner itself says so, ``other`` when it
    is some other protocol, ``unknown`` when the peer sent nothing. No ADB
    handshake (CNXN) is ever sent — that handshake is what opens the shell.
    """
    if not banner:
        return "unknown"
    head = banner[:32]
    low = banner.lower()
    if (head.startswith(b"SSH-") or head.startswith(b"HTTP/")
            or head.startswith(b"220") or head[:1] == b"\xff"):
        return "other"
    if b"CNXN" in banner or b"AUTH" in banner[:16] or b"android debug" in low:
        return "adb"
    if any(32 <= byte < 127 for byte in banner[:8]):
        return "other"
    return "unknown"


def peek_banner(host: str, port: int, timeout: float = 1.5) -> bytes:
    """Read whatever the service sends on connect. Send nothing."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        try:
            sock.settimeout(1.0)
            data = sock.recv(128)
        except socket.timeout:
            data = b""
        sock.close()
        return data or b""
    except OSError:
        return b""


def _banner_preview(raw: bytes) -> str:
    shown = (raw or b"")[:40].decode("latin-1", "replace")
    return "".join(ch if 32 <= ord(ch) < 127 else "." for ch in shown)


def probe_dnscfg_cgi(client: "HttpClient", host: str) -> List[Dict]:
    """Reachability-only GET of /dnscfg.cgi. Never sends DNS parameters."""
    findings: List[Dict] = []
    origin = client.origin() if hasattr(client, "origin") else f"http://{host}"
    dns_resp = client.get("/dnscfg.cgi")
    if dns_resp is None or dns_resp.status == 404:
        return findings
    loc = dns_resp.header("Location") or ""
    gated = (dns_resp.status in (401, 403)
             or looks_like_login(dns_resp.text)
             or "login" in loc.lower())
    if gated:
        findings.append({
            "id": "DLINK-007",
            "title": "dnscfg.cgi present (auth-gated) — CVE-2026-0625 endpoint family",
            "severity": SEV_INFO,
            "cve": "CVE-2026-0625 (family exposure)",
            "description": (
                "The router serves the dnscfg.cgi endpoint (HTTP "
                f"{dns_resp.status}) but demanded authentication in this probe. "
                "This is the same CGI family behind CVE-2026-0625, the actively "
                "exploited unauthenticated DNSChanger command injection on legacy "
                "D-Link DSL gateways. This unit did not expose it without a login "
                "in this test - exposure is currently gated, but the endpoint "
                "is on the box. Confirmed-affected models are DSL-2740R, "
                "DSL-2640B, DSL-2780B and DSL-526B; a gated 401 is not that list."
            ),
            "url": f"{origin}/dnscfg.cgi",
            "impact": (
                "Low while it stays auth-gated on the LAN side. The risk model "
                "changes completely if the management UI is ever reachable from "
                "the WAN: the exploit needs no credentials at all on affected "
                "builds."
            ),
            "fix": (
                "1. Keep remote/WAN management DISABLED - this is the control\n"
                "2. Re-test after any firmware change\n"
                "3. Track D-Link's CVE-2026-0625 model list - D-Link is still "
                "reviewing firmware builds for the same CGI library\n"
                "4. Planning assumption for EOL DSL hardware: replace or bridge"
            ),
            "urls": [
                "https://nvd.nist.gov/vuln/detail/CVE-2026-0625",
                "https://thehackernews.com/2026/01/active-exploitation-hits-legacy-d-link.html",
            ],
        })
    else:
        findings.append({
            "id": "DLINK-007",
            "title": "dnscfg.cgi reachable WITHOUT authentication — CVE-2026-0625 exposure",
            "severity": SEV_HIGH,
            "cve": "CVE-2026-0625",
            "cvss": "9.3 (confirmed models: DSL-2740R/2640B/2780B/526B)",
            "description": (
                "The router answered a bare, unauthenticated GET of /dnscfg.cgi "
                f"with HTTP {dns_resp.status} (a 404 would mean absent). The CGI "
                "executed or served content without any login session. This is "
                "the endpoint exploited by CVE-2026-0625 - unauthenticated OS "
                "command injection used for DNS hijacking, observed in the wild "
                "since 2025-11-27. NOTE: Bug Hunter is read-only and sent NO "
                "injection payload, so exploitability itself is unconfirmed; what "
                "is confirmed is that the endpoint does not demand a session."
            ),
            "url": f"{origin}/dnscfg.cgi",
            "impact": (
                "On confirmed-affected builds this endpoint gives unauthenticated "
                "remote code execution and silent DNS hijack of every device "
                "behind the router. Your model is not on D-Link's confirmed list, "
                "but the endpoint being reachable without auth is the pre-condition "
                "the exploit needs."
            ),
            "fix": (
                "1. DISABLE remote/WAN management immediately if enabled\n"
                "2. Verify DNS settings on the router and downstream clients now\n"
                "3. Assume the worst for EOL DSL hardware: D-Link's guidance for "
                "confirmed models is retire/replace - no patch exists\n"
                "4. Bridge the unit and route through hardware you control\n"
                "5. Re-run this audit after any firmware change"
            ),
            "urls": [
                "https://nvd.nist.gov/vuln/detail/CVE-2026-0625",
                "https://thehackernews.com/2026/01/active-exploitation-hits-legacy-d-link.html",
                "https://supportannouncement.us.dlink.com/",
            ],
        })
    return findings


# Vendor detection patterns
VENDOR_PATTERNS = {
    "dlink": {
        "patterns": [
            re.compile(r"D-Link", re.I),
            re.compile(r"DSL-2[0-9]+", re.I),
            re.compile(r"webproc", re.I),
            re.compile(r"DIR-\d+", re.I),
            re.compile(r"DSL-\d+", re.I),
            re.compile(r"Conexant", re.I),
        ],
        "server": [
            # The ACME-Labs family. Real banners use the underscore spelling
            # ("micro_httpd") - the hyphenated form appears in some writeups,
            # so both are matched.
            re.compile(r"micro[-_]?httpd", re.I),
            re.compile(r"thttpd", re.I),
            re.compile(r"mini[-_]?httpd", re.I),
            re.compile(r"conexant", re.I),
            re.compile(r"d-link", re.I),
        ],
    },
    "zte": {
        "patterns": [
            re.compile(r"ZTE", re.I),
            re.compile(r"ZXHN", re.I),
            re.compile(r"ZXV10", re.I),
            re.compile(r"F6\d+", re.I),
            re.compile(r"H168N", re.I),
        ],
        "server": [
            re.compile(r"zte", re.I),
        ],
    },
    "tplink": {
        "patterns": [
            re.compile(r"TP-?LINK", re.I),
            re.compile(r"TL-WR\d+", re.I),
            re.compile(r"TD-W\d+", re.I),
            re.compile(r"Archer", re.I),
            re.compile(r"RomPager", re.I),
        ],
        "server": [
            re.compile(r"rompager", re.I),
            re.compile(r"tp-link", re.I),
        ],
    },
    "huawei": {
        "patterns": [
            re.compile(r"Huawei", re.I),
            re.compile(r"HG\d+", re.I),
            re.compile(r"HG\d+", re.I),
            re.compile(r"EchoLife", re.I),
            re.compile(r"OptiXstar", re.I),
        ],
        "server": [
            re.compile(r"huawei", re.I),
        ],
    },
    "netgear": {
        "patterns": [
            re.compile(r"NETGEAR", re.I),
            re.compile(r"WNR\d+", re.I),
            re.compile(r"R\d+000", re.I),
        ],
        "server": [
            re.compile(r"netgear", re.I),
        ],
    },
    "linksys": {
        "patterns": [
            re.compile(r"Linksys", re.I),
            re.compile(r"WRT\d+", re.I),
            re.compile(r"E\d+00", re.I),
        ],
        "server": [
            re.compile(r"linksys", re.I),
        ],
    },
    "fiberhome": {
        "patterns": [
            re.compile(r"FiberHome", re.I),
            re.compile(r"AN\d+", re.I),
            re.compile(r"HG\d+", re.I),
        ],
        "server": [
            re.compile(r"fiberhome", re.I),
        ],
    },
    # --- v2: broadened vendor coverage (body patterns + banner match) ---
    "asus": {
        "patterns": [
            re.compile(r"ASUS", re.I),
            re.compile(r"RT-[AN][CD]\d+", re.I),
            re.compile(r"RT-AX\d+", re.I),
            re.compile(r"ZenWiFi", re.I),
        ],
        "server": [re.compile(r"asus", re.I)],
    },
    "tenda": {
        "patterns": [
            re.compile(r"Tenda", re.I),
            re.compile(r"tendawifi", re.I),
            re.compile(r"\bAC\d{3,4}\b|\bF\d{1,2}\b|\bFH\d{3,4}\b", re.I),
        ],
        "server": [re.compile(r"tendawifi|tenda", re.I)],
    },
    "totolink": {
        "patterns": [
            re.compile(r"TOTOLINK", re.I),
            re.compile(r"\b[NA]\d{3,4}[RV]?\b"),
        ],
        "server": [re.compile(r"totolink", re.I)],
    },
    "cisco": {
        "patterns": [
            re.compile(r"Cisco", re.I),
            re.compile(r"\bRV\d{3}\b", re.I),
            re.compile(r"Small Business", re.I),
        ],
        "server": [re.compile(r"cisco", re.I)],
    },
    "mikrotik": {
        "patterns": [
            re.compile(r"MikroTik", re.I),
            re.compile(r"RouterOS", re.I),
            re.compile(r"RouterBOARD", re.I),
        ],
        "server": [re.compile(r"mikrotik", re.I)],
    },
    "ubiquiti": {
        "patterns": [
            re.compile(r"Ubiquiti", re.I),
            re.compile(r"UniFi", re.I),
            re.compile(r"EdgeRouter", re.I),
            re.compile(r"airOS", re.I),
        ],
        "server": [re.compile(r"ubnt|ubiquiti|aircontrol", re.I)],
    },
    "draytek": {
        "patterns": [
            re.compile(r"DrayTek", re.I),
            re.compile(r"Vigor\d+", re.I),
        ],
        "server": [re.compile(r"vigor|draytek", re.I)],
    },
    "belkin": {
        "patterns": [re.compile(r"Belkin", re.I)],
        "server": [re.compile(r"belkin", re.I)],
    },
    "trendnet": {
        "patterns": [
            re.compile(r"TRENDnet", re.I),
            re.compile(r"TEW-\d+", re.I),
        ],
        "server": [re.compile(r"trendnet", re.I)],
    },
    "xiaomi": {
        "patterns": [
            re.compile(r"Xiaomi", re.I),
            re.compile(r"MiWiFi", re.I),
            re.compile(r"Redmi", re.I),
        ],
        "server": [re.compile(r"miwifi|xiaomi", re.I)],
    },
    "mercusys": {
        "patterns": [
            re.compile(r"MERCUSYS", re.I),
            re.compile(r"\bMW\d{3}[A-Z]*\b", re.I),
        ],
        "server": [re.compile(r"mercusys", re.I)],
    },
    "openwrt": {
        "patterns": [
            re.compile(r"OpenWrt", re.I),
            re.compile(r"LuCI", re.I),
        ],
        "server": [re.compile(r"uhttpd|openwrt", re.I)],
    },
}

# Model/Firmware extraction patterns
MODEL_RES = {
    "dlink": [
        re.compile(r"(?:Model\s*(?:Name)?|Device\s*Name)\s*:?\s*"
                   r"([A-Za-z0-9][A-Za-z0-9\-_/]{1,31})", re.I),
        re.compile(r"(DSL-\d+[A-Z]*(?:/[A-Z])?)", re.I),
        re.compile(r"(DIR-\d+)", re.I),
    ],
    "zte": [
        re.compile(r"(?:model\s*(?:name)?|device\s*name)\s*[:=]?\s*"
                   r"((?:ZXHN\s+[A-Za-z0-9][A-Za-z0-9._/-]*"
                   r"|[A-Za-z0-9][A-Za-z0-9._/-]*))", re.I),
        re.compile(r"(ZXHN\s+\S+)", re.I),
    ],
    "tplink": [
        re.compile(r"(?:Model\s*(?:Name)?|Device\s*Name)\s*:?\s*"
                   r"([A-Za-z][A-Za-z0-9-]{2,31})", re.I),
        re.compile(r"((?:TL|TD|Archer)-[A-Za-z0-9]+)", re.I),
    ],
    # v2: light model matchers for the broadened vendors (generic REs apply too).
    "asus": [re.compile(r"(RT-[A-Z]+\d+[A-Z]*)", re.I)],
    "tenda": [re.compile(r"\b((?:AC|F|FH)\d{1,4}[A-Z]*)", re.I)],
    "totolink": [re.compile(r"\b([NA]\d{3,4}[RV]?)", re.I)],
    "cisco": [re.compile(r"\b(RV\d{3}[A-Z]*)", re.I)],
    "mikrotik": [re.compile(r"(RouterBOARD\s+\S+|RB\S+)", re.I)],
    "ubiquiti": [re.compile(r"(UniFi\s+\S+|EdgeRouter\s+\S+)", re.I)],
    "draytek": [re.compile(r"(Vigor\s?\d+[A-Za-z]*)", re.I)],
    "xiaomi": [re.compile(r"(Mi\s*Router\s*[^<\n]{0,24}|RA\d{2}[A-Z]*)", re.I)],
    "mercusys": [re.compile(r"\b(MW\d{3}[A-Z]*)", re.I)],
    "openwrt": [re.compile(r"(OpenWrt\s+[0-9][0-9A-Za-z._-]*)", re.I)],
    "generic": [
        re.compile(r"(?:Model|Device)\s*[:=]\s*"
                   r"([A-Za-z0-9][A-Za-z0-9\-_/\.]{1,63})", re.I),
    ],
}

FIRMWARE_RES = {
    "dlink": [
        re.compile(r"(?:Firmware|Software)\s*Version\s*:?\s*"
                   r"([A-Za-z0-9][A-Za-z0-9\-_.]{1,63}"
                   r"(?:\s+[0-9]{6,8})?)", re.I),
    ],
    "zte": [
        re.compile(r"(?:software|firmware)\s*version\s*[:=]?\s*"
                   r"([A-Za-z0-9][A-Za-z0-9._/-]{1,79})", re.I),
    ],
    "tplink": [
        re.compile(r"(?:firmware|software)\s*(?:version)?\s*[:=]?\s*"
                   r"([A-Za-z0-9()._-]+(?:\s+Build\s+[A-Za-z0-9._-]+)?)", re.I),
    ],
    "generic": [
        re.compile(r"(?:firmware|software)\s*(?:version)?\s*[:=]?\s*"
                   r"([A-Za-z0-9()._-]{3,79})", re.I),
    ],
}

HARDWARE_RES = [
    # PTCL/D-Link revisions are often letter+digit ("J2", "D1", "T3"), so the
    # value shape must not require a leading digit. Also matches "v2", "V4.0".
    re.compile(r"(?:hardware|h\.?w\.?)\s*(?:version|ver\.?)?\s*[:=]?\s*"
               r"([A-Za-z]{0,2}\s*\d+(?:\.\d+)?[A-Za-z]?)", re.I),
]

SERIAL_RES = [
    re.compile(r"serial\s*(?:number|no\.?|num)?\s*[:=]?\s*"
               r"([A-Za-z0-9][A-Za-z0-9\-]{5,31})", re.I),
]

# LAN/WLAN/WAN MACs — the device-info page can show several; collect them all.
MAC_RE = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")


def detect_vendor(text: str, server_header: Optional[str],
                  webproc_reachable: bool = False) -> str:
    """Detect router vendor from page text, server header, and probe signals.

    `webproc_reachable` means GET /cgi-bin/webproc answered with anything but a
    404. That CGI is the Conexant web stack's signature endpoint, but some
    routers return 401 for every unknown path - so the bare signal is only
    trusted when a corroborating banner (ACME httpd / Conexant / D-Link) is
    also present.
    """
    for vendor, config in VENDOR_PATTERNS.items():
        # Check body patterns
        for pat in config["patterns"]:
            if pat.search(text):
                return vendor
        # Check server header patterns
        if server_header:
            for pat in config["server"]:
                if pat.search(server_header):
                    return vendor

    if (webproc_reachable and server_header
            and re.search(r"micro[-_]?httpd|thttpd|mini[-_]?httpd"
                          r"|conexant|d-link", server_header, re.I)):
        return "dlink"

    return "generic"


def extract_info(text: str, vendor: str) -> Dict[str, Any]:
    """Extract model, firmware, hardware version, serial, and MACs from page text."""
    info: Dict[str, Any] = {
        "model": None,
        "firmware": None,
        "hardware_version": None,
        "serial": None,
        "mac_addresses": [],
    }

    clean = strip_tags(text)

    # Model
    patterns = MODEL_RES.get(vendor, MODEL_RES["generic"]) + MODEL_RES["generic"]
    for pat in patterns:
        m = pat.search(clean)
        if m:
            info["model"] = m.group(1).strip()
            break

    # Firmware
    patterns = FIRMWARE_RES.get(vendor, FIRMWARE_RES["generic"]) + FIRMWARE_RES["generic"]
    for pat in patterns:
        m = pat.search(clean)
        if m:
            info["firmware"] = m.group(1).strip()
            break

    # Hardware version
    for pat in HARDWARE_RES:
        m = pat.search(clean)
        if m:
            info["hardware_version"] = m.group(1).strip()
            break

    # Serial number (used to tie the audit to the physical unit)
    for pat in SERIAL_RES:
        m = pat.search(clean)
        if m:
            info["serial"] = m.group(1).strip()
            break

    # Every MAC shown on the page (LAN/WLAN/WAN may differ) — matched against
    # the sticker MAC by merge_identity(). Raw text is searched so MACs sitting
    # in JavaScript are found too; results are normalized to upper-case colons.
    info["mac_addresses"] = sorted(
        {m.upper().replace("-", ":") for m in MAC_RE.findall(text)}
    )

    return info


# --------------------------------------------------------------------------- #
# Physical-unit identity (sticker/label) & firmware-build classification
# --------------------------------------------------------------------------- #

def classify_firmware_build(firmware: str) -> Optional[str]:
    """Return a caution note when the firmware is an ISP-custom build that no
    public CVE affected-version list covers.

    PTCL builds are named ``PT_*`` or carry the ISP name (``PT_1.10_J2``,
    ``PT_2.00``, ``K92_PTCL_R2005_20170510``). Public CVE lists name retail
    builds only (``IN_*``/``SEA_*``/``ME_*``), so these are untested, not clean.
    """
    f = (firmware or "").strip().lower()
    if not f:
        return None
    if f.startswith("pt_") or "ptcl" in f:
        return ("PTCL ISP build - public CVE affected-version lists name retail "
                "builds only (IN_*/SEA_*/ME_*); this build is untested by them, "
                "which is not the same as clean. Only live probing decides.")
    return None


def normalize_mac(mac: str) -> str:
    return mac.strip().upper().replace("-", ":")


def build_identity(model=None, firmware=None, hardware=None,
                   serial=None, mac=None) -> Dict[str, str]:
    """Physical-unit identity as printed on the sticker/label of the unit."""
    ident: Dict[str, str] = {}
    if model:
        ident["model"] = model.strip()
    if firmware:
        ident["firmware"] = firmware.strip()
    if hardware:
        ident["hardware_version"] = hardware.strip()
    if serial:
        ident["serial"] = serial.strip()
    if mac:
        ident["mac"] = normalize_mac(mac)
    return ident


def merge_identity(fingerprint: Dict, identity: Dict[str, str]) -> None:
    """Merge sticker identity into the device fingerprint, in place.

    * Fields the device did not report are filled from the label
      (recorded in ``fingerprint["label_fields"]``).
    * Fields where the device reports something DIFFERENT from the label are
      recorded in ``fingerprint["label_mismatches"]`` — scanning the wrong
      box, a mis-labelled unit, or a page that lies.
    * The label MAC is checked against every MAC the device displayed.
    """
    if not identity:
        return
    filled: List[str] = []
    mismatches: List[Dict[str, str]] = []
    for key in ("model", "firmware", "hardware_version", "serial"):
        label = identity.get(key)
        if not label:
            continue
        detected = fingerprint.get(key)
        if not detected:
            fingerprint[key] = label
            filled.append(key)
        elif detected.strip().lower() != label.strip().lower():
            mismatches.append({"field": key, "label": label, "detected": detected})
    if filled:
        fingerprint["label_fields"] = sorted(
            set(fingerprint.get("label_fields", []) + filled))
    if mismatches:
        fingerprint["label_mismatches"] = mismatches

    label_mac = identity.get("mac")
    if label_mac:
        seen = {normalize_mac(m) for m in fingerprint.get("mac_addresses") or []}
        # True = the device itself showed the sticker MAC; False = it showed
        # MACs but not the sticker one; None = it showed none (no evidence).
        fingerprint["mac_label_match"] = (label_mac in seen) if seen else None


# --------------------------------------------------------------------------- #
# Vulnerability Check: D-Link (PTCL DSL-series)
# --------------------------------------------------------------------------- #

def check_dlink_vulns(client: HttpClient, host: str, info: Dict) -> List[Dict]:
    """Check D-Link specific vulnerabilities."""
    findings: List[Dict] = []
    _webproc_statuses: List[int] = []
    _orig_get = client.get

    def _tracking_get(path, *args, **kwargs):
        resp = _orig_get(path, *args, **kwargs)
        if isinstance(path, str) and "webproc" in path and resp is not None:
            _webproc_statuses.append(resp.status)
        return resp

    client.get = _tracking_get  # type: ignore[method-assign]

    # --- Check 1: webproc Authentication Bypass (wizard) ---
    wizard_urls = [
        "/cgi-bin/webproc?getpage=html/index.html&errorpage=html/main.html"
        "&var:language=en_us&var:menu=setup&var:subpage=wizentrance&var:page=wizard",
        "/cgi-bin/webproc?getpage=html/index.html"
        "&var:menu=setup&var:page=wizard",
    ]

    for idx, url in enumerate(wizard_urls):
        resp = client.get(url)
        if resp and resp.status == 200 and not looks_like_login(resp.text):
            finding = {
                "id": f"DLINK-00{idx+1}",
                "title": "D-Link webproc Authentication Bypass",
                "severity": SEV_CRITICAL,
                "cve": "CVE-2025-34048 / CVE-2019-1010155 / CVE-2019-1010156",
                "description": (
                    "The D-Link router serves the setup wizard pages to unauthenticated "
                    "requests. The webproc CGI endpoint does not check the session for "
                    "the wizard code path (var:page=wizard), allowing any device on the "
                    "LAN to access the full setup interface without a password. "
                    "An unauthenticated session cookie (:sessionid) is minted and "
                    "remains valid with no timeout, keeping the entire admin UI open."
                ),
                "url": f"http://{host}{url}",
                "impact": (
                    "Full administrative access without authentication. "
                    "Wi-Fi SSID and WPA/WPA2 key may be leaked in page source. "
                    "DNS settings, port forwarding, and other configuration can be changed."
                ),
                "fix": (
                    "1. Rotate Wi-Fi PSK and admin password immediately\n"
                    "2. Reboot the router to clear the bypass session\n"
                    "3. Disable WAN/remote management\n"
                    "4. Ask ISP (PTCL) for updated firmware for your hardware revision\n"
                    "5. Best fix: Bridge the unit and use your own router behind it\n"
                    "6. NOTE: D-Link considers ISP firmware out of scope — "
                    "this may never be patched by the vendor"
                ),
                "urls": [
                    "https://nvd.nist.gov/vuln/detail/CVE-2025-34048",
                    "https://nvd.nist.gov/vuln/detail/CVE-2019-1010155",
                    "https://nvd.nist.gov/vuln/detail/CVE-2019-1010156",
                    "https://www.exploit-db.com/search?cve=2025-34048",
                ],
            }
            findings.append(finding)
            break  # One finding is enough

    # --- Check 2: Wi-Fi Credential Disclosure via Wizard ---
    wl_resp = client.get(
        "/cgi-bin/webproc?getpage=html/index.html&errorpage=html/index.html"
        "&var:language=en_us&var:menu=setup&var:subpage=wizwl&var:page=wizard"
    )
    if wl_resp and wl_resp.status == 200 and not looks_like_login(wl_resp.text):
        ssid_match = re.search(r'var\s+wireless_name\s*=\s*"([^"]*)"', wl_resp.text)
        wpa_match = re.search(r'var\s+randomWPAKEY\s*=\s*"([^"]*)"', wl_resp.text)
        if ssid_match or wpa_match:
            findings.append({
                "id": "DLINK-003",
                "title": "Wi-Fi Credential Disclosure via Unauthenticated Wizard",
                "severity": SEV_CRITICAL,
                "cve": "CVE-2019-1010156",
                "description": (
                    "The wireless setup wizard step (wizwl) leaks the Wi-Fi SSID and "
                    "WPA/WPA2 pre-shared key in JavaScript variables in the page source. "
                    "The values are hidden by input type=password on screen, but visible "
                    "in the HTML source to any unauthenticated client."
                ),
                "url": f"http://{host}/cgi-bin/webproc?getpage=html/index.html"
                       "&var:menu=setup&var:subpage=wizwl&var:page=wizard",
                "impact": (
                    "Wi-Fi passphrase and SSID exposed to anyone on the LAN. "
                    "Enables unauthorized network access and man-in-the-middle attacks."
                ),
                "fix": (
                    "1. Change Wi-Fi passphrase immediately from a wired client\n"
                    "2. Change admin password\n"
                    "3. Reboot router to clear the session\n"
                    "4. Disable WAN management\n"
                    "5. Consider bridging the device and using your own router"
                ),
                "urls": [
                    "https://nvd.nist.gov/vuln/detail/CVE-2019-1010156",
                ],
            })

    # --- Check 3: File Traversal via getpage ---
    # Same proven logic as ptcl-dlink/tools/ptcl_check.py: a real /proc/version
    # contains "Linux" (any spelling) and a bounced request will echo the
    # webproc page back instead. The old strict `Linux x.y.z #` regex missed
    # real /proc/version lines (the (gcc ...) parenthetical sits before the #).
    trav_resp = client.get(
        "/cgi-bin/webproc?getpage=/proc/version&errorpage=html/main.html"
        "&var:language=en_us&var:menu=setup&var:page=wizard"
    )
    if trav_resp and trav_resp.status == 200:
        if "linux" in trav_resp.text.lower() and "var:menu=" not in trav_resp.text:
            findings.append({
                "id": "DLINK-004",
                "title": "Unauthenticated File Read via getpage Parameter",
                "severity": SEV_CRITICAL,
                "cve": "CVE-2025-34048",
                "cvss": "8.7",
                "description": (
                    "The getpage parameter of /cgi-bin/webproc accepts filesystem "
                    "paths, not just template names. This allows unauthenticated "
                    "reading of arbitrary files from the router, including /proc/version "
                    "(confirmed), /etc/passwd, config partitions, and credential stores."
                ),
                "url": f"http://{host}/cgi-bin/webproc?getpage=/proc/version"
                       "&errorpage=html/main.html&var:menu=setup&var:page=wizard",
                "impact": (
                    "Unauthenticated read access to any file on the device. "
                    "Can expose credentials, configuration, encryption keys, "
                    "and system information. CVSS 8.7."
                ),
                "fix": (
                    "1. This is a firmware-level bug — no user-side patch exists\n"
                    "2. Disable WAN/remote management to reduce exposure\n"
                    "3. Bridge the device and route through your own hardware\n"
                    "4. Request updated firmware from ISP (PTCL)\n"
                    "5. Assume compromise — rotate all credentials"
                ),
                "urls": [
                    "https://nvd.nist.gov/vuln/detail/CVE-2025-34048",
                ],
            })

    # --- Check 4: Persistent Session (session stays open) ---
    if findings:
        dash_resp = client.get(
            "/cgi-bin/webproc?getpage=html/index.html&errorpage=html/index.html"
            "&var:language=en_us&var:menu=status&var:page=deviceinfo"
        )
        if dash_resp and dash_resp.status == 200 and not looks_like_login(dash_resp.text):
            findings.append({
                "id": "DLINK-005",
                "title": "Persistent Unauthenticated Session",
                "severity": SEV_HIGH,
                "cve": "CVE-2019-1010155",
                "description": (
                    "After visiting the wizard bypass URL, the minted :sessionid "
                    "cookie persists and allows access to normally protected pages "
                    "(dashboard, device info, advanced settings). The session has no "
                    "timeout and is never invalidated — only a full reboot clears it."
                ),
                "url": f"http://{host}/cgi-bin/webproc?getpage=html/index.html"
                       "&var:menu=status&var:page=deviceinfo",
                "impact": (
                    "Once the bypass is triggered, the entire admin panel is accessible "
                    "to any device on the LAN without re-authentication."
                ),
                "fix": (
                    "1. Reboot the router to clear the session from RAM\n"
                    "2. The underlying bug requires a firmware update\n"
                    "3. As a workaround, bridge the device"
                ),
                "urls": [
                    "https://nvd.nist.gov/vuln/detail/CVE-2019-1010155",
                ],
            })

    # --- Check 5: ACME httpd front door (CVE-2014-4927, never patched) ---
    # The real banner is the underscore spelling ("micro_httpd"); the hyphenated
    # form appears in writeups. This check only FLAGS the banner - it never
    # sends the long URI, because that is a DoS against your own device.
    server = client.server_header or ""
    acme = re.search(r"micro[-_]?httpd|thttpd|mini[-_]?httpd", server, re.I)
    if acme:
        name = acme.group(0)
        findings.append({
            "id": "DLINK-006",
            "title": "ACME httpd front door — long-URI DoS (CVE-2014-4927, never patched)",
            "severity": SEV_HIGH,
            "cve": "CVE-2014-4927 (see also CVE-2010-1544, same server)",
            "description": (
                f"Port 80 is fronted by ACME Labs '{name}', a ~200-line inetd-style "
                "HTTP server whose last public build is August 2014. CVE-2014-4927 "
                "(crash via a long URI in a GET request) explicitly names D-Link "
                "DSL-2750U/DSL-2740U — the hardware class PTCL ships — and was never "
                "patched; the project is dormant, so no fixed version exists. PTCL "
                "ISP build strings (PT_*, K92_PTCL_*, GAN5.PT113A-*) appear in no "
                "public affected-version list: untested, not clean. This scanner "
                "does NOT send the long URI — that would be a DoS against your own "
                "device."
            ),
            "url": f"http://{host}/",
            "impact": (
                "Anyone who can reach port 80 can crash the admin UI (the whole "
                "web stack dies until a power cycle). LAN-only = nuisance; "
                "internet-reachable = remote DoS for free."
            ),
            "fix": (
                "1. Keep port 80 off the WAN — disable remote management; exposure is the only control\n"
                "2. Optionally confirm it live on YOUR unit (accepts a possible admin-UI crash):\n"
                f"     python3 ptcl-dlink/tools/micro_httpd_probe.py {host} --dos\n"
                "3. Durable fix: bridge the unit and route with hardware you control"
            ),
            "urls": [
                "https://nvd.nist.gov/vuln/detail/CVE-2014-4927",
                "http://www.exploit-db.com/exploits/34102",
                "https://github.com/advisories/GHSA-rfw9-259h-m9m6",
            ],
        })

    # --- Check 7: dnscfg.cgi exposure probe (CVE-2026-0625) ---
    # READ-ONLY: probe_dnscfg_cgi sends a bare GET. No DNS parameters.
    findings.extend(probe_dnscfg_cgi(client, host))
    if isinstance(info, dict):
        info["dnscfg_probed"] = True

    # --- Check 8: vendor probes that did not demonstrate a bypass ---
    # A silent zero used to read as "clean" when every wizard URL was 401.
    # Only emit this when a response was actually seen (a connection failure
    # is not evidence either way).
    if _webproc_statuses and not any(
            f["id"] in ("DLINK-001", "DLINK-002", "DLINK-003",
                        "DLINK-004", "DLINK-005")
            for f in findings):
        seen = sorted(set(_webproc_statuses))
        if all(code == 404 for code in seen):
            why = ("every webproc URL returned 404, so this does not look "
                   "like the Conexant CGI")
        elif any(code in (401, 403) for code in seen):
            why = ("the server answered HTTP " + ", ".join(str(c) for c in seen)
                   + " and no wizard page was served. A reject is not proof "
                   "the wizard bug is absent, and this scanner does not "
                   "attempt an authentication bypass")
        else:
            why = ("probes returned HTTP " + ", ".join(str(c) for c in seen)
                   + " and no unauthenticated wizard page was served")
        origin = client.origin() if hasattr(client, "origin") else f"http://{host}"
        findings.append({
            "id": "DLINK-008",
            "title": "D-Link webproc class checked — bypass not demonstrated",
            "severity": SEV_INFO,
            "cve": "CVE-2025-34048 / CVE-2019-1010155 (not confirmed)",
            "description": (
                "The Conexant/webproc checks ran and " + why + ". "
                "Vulnerable units serve the wizard at HTTP 200 without a "
                "login form. This result is inconclusive, not a clean bill."
            ),
            "url": origin + "/",
            "impact": (
                "No demonstrated unauthenticated admin page in this pass. "
                "If the management ports are reachable from the WAN, that "
                "exposure remains regardless of this result."
            ),
            "fix": (
                "1. Keep remote/WAN management disabled\n"
                "2. Pass --model/--firmware/--hw from the sticker so the "
                "audit is tied to a real build\n"
                "3. Re-test after any firmware change — a 401 today is not "
                "a patch"
            ),
            "urls": [
                "https://nvd.nist.gov/vuln/detail/CVE-2025-34048",
            ],
        })

    client.get = _orig_get  # type: ignore[method-assign]
    return findings


# --------------------------------------------------------------------------- #
# Vulnerability Check: ZTE (PTCL H168N and others)
# --------------------------------------------------------------------------- #

def check_zte_vulns(client: HttpClient, host: str, info: Dict,
                     probe_upnp: bool = False) -> List[Dict]:
    """Check ZTE specific vulnerabilities."""
    findings: List[Dict] = []
    firmware = info.get("firmware") or ""
    model = info.get("model") or ""

    # --- Check 1: UPnP WLAN Key Disclosure (CVE-2018-7357/7358) ---
    # Check version string for known-affected firmware
    affected_versions = [
        "V2.2.0_PK1.2T5", "V2.2.0_PK1.2T2",
        "V2.2.0_PK11T7", "V2.2.0_PK11T4",
    ]

    for ver in affected_versions:
        if ver.lower() in firmware.lower():
            findings.append({
                "id": "ZTE-001",
                "title": "ZTE H168N UPnP WLAN Key Disclosure",
                "severity": SEV_CRITICAL,
                "cve": "CVE-2018-7357 / CVE-2018-7358",
                "cvss": "8.8 (NVD) / 6.5 (ZTE CNA)",
                "description": (
                    "The ZTE ZXHN H168N v2.2 exposes a UPnP WLAN service on TCP "
                    "port 52869 that allows unauthenticated GetSecurityKeys requests. "
                    "This returns the Wi-Fi pre-shared key and other security material. "
                    "The SetSecurityKeys action can also change the passphrase."
                ),
                "url": f"http://{host}:52869/control/igd/wlanc_1_1",
                "impact": (
                    "Wi-Fi passphrase disclosed to any LAN client. "
                    "Passphrase can also be changed by an attacker, "
                    "locking out legitimate users."
                ),
                "fix": (
                    "1. Disable UPnP in router settings immediately\n"
                    "2. Update firmware to V2.2.0_PK1.2T6 or later (ZTE's fixed version)\n"
                    "3. Ask ISP (PTCL) for the specific update image for your hardware\n"
                    "4. Change Wi-Fi passphrase (assume it was already exposed)\n"
                    "5. Do NOT cross-flash retail firmware — hardware revisions differ"
                ),
                "urls": [
                    "https://nvd.nist.gov/vuln/detail/CVE-2018-7357",
                    "https://nvd.nist.gov/vuln/detail/CVE-2018-7358",
                    "https://www.exploit-db.com/exploits/45972",
                    "http://support.zte.com.cn/support/news/LoopholeInfoDetail.aspx?newsId=1009523",
                ],
            })
            break

    # --- Check 2: UPnP Probe (if requested) ---
    if probe_upnp and is_port_open(host, 52869, timeout=3):
        soap_body = (
            '<?xml version="1.0" encoding="utf-8"?>'
            '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
            's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
            '<s:Body><u:GetSecurityKeys '
            'xmlns:u="urn:dslforum-org:service:WLANConfiguration:1">'
            '</u:GetSecurityKeys></s:Body></s:Envelope>'
        ).encode("utf-8")

        try:
            conn = http.client.HTTPConnection(host, 52869, timeout=5)
            conn.request("POST", "/control/igd/wlanc_1_1",
                         body=soap_body,
                         headers={
                             "Content-Type": 'text/xml; charset="utf-8"',
                             "SOAPAction": '"urn:dslforum-org:service:'
                                           'WLANConfiguration:1#GetSecurityKeys"',
                         })
            raw = conn.getresponse()
            body = raw.read(8192)
            conn.close()

            # Check if response contains key material (without printing it)
            key_pattern = re.compile(
                rb"<(?:NewPreSharedKey|NewKeyPassphrase|NewWEPKey)\b[^>]*>\s*\S",
                re.I
            )
            if key_pattern.search(body):
                if not any(f["id"] == "ZTE-001" for f in findings):
                    findings.append({
                        "id": "ZTE-001-LIVE",
                        "title": "CONFIRMED: UPnP WLAN Key Disclosure (Live Probe)",
                        "severity": SEV_CRITICAL,
                        "cve": "CVE-2018-7357",
                        "description": (
                            "Live probe confirmed: the UPnP service on port 52869 "
                            "responds to GetSecurityKeys with actual WLAN key material. "
                            "This is an active, exploitable vulnerability."
                        ),
                        "url": f"http://{host}:52869/control/igd/wlanc_1_1",
                        "impact": "Wi-Fi passphrase is actively exposed and retrievable.",
                        "fix": (
                            "1. Disable UPnP immediately\n"
                            "2. Update firmware\n"
                            "3. Change Wi-Fi passphrase\n"
                            "4. Contact ISP for patched image"
                        ),
                        "urls": [
                            "https://nvd.nist.gov/vuln/detail/CVE-2018-7357",
                            "https://www.exploit-db.com/exploits/45972",
                        ],
                    })
        except (OSError, http.client.HTTPException):
            pass

    # --- Check 3: H168N v3.5 Information Leak (CVE-2021-21735) ---
    if "v3.5" in model.lower() or "v3.5" in firmware.lower():
        findings.append({
            "id": "ZTE-002",
            "title": "ZTE H168N v3.5 Information Leak via Wizard Page",
            "severity": SEV_HIGH,
            "cve": "CVE-2021-21735",
            "cvss": "6.5 (NVD)",
            "description": (
                "ZTE ZXHN H168N V3.5 has an information leak through a wizard page "
                "due to improper permissions. Unauthenticated access to configuration "
                "data is possible."
            ),
            "url": f"http://{host}/",
            "impact": "Configuration data may be accessible without authentication.",
            "fix": (
                "1. Update to V3.5.0_EG1T10_ETS or later\n"
                "2. Contact ISP for the correct image for your hardware\n"
                "3. Disable WAN management"
            ),
            "urls": [
                "https://nvd.nist.gov/vuln/detail/CVE-2021-21735",
                "https://support.zte.com.cn/support/news/LoopholeInfoDetail.aspx?newsId=1015924",
            ],
        })

    # --- Check 4: H168N v3.5 CSRF (CVE-2021-21729) ---
    if "v3.5" in model.lower() or "v3.5" in firmware.lower():
        findings.append({
            "id": "ZTE-003",
            "title": "ZTE H168N v3.5 Missing CSRF Protection",
            "severity": SEV_HIGH,
            "cve": "CVE-2021-21729",
            "cvss": "6.2 (ZTE CNA) / 9.8 enriched (NVD)",
            "description": (
                "The ZTE H168N V3.5 lacks CSRF random-value checks, allowing "
                "cross-site request forgery attacks that could perform unauthorized "
                "configuration changes."
            ),
            "url": f"http://{host}/",
            "impact": (
                "An attacker could trick an authenticated admin into performing "
                "unauthorized actions via crafted cross-site requests."
            ),
            "fix": (
                "1. Update to V3.5.0P1N3_TE1 or later\n"
                "2. Be cautious of links while logged into the router\n"
                "3. Use a separate browser for router admin"
            ),
            "urls": [
                "https://nvd.nist.gov/vuln/detail/CVE-2021-21729",
                "https://support.zte.com.cn/support/news/LoopholeInfoDetail.aspx?newsId=1014904",
            ],
        })

    return findings


# --------------------------------------------------------------------------- #
# Vulnerability Check: TP-Link (PTCL-associated)
# --------------------------------------------------------------------------- #

def check_tplink_vulns(client: HttpClient, host: str, info: Dict,
                        probe_rom0: bool = False) -> List[Dict]:
    """Check TP-Link specific vulnerabilities."""
    findings: List[Dict] = []
    firmware = (info.get("firmware") or "").lower()
    model = (info.get("model") or "").lower()
    hw_ver = (info.get("hardware_version") or "").lower()

    # --- Check 1: rom-0 Config Backup Disclosure ---
    head_resp = client.head("/rom-0")
    if head_resp:
        ct = (head_resp.header("Content-Type") or "").lower()
        cl = head_resp.header("Content-Length") or "0"
        if head_resp.status == 200 and ("octet" in ct or "binary" in ct or
                                         (cl.isdigit() and int(cl) > 100)):
            findings.append({
                "id": "TPLINK-001",
                "title": "rom-0 Configuration Backup Exposed Without Authentication",
                "severity": SEV_HIGH,
                "cve": "Known class vulnerability (RomPager/ZyNOS family)",
                "description": (
                    "The router exposes /rom-0 without authentication. This endpoint "
                    "serves a configuration backup that may contain administrative "
                    "credentials, ISP PPPoE passwords, and Wi-Fi keys. "
                    "The HEAD request returned a binary response, confirming exposure."
                ),
                "url": f"http://{host}/rom-0",
                "impact": (
                    "Configuration backup with credentials is downloadable by "
                    "anyone on the LAN. Can be decoded to extract admin passwords, "
                    "ISP credentials, and Wi-Fi keys."
                ),
                "fix": (
                    "1. Update firmware to the latest version for your hardware revision\n"
                    "2. Check TP-Link's regional download page for your exact model/HW ver\n"
                    "3. Change admin password and Wi-Fi passphrase\n"
                    "4. Disable WAN management\n"
                    "5. NOTE: Older TP-Link models may be EOL — replacement may be needed"
                ),
                "urls": [
                    "https://www.tp-link.com/pk/support/download/",
                    "https://community.tp-link.com/en/home/forum/topic/78603",
                ],
            })

    # --- Check 2: TL-WR840N CVE-2023-50224 (unpatched v2/v3) ---
    if "wr840" in model:
        if any(v in hw_ver for v in ["2", "v2", "3", "v3"]):
            findings.append({
                "id": "TPLINK-002",
                "title": "TL-WR840N v2/v3 — Unpatched Credential Disclosure",
                "severity": SEV_CRITICAL,
                "cve": "CVE-2023-50224",
                "cvss": "8.1",
                "description": (
                    "TP-Link's May 2026 advisory explicitly states TL-WR840N v2/v3 "
                    "remains UNPATCHED. The HTTPD service has an improper authentication "
                    "flaw that lets a network-adjacent attacker retrieve sensitive "
                    "information including stored credentials. Active exploitation "
                    "has been reported."
                ),
                "url": f"http://{host}/",
                "impact": (
                    "Stored credentials can be retrieved by an attacker on the LAN. "
                    "Active exploitation with DNS manipulation has been reported."
                ),
                "fix": (
                    "1. TP-Link says this is UNPATCHED on v2/v3 — REPLACE the device\n"
                    "2. Do NOT expose the admin interface to WAN\n"
                    "3. Disable remote management\n"
                    "4. Change all passwords as a precaution"
                ),
                "urls": [
                    "https://www.tp-link.com/us/support/faq/5058/",
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-50224",
                ],
            })

    # --- Check 3: TL-WR840N v6 Command Injection (CVE-2026-3227) ---
    if "wr840" in model and "v6" in hw_ver:
        # Check if firmware might be vulnerable
        findings.append({
            "id": "TPLINK-003",
            "title": "TL-WR840N v6 — Authenticated Command Injection via Config Import",
            "severity": SEV_HIGH,
            "cve": "CVE-2026-3227",
            "cvss": "8.5 (v4.0)",
            "description": (
                "TL-WR840N v6 with firmware below V6_260304 has an authenticated "
                "command injection vulnerability in the configuration import process. "
                "A crafted config file can achieve OS command execution as root."
            ),
            "url": f"http://{host}/",
            "impact": (
                "Root-level command execution via crafted configuration import. "
                "Complete device compromise."
            ),
            "fix": (
                "1. Update firmware to V6_260304 or later\n"
                "2. Never import configuration files from untrusted sources\n"
                "3. Verify firmware version on the status page"
            ),
            "urls": [
                "https://www.tp-link.com/us/support/faq/5018/",
                "https://nvd.nist.gov/vuln/detail/CVE-2026-3227",
            ],
        })

    # --- Check 4: TD-W8961N v4 HTTPD DoS (CVE-2025-15606) ---
    if "w8961" in model and "v4" in hw_ver:
        findings.append({
            "id": "TPLINK-004",
            "title": "TD-W8961N v4 — HTTPD Denial of Service",
            "severity": SEV_MEDIUM,
            "cve": "CVE-2025-15606",
            "cvss": "7.1 (v4.0)",
            "description": (
                "TD-W8961N v4.0 firmware below V4_250925 is vulnerable to an "
                "unauthenticated HTTPD crash via crafted request. The product is EOL."
            ),
            "url": f"http://{host}/",
            "impact": (
                "Router management interface can be crashed by any LAN client. "
                "Product is end-of-life."
            ),
            "fix": (
                "1. Update to V4_250925 if available for your region\n"
                "2. TP-Link recommends replacing EOL devices\n"
                "3. Disable WAN management"
            ),
            "urls": [
                "https://www.tp-link.com/us/support/faq/5028/",
                "https://nvd.nist.gov/vuln/detail/CVE-2025-15606",
            ],
        })

    # --- Check 5: TD-W9970 Command Injection (CVE-2023-6437) ---
    if "w9970" in model:
        findings.append({
            "id": "TPLINK-005",
            "title": "TD-W9970 — Authenticated OS Command Injection",
            "severity": SEV_HIGH,
            "cve": "CVE-2023-6437",
            "description": (
                "TD-W9970 / TD-W9970v3 has an authenticated OS command injection "
                "vulnerability. While authentication is required, an attacker with "
                "admin access (possibly obtained via other bugs) can execute arbitrary "
                "commands as root."
            ),
            "url": f"http://{host}/",
            "impact": "Root command execution with admin credentials.",
            "fix": (
                "1. Check TP-Link regional download page for firmware update\n"
                "2. Contact ISP for patched image\n"
                "3. Change admin password\n"
                "4. Disable WAN management"
            ),
            "urls": [
                "https://nvd.nist.gov/vuln/detail/CVE-2023-6437",
                "https://siberguvenlik.gov.tr/guvenlik-bildirimleri/detay/tr-24-0244",
            ],
        })

    # --- Check 6: Misfortune Cookie (CVE-2014-9222) for RomPager ---
    server = client.server_header or ""
    if "rompager" in server.lower():
        findings.append({
            "id": "TPLINK-006",
            "title": "RomPager Server Detected — Potential Misfortune Cookie Exposure",
            "severity": SEV_MEDIUM,
            "cve": "CVE-2014-9222",
            "description": (
                "The router uses RomPager HTTP server, which is associated with the "
                "'Misfortune Cookie' vulnerability (CVE-2014-9222). This allows session "
                "hijacking via malformed cookie values. Many TP-Link models using "
                "RomPager were affected; firmware fixes exist for most revisions."
            ),
            "url": f"http://{host}/",
            "impact": (
                "Session hijacking possible if the specific RomPager version is "
                "vulnerable. An attacker could take over an admin session."
            ),
            "fix": (
                "1. Update firmware — TP-Link fixed Misfortune Cookie in many models\n"
                "2. TD-W8951ND V5: fixed in TD-W8951ND_V5_160113\n"
                "3. TD-W8961ND V3: fixed in V3_150707\n"
                "4. Check your model's firmware page on TP-Link's site"
            ),
            "urls": [
                "https://nvd.nist.gov/vuln/detail/CVE-2014-9222",
                "https://community.tp-link.com/en/home/forum/topic/78603",
            ],
        })

    return findings


# --------------------------------------------------------------------------- #
# v2 low-level UDP probes (read-only, LAN-only, stdlib sockets)
# --------------------------------------------------------------------------- #

def _snmp_get_request(community: str = "public") -> bytes:
    """Minimal SNMPv1 GET for sysDescr.0 (1.3.6.1.2.1.1.1.0)."""
    # OID 1.3.6.1.2.1.1.1.0 -> 2B 06 01 02 01 01 01 00
    oid = bytes([0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00])
    varbind = (b"\x30\x0e" b"\x30\x0c" b"\x06\x08" + oid + b"\x05\x00")
    pdu = (b"\xa0\x13" b"\x02\x01\x00" b"\x02\x01\x00" b"\x02\x01\x00" + varbind)
    community_b = community.encode("ascii", "replace")
    body = (b"\x02\x01\x00" b"\x04" + bytes([len(community_b)]) + community_b + pdu)
    return b"\x30" + bytes([len(body)]) + body


def snmp_sysdescr_probe(host: str, community: str = "public",
                        timeout: float = 2.5) -> Optional[str]:
    """Ask the router's SNMP agent for sysDescr. Returns the string or None.

    Read-only GET with the `public` community — the standard audit for
    "SNMP answers the world with defaults". Returns None on timeout/refusal.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(_snmp_get_request(community), (host, 161))
        data, _ = sock.recvfrom(4096)
        sock.close()
    except (OSError, socket.timeout):
        return None
    if not data or data[0] != 0x30:
        return None
    # Walk to the first OCTET STRING after the OID — sysDescr value.
    try:
        idx = data.find(bytes([0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00]))
        if idx < 0:
            return None
        seg = data[idx:]
        s_idx = seg.find(b"\x04")
        if s_idx < 0 or s_idx + 2 > len(seg):
            return None
        length = seg[s_idx + 1]
        if length & 0x80:  # long form
            nbytes = length & 0x7F
            length = int.from_bytes(seg[s_idx + 2:s_idx + 2 + nbytes], "big")
            start = s_idx + 2 + nbytes
        else:
            start = s_idx + 2
        raw = seg[start:start + length]
        text = raw.decode("utf-8", "replace").strip()
        return text[:256] if text else None
    except (IndexError, ValueError):
        return None


def dns_version_probe(host: str, timeout: float = 2.5) -> Optional[str]:
    """Query version.bind (CHAOS/TXT). Returns the version string or None."""
    try:
        import struct as _struct
        # Header: id, flags=RD, 1 question. Q: version.bind CHAOS TXT.
        pkt = _struct.pack(">HHHHHH", 0xBEEF, 0x0100, 1, 0, 0, 0)
        for label in (b"version", b"bind"):
            pkt += bytes([len(label)]) + label
        pkt += b"\x00" + _struct.pack(">HH", 16, 3)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(pkt, (host, 53))
        data, _ = sock.recvfrom(2048)
        sock.close()
    except (OSError, socket.timeout):
        return None
    if len(data) < 12 or data[2] & 0x0F != 0:
        return None  # RCODE != NOERROR
    try:
        # Skip question section, read first TXT answer.
        pos = 12
        while pos < len(data) and data[pos] != 0:
            if data[pos] & 0xC0 == 0xC0:
                pos += 2
                break
            pos += 1 + data[pos]
        else:
            pos += 1
        pos += 4  # QTYPE+QCLASS
        # Answer: name (maybe pointer) + type/class/ttl/rdlen + rdata
        if pos + 10 > len(data):
            return None
        if data[pos] & 0xC0 == 0xC0:
            pos += 2
        else:
            while pos < len(data) and data[pos] != 0:
                pos += 1 + data[pos]
            pos += 1
        if pos + 10 > len(data):
            return None
        rdlen = int.from_bytes(data[pos + 8:pos + 10], "big")
        rdata = data[pos + 10:pos + 10 + rdlen]
        if rdata and rdata[0] + 1 <= len(rdata):
            text = rdata[1:1 + rdata[0]].decode("utf-8", "replace").strip()
            return text[:160] if text else None
    except (IndexError, ValueError):
        return None
    return None


# --------------------------------------------------------------------------- #
# Generic Vulnerability Checks (all routers)
# --------------------------------------------------------------------------- #

def check_generic_vulns(client: HttpClient, host: str, info: Dict,
                         open_ports: List[Dict],
                         probe_rom0: bool = False,
                         probe_udp: bool = False) -> List[Dict]:
    """Run generic vulnerability checks applicable to all routers."""
    findings: List[Dict] = []
    server = client.server_header or ""

    # --- Check 1: Telnet Exposed ---
    telnet_open = any(p["port"] == 23 for p in open_ports)
    if telnet_open:
        findings.append({
            "id": "GEN-001",
            "title": "Telnet Service Exposed on LAN",
            "severity": SEV_HIGH,
            "cve": "N/A (insecure service)",
            "description": (
                "The router has Telnet (port 23) open. Telnet transmits all data "
                "including credentials in plaintext. This is an insecure remote "
                "access protocol that should never be exposed on a network."
            ),
            "url": f"telnet://{host}/",
            "impact": (
                "Credentials and commands transmitted in cleartext. "
                "Susceptible to eavesdropping and credential theft."
            ),
            "fix": (
                "1. Disable Telnet in router admin settings\n"
                "2. Use SSH (port 22) instead if remote CLI access is needed\n"
                "3. If Telnet cannot be disabled, ensure the router is behind "
                "a firewall that blocks external access"
            ),
            "urls": [],
        })

    # --- Check 2: FTP Exposed ---
    ftp_open = any(p["port"] == 21 for p in open_ports)
    if ftp_open:
        findings.append({
            "id": "GEN-002",
            "title": "FTP Service Exposed on LAN",
            "severity": SEV_MEDIUM,
            "cve": "N/A (insecure service)",
            "description": (
                "The router has an FTP server (port 21) open. FTP transmits "
                "credentials in plaintext and may allow file access to router storage."
            ),
            "url": f"ftp://{host}/",
            "impact": (
                "Plaintext credential transmission. Possible unauthorized "
                "file access if default credentials are active."
            ),
            "fix": (
                "1. Disable FTP service in router settings\n"
                "2. If USB storage sharing is needed, use SFTP or SMB instead\n"
                "3. Change any FTP-specific credentials"
            ),
            "urls": [],
        })

    # --- Check 3: TR-069/CWMP Exposed ---
    cwmp_open = any(p["port"] == 7547 for p in open_ports)
    if cwmp_open:
        findings.append({
            "id": "GEN-003",
            "title": "TR-069/CWMP Management Port Exposed",
            "severity": SEV_HIGH,
            "cve": "Multiple CVEs (class vulnerability)",
            "description": (
                "Port 7547 (TR-069/CWMP) is open. This ISP remote management "
                "protocol has been the target of multiple critical vulnerabilities "
                "allowing remote code execution. If exposed to the WAN, it can be "
                "exploited from the internet."
            ),
            "url": f"http://{host}:7547/",
            "impact": (
                "If exposed to WAN: remote code execution, full device compromise. "
                "Multiple critical CVEs exist for TR-069 implementations."
            ),
            "fix": (
                "1. Ensure port 7547 is NOT accessible from the WAN\n"
                "2. If not needed, disable TR-069 in router settings\n"
                "3. Contact ISP about securing this interface\n"
                "4. Check WAN firewall rules"
            ),
            "urls": [
                "https://nvd.nist.gov/vuln/detail/CVE-2012-4036",
            ],
        })

    # --- Check 4: SNMP Exposed ---
    snmp_open = any(p["port"] == 161 for p in open_ports)
    if snmp_open:
        findings.append({
            "id": "GEN-004",
            "title": "SNMP Service Exposed",
            "severity": SEV_MEDIUM,
            "cve": "N/A (configuration issue)",
            "description": (
                "SNMP (port 161) is open. SNMP v1/v2c use community strings sent "
                "in plaintext (default: 'public'/'private'). This exposes device "
                "configuration, traffic statistics, and network topology."
            ),
            "url": f"snmp://{host}:161/",
            "impact": (
                "Network topology, device config, and traffic data exposure. "
                "Default community strings allow unauthorized monitoring."
            ),
            "fix": (
                "1. Disable SNMP if not actively needed for monitoring\n"
                "2. Change default community strings (public/private)\n"
                "3. Use SNMPv3 with authentication and encryption\n"
                "4. Restrict SNMP access to a management VLAN"
            ),
            "urls": [],
        })

    # --- Check 5: UPnP Enabled ---
    upnp_open = any(p["port"] == 1900 for p in open_ports)
    if upnp_open:
        findings.append({
            "id": "GEN-005",
            "title": "UPnP/SSDP Service Enabled",
            "severity": SEV_MEDIUM,
            "cve": "Multiple (class vulnerability)",
            "description": (
                "UPnP (Universal Plug and Play) is enabled. This protocol allows "
                "devices on the LAN to open firewall ports, modify forwarding rules, "
                "and discover services. Malware on any LAN device can abuse UPnP "
                "to expose internal services to the internet."
            ),
            "url": f"http://{host}:1900/",
            "impact": (
                "Malware on any LAN device can open WAN ports, create forwarding "
                "rules, and expose internal services. This is a known attack vector "
                "for botnets and ransomware."
            ),
            "fix": (
                "1. Disable UPnP in router admin settings\n"
                "2. Manually configure port forwarding for any services that need it\n"
                "3. Monitor firewall rules for unauthorized changes"
            ),
            "urls": [
                "https://www.us-cert.gov/ncas/alerts/TA11-047A",
            ],
        })

    # --- Check 6: HTTP without HTTPS ---
    http_open = any(p["port"] == 80 for p in open_ports)
    https_open = any(p["port"] == 443 for p in open_ports)
    if http_open and not https_open:
        findings.append({
            "id": "GEN-006",
            "title": "Admin Panel Only Available Over Unencrypted HTTP",
            "severity": SEV_MEDIUM,
            "cve": "N/A (configuration issue)",
            "description": (
                "The router's admin interface is only served over plain HTTP (no HTTPS). "
                "All admin credentials and configuration changes are transmitted in "
                "cleartext, visible to anyone on the network."
            ),
            "url": f"http://{host}/",
            "impact": (
                "Admin passwords and configuration transmitted in plaintext. "
                "Network sniffing can capture credentials."
            ),
            "fix": (
                "1. Enable HTTPS in router admin settings if available\n"
                "2. Access the admin panel only from a trusted, private network\n"
                "3. Never access admin over public WiFi"
            ),
            "urls": [],
        })

    # --- Check 7: SSH with Potential Default Creds ---
    ssh_open = any(p["port"] == 22 for p in open_ports)
    if ssh_open:
        findings.append({
            "id": "GEN-007",
            "title": "SSH Service Exposed — Verify Non-Default Credentials",
            "severity": SEV_LOW,
            "cve": "N/A (hardening issue)",
            "description": (
                "SSH (port 22) is open on the router. While SSH itself is secure, "
                "many routers ship with default or weak SSH credentials (root/root, "
                "admin/admin, etc.). Ensure strong, unique credentials are set."
            ),
            "url": f"ssh://{host}/",
            "impact": (
                "If default credentials are active, full CLI access is possible. "
                "SSH brute-force from the LAN is also a risk."
            ),
            "fix": (
                "1. Change the default SSH/admin password\n"
                "2. Disable SSH if not needed\n"
                "3. If available, use key-based authentication instead of passwords\n"
                "4. Restrict SSH access to specific LAN IPs"
            ),
            "urls": [],
        })

    # --- Check 8: Server Header Information Leakage ---
    if server:
        findings.append({
            "id": "GEN-008",
            "title": "Server Header Information Disclosure",
            "severity": SEV_INFO,
            "cve": "N/A",
            "description": (
                f"The router's HTTP server identifies itself as '{server}'. "
                "This reveals the web server software and potentially its version, "
                "helping attackers identify known vulnerabilities."
            ),
            "url": f"http://{host}/",
            "impact": "Minor: aids attacker reconnaissance.",
            "fix": (
                "1. This is informational — many routers cannot suppress this header\n"
                "2. Focus on fixing actual vulnerabilities, not this disclosure\n"
                "3. If the firmware allows, hide the server header"
            ),
            "urls": [],
        })

    # --- Check 9: TCP 5555 (ADB only if the banner says so) ---
    # A connect-and-read is not an ADB handshake. Sending CNXN is what
    # opens a shell; this scanner never sends it.
    if any(p["port"] == 5555 for p in open_ports):
        cached = None
        if isinstance(info, dict):
            cached = (info.get("_port_banners") or {}).get(5555)
        raw = cached if isinstance(cached, (bytes, bytearray)) else peek_banner(host, 5555)
        kind = classify_tcp_5555(bytes(raw))
        preview = _banner_preview(bytes(raw))
        if kind == "adb":
            findings.append({
                "id": "GEN-009",
                "title": "ADB protocol banner on TCP 5555",
                "severity": SEV_HIGH,
                "cve": "N/A (debug interface exposure)",
                "description": (
                    "TCP 5555 answered with an Android Debug Bridge banner "
                    f"({preview!r}). That is the debug bridge, not a guess from "
                    "the port number. No handshake was sent, so this is not a "
                    "confirmed shell — it is a confirmed ADB listener."
                ),
                "url": f"tcp://{host}:5555/",
                "impact": (
                    "An ADB listener on the LAN can become a shell if a client "
                    "completes the handshake. This scanner did not do that."
                ),
                "fix": (
                    "1. Disable ADB debugging in device settings\n"
                    "2. If this is an Android TV box, disable developer options\n"
                    "3. Block port 5555 at the firewall"
                ),
                "urls": [],
            })
        else:
            if kind == "other":
                detail = f"The passive read returned {preview!r}, which is not an ADB banner."
            else:
                detail = ("A passive read returned no banner. Many DSL CPEs use "
                          "5555 for a debug or management listener that is not ADB.")
            findings.append({
                "id": "GEN-012",
                "title": "TCP 5555 open — ADB not confirmed",
                "severity": SEV_MEDIUM,
                "cve": "N/A (unidentified listener)",
                "description": (
                    "Port 5555 is open. " + detail + " No ADB handshake was "
                    "sent. Calling this a full shell would be a guess."
                ),
                "url": f"tcp://{host}:5555/",
                "impact": (
                    "An unidentified LAN listener. It may be harmless debug, "
                    "or a management service. It is not evidence of a shell."
                ),
                "fix": (
                    "1. Identify the service from the device manual or sticker vendor\n"
                    "2. Disable unused debug/management listeners in the admin UI\n"
                    "3. Keep port 5555 off the WAN\n"
                    "4. Do not run an ADB client against it just to 'see'"
                ),
                "urls": [],
            })

    # --- Check 10: No Authentication on Web UI ---
    base_resp = client.get("/", use_cookies=False)
    if base_resp and base_resp.status == 200 and not looks_like_login(base_resp.text):
        # Check if the page has real content (not just a redirect stub)
        if len(base_resp.body) > 500:
            findings.append({
                "id": "GEN-010",
                "title": "Web Admin Interface Accessible Without Login Prompt",
                "severity": SEV_HIGH,
                "cve": "Vendor-specific",
                "description": (
                    "The router's main web page does not show a login form. "
                    "This could indicate the admin panel is accessible without "
                    "authentication, or that authentication is bypassed for certain "
                    "paths. Further investigation is needed."
                ),
                "url": f"http://{host}/",
                "impact": (
                    "Possible unauthenticated access to admin functions. "
                    "Severity depends on what pages/actions are reachable."
                ),
                "fix": (
                    "1. Check if the admin panel requires login by navigating all pages\n"
                    "2. Set/change the admin password\n"
                    "3. Check for firmware updates\n"
                    "4. Disable WAN management"
                ),
                "urls": [],
            })

    # --- Check 11: Boa banner (abandoned httpd; no bypass probe) ---
    banners = []
    for candidate in (
            server,
            (info or {}).get("server_header") if isinstance(info, dict) else None,
            (info or {}).get("https_server") if isinstance(info, dict) else None,
    ):
        if candidate and candidate not in banners:
            banners.append(candidate)
    boa_banner = next((b for b in banners if BOA_BANNER_RE.search(b)), None)
    if boa_banner:
        findings.append(boa_banner_finding(host, boa_banner))
        # The D-Link checks already probed dnscfg when vendor was dlink.
        # A Boa box that was not classified as D-Link still deserves the
        # reachability-only GET — that is how a 401 used to vanish.
        if isinstance(info, dict) and not info.get("dnscfg_probed"):
            findings.extend(probe_dnscfg_cgi(client, host))
            info["dnscfg_probed"] = True

    # --- Check 12: Basic auth on cleartext HTTP ---
    scheme = ""
    realm = ""
    if isinstance(info, dict):
        scheme = info.get("auth_scheme") or ""
        realm = info.get("auth_realm") or ""
    if not scheme and getattr(client, "www_authenticate", None):
        scheme, realm = parse_www_authenticate(client.www_authenticate)
    cleartext_basic = bool(isinstance(info, dict) and info.get("basic_on_cleartext"))
    if not cleartext_basic and (scheme or "").lower() == "basic" and not getattr(client, "tls", False):
        cleartext_basic = True
    if cleartext_basic:
        findings.append({
            "id": "GEN-013",
            "title": "Admin login uses HTTP Basic on cleartext HTTP",
            "severity": SEV_MEDIUM,
            "cve": "N/A (transport exposure)",
            "description": (
                "WWW-Authenticate advertised Basic"
                + (f" (realm {realm!r})" if realm else "")
                + ". The password is only Base64 on the wire. Anyone on the "
                "LAN who can see the admin session can recover it. No "
                "credentials were sent by this scanner."
            ),
            "url": f"http://{host}/",
            "impact": (
                "Admin password recoverable from a LAN capture. Combined with "
                "an open telnet or FTP port, the same password is often reused."
            ),
            "fix": (
                "1. Prefer the HTTPS admin port if the firmware has one\n"
                "2. Change the admin password; do not reuse it for Wi-Fi or ISP login\n"
                "3. Disable remote management so this header is not on the WAN"
            ),
            "urls": [],
        })

    # --- Check 13 (v2): MikroTik Winbox / API exposed ---
    if any(p["port"] in (8291, 8728) for p in open_ports):
        which = ", ".join(str(p["port"]) for p in open_ports
                          if p["port"] in (8291, 8728))
        findings.append({
            "id": "GEN-014",
            "title": "MikroTik Winbox/API port exposed on LAN",
            "severity": SEV_HIGH,
            "cve": "CVE-2018-14847 (class — unpatched RouterOS leaks admin creds)",
            "description": (
                f"Port(s) {which} answer — the MikroTik Winbox/API management "
                "plane. Unpatched RouterOS (< 6.42.1) discloses the admin "
                "password file to an unauthenticated peer (CVE-2018-14847, "
                "actively exploited by VPNFilter-era campaigns). This scanner "
                "does not send the exploit directory-traversal; the finding "
                "is the exposure plus the patch question."
            ),
            "url": f"http://{host}:8291/",
            "impact": (
                "If RouterOS predates the 2018 fix: unauthenticated admin "
                "credential disclosure, then full takeover."
            ),
            "fix": (
                "1. Upgrade RouterOS past 6.42.1 immediately (check /system package)\n"
                "2. Restrict Winbox to a management IP list (/ip service)\n"
                "3. Never expose 8291/8728 to the WAN"
            ),
            "urls": [
                "https://nvd.nist.gov/vuln/detail/CVE-2018-14847",
                "https://blog.mikrotik.com/security/",
            ],
        })

    # --- Check 14 (v2): SNMP answers with the `public` community (UDP) ---
    # Opt-in via --probe-udp: it sends one read-only GET per host.
    if probe_udp:
        sysdescr = snmp_sysdescr_probe(host)
        if sysdescr:
            findings.append({
                "id": "GEN-015",
                "title": "SNMP answers with default `public` community",
                "severity": SEV_MEDIUM,
                "cve": "N/A (default-credential class)",
                "description": (
                    "A read-only SNMPv1 GET for sysDescr.0 with community "
                    f"`public` was answered: '{sysdescr}'. Any LAN host can "
                    "enumerate interfaces, ARP, routes and often the WLAN "
                    "table without any credential."
                ),
                "url": f"snmp://{host}:161/",
                "impact": (
                    "LAN-wide network/configuration disclosure; often the "
                    "first step toward targeted attacks on the gateway."
                ),
                "fix": (
                    "1. Change the SNMP community from `public` to a long random string\n"
                    "2. Prefer SNMPv3 with authPriv, or disable SNMP entirely\n"
                    "3. Restrict SNMP to a management host"
                ),
                "urls": [],
            })

    # --- Check 15 (v2): DNS version.bind disclosure (UDP) ---
    if probe_udp:
        dnsver = dns_version_probe(host)
        if dnsver:
            findings.append({
                "id": "GEN-016",
                "title": "DNS server discloses its version (version.bind)",
                "severity": SEV_INFO,
                "cve": "N/A (reconnaissance)",
                "description": (
                    f"CHAOS/TXT version.bind answered: '{dnsver}'. Minor on "
                    "its own — it tells an attacker exactly which dnsmasq/"
                    "BIND build to look up CVEs for."
                ),
                "url": f"dns://{host}/",
                "impact": "Aids targeted CVE lookup; no direct exploit.",
                "fix": (
                    "If the firmware allows it, set `version.bind` to refused "
                    "(`bind-interfaces` + no version string in dnsmasq)."
                ),
                "urls": [],
            })

    # --- Check 16 (v2): modern-HTTPD banner note (GoAhead/uhttpd/lighttpd) ---
    for _banner in (server, (info or {}).get("https_server") or ""):
        _match = re.search(r"(GoAhead|uhttpd|lighttpd|Allegro)[-/ ]?([0-9.]*)?",
                           _banner or "", re.I)
        if _match:
            findings.append({
                "id": "GEN-017",
                "title": f"Embedded httpd banner: {_match.group(0)}",
                "severity": SEV_INFO,
                "cve": "N/A (reconnaissance)",
                "description": (
                    f"Server banner '{_banner}' identifies the embedded "
                    "httpd. Version-specific CVEs (e.g. the GoAhead LD_PRELOAD "
                    "class on old builds) can only be matched once the exact "
                    "model/firmware is known — pass --model/--firmware from "
                    "the sticker."
                ),
                "url": f"http://{host}/",
                "impact": "Reconnaissance value only at this stage.",
                "fix": "Anchor the audit with sticker --model/--firmware and re-run.",
                "urls": [],
            })
            break

    return findings


# --------------------------------------------------------------------------- #
# Report Generation
# --------------------------------------------------------------------------- #

def generate_text_report(network_info: Dict, fingerprint: Dict,
                          open_ports: List[Dict], findings: List[Dict],
                          vendor: str,
                          identity: Optional[Dict] = None,
                          drift: Optional[Dict] = None,
                          prev_audit: Optional[Dict] = None,
                          extra: Optional[Dict] = None) -> str:
    """Generate a comprehensive text report."""
    lines: List[str] = []
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    lines.append("=" * 78)
    lines.append("  BUG HUNTER — ROUTER VULNERABILITY SCAN REPORT")
    lines.append(f"  Version {VERSION}")
    lines.append("=" * 78)
    lines.append("")
    lines.append(f"  Scan Date     : {now}")
    lines.append(f"  Scan Type     : {'PHYSICAL DEVICE AUDIT (live unit)' if identity else 'live LAN scan'}")
    lines.append(f"  Platform      : {network_info.get('platform', 'unknown')}")
    lines.append(f"  Hostname      : {network_info.get('hostname', 'unknown')}")
    lines.append(f"  Local IP      : {network_info.get('local_ip', 'unknown')}")
    lines.append(f"  Gateway IP    : {network_info.get('gateway', 'unknown')}")
    lines.append("")

    # Device fingerprint
    lines.append("-" * 78)
    lines.append("  DEVICE FINGERPRINT (what the unit says about itself)")
    lines.append("-" * 78)
    lines.append(f"  Detected Vendor    : {vendor.upper()}")
    lines.append(f"  Model              : {fingerprint.get('model', 'Unknown')}")
    if fingerprint.get("model_note"):
        lines.append(f"  Model (note)       : {fingerprint['model_note']}")
    if fingerprint.get("vendor_hint"):
        lines.append(f"  Vendor (note)      : {fingerprint['vendor_hint']}")
    lines.append(f"  Firmware           : {fingerprint.get('firmware', 'Unknown')}")
    if fingerprint.get("firmware_note"):
        lines.append(f"  Firmware (note)    : {fingerprint['firmware_note']}")
    lines.append(f"  Hardware Version   : {fingerprint.get('hardware_version', 'Unknown')}")
    if fingerprint.get("serial"):
        lines.append(f"  Serial (unit)      : {fingerprint['serial']}")
    if fingerprint.get("mac_addresses"):
        lines.append(f"  MACs seen          : {', '.join(fingerprint['mac_addresses'])}")
    lines.append(f"  HTTP Server        : {fingerprint.get('server_header', 'Unknown')}")
    lines.append(f"  HTTP Status        : {fingerprint.get('http_status', 'Unknown')}")
    if fingerprint.get("auth_scheme") or fingerprint.get("auth_realm"):
        realm = fingerprint.get("auth_realm") or "(none)"
        lines.append(f"  HTTP auth          : {fingerprint.get('auth_scheme') or '?'} realm={realm}")
    if "webproc_evidence" in fingerprint:
        lines.append("  webproc CGI        : "
                     + ("yes" if fingerprint.get("webproc_evidence") else "no"))
    if fingerprint.get("https_status") is not None or fingerprint.get("https_error"):
        lines.append(f"  HTTPS Status       : {fingerprint.get('https_status', fingerprint.get('https_error'))}")
    if fingerprint.get("https_server"):
        lines.append(f"  HTTPS Server       : {fingerprint['https_server']}")
    lines.append("")

    # Label / sticker identity of the physical unit
    if identity:
        lines.append("-" * 78)
        lines.append("  LABEL / STICKER IDENTITY (physical unit under audit)")
        lines.append("-" * 78)
        for key, label in (("model", "Model"), ("firmware", "Firmware"),
                            ("hardware_version", "Hardware rev"),
                            ("serial", "Serial"), ("mac", "MAC")):
            if identity.get(key):
                lines.append(f"    {label:12} : {identity[key]}")
        filled = fingerprint.get("label_fields")
        if filled:
            lines.append(f"    (label filled device fields the UI did not show: "
                         f"{', '.join(filled)})")
        for mm in fingerprint.get("label_mismatches", []):
            lines.append(f"    ! MISMATCH {mm['field']}: sticker says "
                         f"'{mm['label']}' but the unit reports '{mm['detected']}'")
        mac_match = fingerprint.get("mac_label_match")
        if mac_match is True:
            lines.append("    MAC check    : unit displayed the sticker MAC — "
                         "identity confirmed")
        elif mac_match is False:
            lines.append("    ! MAC check  : sticker MAC was NOT among the MACs the "
                         "unit displayed — verify you scanned the right box")
        lines.append("")

    # Open ports
    lines.append("-" * 78)
    lines.append("  OPEN PORTS & SERVICES")
    lines.append("-" * 78)
    if open_ports:
        for p in open_ports:
            lines.append(f"    Port {p['port']:>5}  —  {p['service']}")
    else:
        lines.append("    No common router ports detected as open.")
    lines.append("")

    # v2 deep-audit sections (only when those phases ran)
    extra = extra or {}
    wifi = extra.get("wifi") or {}
    if wifi.get("available"):
        lines.append("-" * 78)
        lines.append("  WIFI CONTEXT (this machine's uplink)")
        lines.append("-" * 78)
        if wifi.get("ssid"):
            lines.append(f"    SSID     : {wifi['ssid']}")
        if wifi.get("bssid"):
            lines.append(f"    BSSID    : {wifi['bssid']}")
        if wifi.get("signal"):
            lines.append(f"    Signal   : {wifi['signal']}")
        lines.append("")
    discovery = extra.get("discovery") or []
    if discovery:
        lines.append("-" * 78)
        lines.append("  LAN DISCOVERY (router candidates this run)")
        lines.append("-" * 78)
        for entry in discovery[:8]:
            marker = " <-- audited" if entry.get("audited") else ""
            title = (entry.get("title") or entry.get("server") or
                     entry.get("oui_vendor") or "no web banner")
            lines.append(f"    {entry['ip']:15} score={entry.get('router_score', 0)}  "
                         f"{str(title)[:52]}{marker}")
        lines.append("")
    auth = extra.get("auth") or {}
    if auth:
        lines.append("-" * 78)
        lines.append("  CREDENTIALED HTTP AUDIT (owner credentials)")
        lines.append("-" * 78)
        if auth.get("ok"):
            lines.append(f"    Login    : OK as '{auth.get('username')}' "
                         f"(source: {auth.get('source')}, via {auth.get('method')})")
            facts = auth.get("facts") or {}
            if facts.get("model"):
                lines.append(f"    Model (auth)   : {facts['model']}")
            if facts.get("firmware"):
                lines.append(f"    Firmware (auth): {facts['firmware']}")
            if facts.get("wan_ip"):
                lines.append(f"    WAN IP         : {facts['wan_ip']}")
            if facts.get("dns_servers"):
                lines.append(f"    DNS            : {', '.join(facts['dns_servers'])}")
            if facts.get("uptime"):
                lines.append(f"    Uptime         : {facts['uptime']}")
            lines.append(f"    Pages read     : {facts.get('pages_fetched', 0)}")
            if auth.get("config_backup"):
                lines.append(f"    Config backup  : {auth['config_backup']}")
        else:
            lines.append(f"    Login    : FAILED ({auth.get('evidence', '?')})")
        lines.append("")
    shell = extra.get("shell") or {}
    if shell:
        lines.append("-" * 78)
        lines.append("  CREDENTIALED SHELL AUDIT (read-only commands)")
        lines.append("-" * 78)
        if shell.get("ok"):
            facts = shell.get("facts") or {}
            lines.append(f"    Transport  : {shell.get('transport')} "
                         f"(uid={facts.get('uid')}, user={facts.get('shell_user')})")
            if facts.get("kernel"):
                lines.append(f"    Kernel     : {facts['kernel']}")
            if facts.get("cpu"):
                lines.append(f"    CPU        : {facts['cpu']}")
            if facts.get("uptime"):
                lines.append(f"    Uptime     : {facts['uptime']}")
            for part in (facts.get("mtd_partitions") or [])[:16]:
                lines.append(f"    MTD {part['dev']:8} {part['size']:>10} bytes  "
                             f"{part['name']}")
            if shell.get("transcript_path"):
                lines.append(f"    Transcript : {shell['transcript_path']} (redacted)")
        else:
            lines.append(f"    Shell    : FAILED ({shell.get('error', '?')})")
        lines.append("")
    dumps = extra.get("dumps") or []
    if dumps:
        lines.append("-" * 78)
        lines.append("  LOCAL DUMPS (mode 0600 — treat as secret)")
        lines.append("-" * 78)
        for dump in dumps:
            if dump.get("kind") == "mtd":
                lines.append(f"    MTD {dump.get('partition')}: {dump.get('bytes')} bytes, "
                             f"sha256 {(dump.get('sha256') or '?')[:32]}…")
                lines.append(f"        {dump.get('path')}")
            else:
                lines.append(f"    {dump.get('kind')}: {dump.get('path')}")
        lines.append("")

    # Findings summary
    sev_counts = {}
    for f in findings:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1

    lines.append("-" * 78)
    lines.append("  VULNERABILITY SUMMARY")
    lines.append("-" * 78)
    total = len(findings)
    lines.append(f"  Total Findings   : {total}")
    for sev in [SEV_CRITICAL, SEV_HIGH, SEV_MEDIUM, SEV_LOW, SEV_INFO]:
        count = sev_counts.get(sev, 0)
        bar = "!" * count if count else "-"
        lines.append(f"    {sev:10} : {count:>3}  {bar}")
    lines.append("")

    # Overall risk
    if sev_counts.get(SEV_CRITICAL, 0) > 0:
        risk = "CRITICAL — Immediate action required"
    elif sev_counts.get(SEV_HIGH, 0) > 0:
        risk = "HIGH — Prompt remediation recommended"
    elif sev_counts.get(SEV_MEDIUM, 0) > 0:
        risk = "MEDIUM — Security improvements needed"
    elif total > 0:
        risk = "LOW — Minor issues found"
    else:
        risk = "NONE REPORTED — checks that ran did not match; not a guarantee"
    lines.append(f"  Overall Risk     : {risk}")
    lines.append("")

    # Drift against the previous physical audit of the same unit
    if drift is not None:
        prev_ts = (prev_audit or {}).get("timestamp", "unknown time")
        lines.append("-" * 78)
        lines.append("  AUDIT DRIFT — vs previous hunt of this same unit")
        lines.append("-" * 78)
        lines.append(f"  Previous audit : {prev_ts}")
        if drift["new"]:
            lines.append(f"  NEW findings since then      : {', '.join(drift['new'])}")
        else:
            lines.append("  NEW findings since then      : none")
        if drift["resolved"]:
            lines.append(f"  RESOLVED since then          : {', '.join(drift['resolved'])}")
        else:
            lines.append("  RESOLVED since then          : none")
        lines.append(f"  STILL PRESENT                : "
                     f"{', '.join(drift['persistent']) or 'none'}")
        lines.append("")

    # Detailed findings
    lines.append("=" * 78)
    lines.append("  DETAILED FINDINGS")
    lines.append("=" * 78)

    if not findings:
        lines.append("")
        lines.append("  No vulnerabilities detected in the automated checks.")
        lines.append("  This does NOT guarantee the device is secure.")
        lines.append("  Manual review and firmware updates are always recommended.")
    else:
        for f in findings:
            lines.append("")
            lines.append(f"  ┌─── [{f['id']}] {f['severity']}: {f['title']}")
            lines.append(f"  │")
            lines.append(f"  │  CVE/Reference : {f.get('cve', 'N/A')}")
            if f.get('cvss'):
                lines.append(f"  │  CVSS Score    : {f['cvss']}")
            if f.get('confidence'):
                lines.append(f"  │  Confidence    : {f['confidence']}")
            lines.append(f"  │  Severity      : {f['severity']}")
            lines.append(f"  │  Target URL    : {f.get('url', 'N/A')}")
            lines.append(f"  │")
            lines.append(f"  │  DESCRIPTION:")
            for dl in f.get("description", "").split("\n"):
                lines.append(f"  │    {dl}")
            lines.append(f"  │")
            lines.append(f"  │  IMPACT:")
            for dl in f.get("impact", "").split("\n"):
                lines.append(f"  │    {dl}")
            lines.append(f"  │")
            lines.append(f"  │  HOW TO FIX:")
            for dl in f.get("fix", "").split("\n"):
                lines.append(f"  │    {dl}")
            lines.append(f"  │")
            if f.get("urls"):
                lines.append(f"  │  REFERENCE URLS:")
                for u in f["urls"]:
                    lines.append(f"  │    → {u}")
            lines.append(f"  │")
            lines.append(f"  └{'─' * 76}")

    # General recommendations
    lines.append("")
    lines.append("=" * 78)
    lines.append("  GENERAL SECURITY RECOMMENDATIONS")
    lines.append("=" * 78)
    lines.append("")
    lines.append("  1.  CHANGE DEFAULT CREDENTIALS")
    lines.append("      Always change the default admin password and Wi-Fi passphrase.")
    lines.append("      Use strong, unique passwords (12+ characters, mixed case, numbers).")
    lines.append("")
    lines.append("  2.  KEEP FIRMWARE UPDATED")
    lines.append("      Check the manufacturer's website regularly for security updates.")
    lines.append("      ISP-branded firmware may need to be requested from your provider.")
    lines.append("")
    lines.append("  3.  DISABLE WAN/REMOTE MANAGEMENT")
    lines.append("      The admin panel should never be accessible from the internet.")
    lines.append("      Check that ports 80, 8080, 443 are NOT forwarded from WAN.")
    lines.append("")
    lines.append("  4.  DISABLE UNNECESSARY SERVICES")
    lines.append("      Turn off: UPnP, Telnet, FTP, SNMP, TR-069 if not needed.")
    lines.append("      Each enabled service is an additional attack surface.")
    lines.append("")
    lines.append("  5.  USE WPA2/WPA3 FOR WI-FI")
    lines.append("      Disable WEP and WPA(1). Use WPA2-PSK (AES) or WPA3.")
    lines.append("      Change the Wi-Fi passphrase periodically.")
    lines.append("")
    lines.append("  6.  ENABLE FIREWALL")
    lines.append("      Ensure the router's built-in firewall is enabled.")
    lines.append("      Review port forwarding rules — remove any you don't need.")
    lines.append("")
    lines.append("  7.  DISABLE WPS")
    lines.append("      Wi-Fi Protected Setup (WPS) has known PIN brute-force weaknesses.")
    lines.append("      Disable it in the wireless settings.")
    lines.append("")
    lines.append("  8.  CONSIDER REPLACING EOL DEVICES")
    lines.append("      If your router is end-of-life and no longer receiving security")
    lines.append("      updates, replacement is the most reliable fix.")
    lines.append("")
    lines.append("  9.  BRIDGE ISP MODEMS")
    lines.append("      For ISP-provided modems (PTCL, etc.), bridge mode and use your")
    lines.append("      own router behind it. This gives you control over firmware and")
    lines.append("      security settings.")
    lines.append("")
    lines.append("  10. MONITOR CONNECTED DEVICES")
    lines.append("      Regularly check the DHCP client list for unknown devices.")
    lines.append("      Use MAC filtering if appropriate for your network.")
    lines.append("")

    lines.append("=" * 78)
    lines.append(f"  END OF REPORT — Generated by Bug Hunter v{VERSION}")
    lines.append(f"  DISCLAIMER: unauthenticated phases are READ-ONLY; credentialed")
    lines.append(f"  phases (--username/--check-defaults/--shell/--dump-*) only READ,")
    lines.append(f"  using credentials you supplied, and never modify the router.")
    lines.append(f"  Secrets are redacted; dumps are local 0600 files. Audit only")
    lines.append(f"  equipment you own or are authorised to test.")
    lines.append("=" * 78)

    return "\n".join(lines)


def generate_json_report(network_info: Dict, fingerprint: Dict,
                          open_ports: List[Dict], findings: List[Dict],
                          vendor: str,
                          identity: Optional[Dict] = None,
                          drift: Optional[Dict] = None,
                          prev_audit: Optional[Dict] = None,
                          extra: Optional[Dict] = None) -> Dict:
    """Generate a JSON-serializable report."""
    report = {
        "tool": "Bug Hunter",
        "version": VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "scan_type": "physical_device_audit" if identity else "live_lan_scan",
        "network": {
            "platform": network_info.get("platform"),
            "hostname": network_info.get("hostname"),
            "local_ip": network_info.get("local_ip"),
            "gateway": network_info.get("gateway"),
        },
        "device": {
            "vendor": vendor,
            "model": fingerprint.get("model"),
            "firmware": fingerprint.get("firmware"),
            "firmware_note": fingerprint.get("firmware_note"),
            "hardware_version": fingerprint.get("hardware_version"),
            "serial": fingerprint.get("serial"),
            "mac_addresses": fingerprint.get("mac_addresses") or [],
            "server_header": fingerprint.get("server_header"),
            "http_status": fingerprint.get("http_status"),
            "https_status": fingerprint.get("https_status"),
            "https_server": fingerprint.get("https_server"),
            "https_error": fingerprint.get("https_error"),
            "auth_scheme": fingerprint.get("auth_scheme"),
            "auth_realm": fingerprint.get("auth_realm"),
            "webproc_evidence": fingerprint.get("webproc_evidence"),
            "model_note": fingerprint.get("model_note"),
        },
        "label_identity": identity or {},
        "label_check": {
            "filled_fields": fingerprint.get("label_fields", []),
            "mismatches": fingerprint.get("label_mismatches", []),
            "mac_label_match": fingerprint.get("mac_label_match"),
        },
        "open_ports": open_ports,
        "summary": {
            "total_findings": len(findings),
            "by_severity": {
                sev: len([f for f in findings if f["severity"] == sev])
                for sev in [SEV_CRITICAL, SEV_HIGH, SEV_MEDIUM, SEV_LOW, SEV_INFO]
            },
        },
        "findings": findings,
    }
    if extra:
        # v2 deep-audit artefacts (passwords are never present in `extra`).
        for key in ("wifi", "discovery", "auth", "shell", "dumps"):
            if extra.get(key):
                report[key] = extra[key]
    if drift is not None:
        report["drift"] = {
            "previous_audit": (prev_audit or {}).get("timestamp"),
            **drift,
        }
    return report


# --------------------------------------------------------------------------- #
# Audit persistence & drift (physical hunt mode)
# --------------------------------------------------------------------------- #

AUDIT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "audits")

_AUDIT_NAME_RE = re.compile(
    r"^.+_(?P<host>[0-9A-Fa-f.:]+)_(?P<stamp>\d{8}T\d{6}Z)\.json$")


def audit_slug(text: str) -> str:
    """Filesystem-safe slug for the unit's model string."""
    s = re.sub(r"[^A-Za-z0-9._-]+", "_", (text or "router")).strip("_")
    return s or "router"


def save_audit(result: Dict, report_text: str, json_report: Dict) -> Tuple[str, str]:
    """Save the hunt as an audit artifact under audits/. Returns (txt, json)."""
    os.makedirs(AUDIT_DIR, exist_ok=True)
    model = ((result.get("fingerprint") or {}).get("model")
             or (result.get("identity") or {}).get("model")
             or "router")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    base = f"{audit_slug(model)}_{result['target'].replace(':', '_')}_{stamp}"
    txt_path = os.path.join(AUDIT_DIR, base + ".txt")
    json_path = os.path.join(AUDIT_DIR, base + ".json")
    with open(txt_path, "w", encoding="utf-8") as fh:
        fh.write(report_text)
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(json_report, fh, indent=2, ensure_ascii=False)
    return txt_path, json_path


def load_previous_audit(target_host: str, exclude_path: str = "") -> Optional[Dict]:
    """Load the newest saved audit JSON for the same target host, if any."""
    if not os.path.isdir(AUDIT_DIR):
        return None
    host_slug = target_host.replace(":", "_")
    candidates = []
    try:
        names = os.listdir(AUDIT_DIR)
    except OSError:
        return None
    for name in names:
        m = _AUDIT_NAME_RE.match(name)
        if not m or m.group("host") != host_slug:
            continue
        full = os.path.join(AUDIT_DIR, name)
        if exclude_path and os.path.abspath(full) == os.path.abspath(exclude_path):
            continue
        candidates.append((m.group("stamp"), full))
    if not candidates:
        return None
    candidates.sort()
    try:
        with open(candidates[-1][1], "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None


def diff_findings(previous: List[Dict], current: List[Dict]) -> Dict[str, List[str]]:
    """Compare two finding lists by id: what is new / resolved / persistent."""
    prev_ids = {f.get("id", "?") for f in previous or []}
    now_ids = {f.get("id", "?") for f in current or []}
    return {
        "new": sorted(now_ids - prev_ids),
        "resolved": sorted(prev_ids - now_ids),
        "persistent": sorted(prev_ids & now_ids),
    }


# --------------------------------------------------------------------------- #
# Main Scanner Logic
# --------------------------------------------------------------------------- #

def run_scan(target_host: str, target_port: int = 80,
             probe_upnp: bool = False, probe_rom0: bool = False,
             quick: bool = False, force_vendor: str = "",
             verbose: bool = False, timeout: float = 8.0,
             identity: Optional[Dict[str, str]] = None,
             username: str = "", password: str = "",
             check_defaults: bool = False, shell: str = "",
             dump_config: bool = False, dump_mtd: str = "",
             probe_udp: bool = False, audit_dir: str = "",
             confirm: bool = False) -> Dict:
    """Execute the full vulnerability scan against the live, physical device.

    `identity` (optional) is the sticker/label identity of the unit — model,
    firmware, HW revision, serial, MAC. It never changes what is probed; it
    anchors the audit to the physical box: fields the device does not report
    are filled from the label, and contradictions between label and unit are
    flagged as mismatches in the report.

    v2 credentialed phases (all LAN-only, all explicit):
      * `username`/`password` — owner creds for the HTTP deep audit
      * `check_defaults` — try the short well-known-default list (slow)
      * `shell` — "telnet"|"ssh"|"auto": read-only shell audit with creds
      * `dump_config` — download config backup over the authed session
      * `dump_mtd` — "all"|"mtdN": low-level MTD dump over the shell
    Passwords are used for login only — never printed, never stored in `result`.
    """

    result: Dict[str, Any] = {
        "target": target_host,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "network_info": {
            "platform": detect_platform(),
            "hostname": None,
            "local_ip": None,
            "gateway": target_host,
        },
        "identity": identity or {},
        "fingerprint": {},
        "open_ports": [],
        "vendor": "",
        "findings": [],
        "auth": {},
        "shell": {},
        "dumps": [],
        "error": None,
    }

    try:
        result["network_info"]["hostname"] = platform.node() or socket.gethostname()
        result["network_info"]["local_ip"] = get_local_ip()
    except Exception:
        pass

    # Verify target is LAN-local
    resolved = resolve_private(target_host)
    if not resolved:
        result["error"] = (
            f"{target_host} does not resolve to a private/LAN address. "
            "This tool only scans devices on your own network."
        )
        return result

    # Step 1: Port scan
    print(f"\n[*] Scanning ports on {target_host}...")
    ports_to_scan = COMMON_PORTS
    if quick:
        ports_to_scan = [(p, n) for p, n in COMMON_PORTS if p in (22, 23, 80, 443, 8080)]

    result["open_ports"] = scan_ports(target_host, ports_to_scan, timeout=min(timeout, 3))
    print(f"    Found {len(result['open_ports'])} open port(s)")
    for p in result["open_ports"]:
        print(f"      Port {p['port']} — {p['service']}")

    # Step 2: HTTP fingerprinting
    print(f"\n[*] Fingerprinting HTTP service...")
    # --port 443 means the caller already pointed us at the TLS admin port.
    client = HttpClient(target_host, target_port, timeout=timeout,
                        verbose=verbose, tls=(target_port == 443))

    base_resp = client.get("/", use_cookies=False)
    wp_resp = client.get(NEUTRAL_WEBPROC)
    ident = classify_http_identity(
        base_resp, wp_resp, NEUTRAL_WEBPROC, client.server_header)
    fingerprint = {
        "server_header": client.server_header,
        "http_status": ident["http_status"],
        "webproc_evidence": ident["webproc_evidence"],
        "auth_scheme": ident["auth_scheme"],
        "auth_realm": ident["auth_realm"],
    }
    text = ident["text"]
    vendor = ident["vendor"]
    # Record Basic-on-cleartext before a later HTTPS client can hide it.
    if (not client.tls and (ident.get("auth_scheme") or "").lower() == "basic"):
        fingerprint["basic_on_cleartext"] = True

    # Port 443 open, and we have not already fingerprinted it as the primary
    # client. Read-only GET, self-signed CPE certs accepted, no credentials.
    https_open = any(p["port"] == 443 for p in result["open_ports"])
    if https_open and not client.tls:
        print("\n[*] Fingerprinting HTTPS (read-only; router cert is not verified)...")
        https_client = HttpClient(
            target_host, 443, timeout=timeout, verbose=verbose, tls=True)
        h_base = https_client.get("/", use_cookies=False)
        h_wp = https_client.get(NEUTRAL_WEBPROC) if h_base is not None else None
        if h_base is None and h_wp is None:
            fingerprint["https_error"] = "TLS handshake or HTTP response failed"
            print("    HTTPS did not complete a handshake")
        else:
            h_ident = classify_http_identity(
                h_base, h_wp, NEUTRAL_WEBPROC, https_client.server_header)
            fingerprint["https_status"] = h_ident["http_status"]
            fingerprint["https_server"] = https_client.server_header
            print(f"    HTTPS status {h_ident['http_status']}, "
                  f"server {https_client.server_header or 'none'}")
            if not fingerprint.get("auth_realm") and h_ident.get("auth_realm"):
                fingerprint["auth_scheme"] = h_ident["auth_scheme"]
                fingerprint["auth_realm"] = h_ident["auth_realm"]
            fingerprint["webproc_evidence"] = (
                fingerprint["webproc_evidence"] or h_ident["webproc_evidence"])
            text = text + "\n" + h_ident["text"]
            if vendor == "generic" and h_ident["vendor"] != "generic":
                vendor = h_ident["vendor"]
            # Prefer the origin that actually served a page for the vuln checks.
            http_rejected = ident["http_status"] in (None, 401, 403)
            https_served = h_ident["http_status"] not in (None, 401, 403)
            if http_rejected and (https_served or h_ident["webproc_evidence"]):
                client = https_client
                if not fingerprint.get("server_header"):
                    fingerprint["server_header"] = https_client.server_header

    # Sticker-implied vendor: if the UI did not self-identify but the label on
    # the physical unit says D-Link DSL/DIR/DVA, run the D-Link checks anyway.
    if vendor == "generic" and identity and re.match(
            r"(?i)^(?:DSL|DIR|DVA)-\d+", identity.get("model", "")):
        fingerprint["vendor_hint"] = (
            f"UI did not self-identify; vendor taken from the sticker model "
            f"'{identity['model']}'")
        vendor = "dlink"

    fingerprint.update(extract_info(text, vendor))
    # Realm can carry the model ("DSL-2640B") even when the body was a 401.
    if not fingerprint.get("model") and fingerprint.get("auth_realm"):
        realm_info = extract_info(fingerprint["auth_realm"], vendor)
        if realm_info.get("model"):
            fingerprint["model"] = realm_info["model"]
            fingerprint["model_note"] = (
                "model taken from the WWW-Authenticate realm, not the page body"
            )

    # Firmware-build classification (PTCL PT_* builds: untested by CVE lists)
    fingerprint["firmware_note"] = classify_firmware_build(
        fingerprint.get("firmware") or (identity or {}).get("firmware") or "")

    # Cross-check the sticker/label identity against the unit's self-report
    if identity:
        merge_identity(fingerprint, identity)

    annotate_missing_model(fingerprint, vendor)

    if force_vendor:
        vendor = force_vendor.lower()

    result["vendor"] = vendor
    result["fingerprint"] = fingerprint
    print(f"    Vendor: {vendor.upper()}")
    print(f"    Model: {fingerprint.get('model', 'Unknown')}")
    print(f"    Firmware: {fingerprint.get('firmware', 'Unknown')}")
    print(f"    Server: {fingerprint.get('server_header', 'Unknown')}")
    if identity:
        mm = fingerprint.get("label_mismatches", [])
        match_note = fingerprint.get("mac_label_match")
        print(f"    Sticker: {identity.get('model', '?')} / "
              f"{identity.get('firmware', '?')} / "
              f"HW {identity.get('hardware_version', '?')}"
              + (f"  [! {len(mm)} mismatch(es)]" if mm else "")
              + ("  [MAC confirmed]" if match_note is True else ""))

    # Step 3: Vendor-specific checks
    print(f"\n[*] Running {vendor.upper()} vulnerability checks...")

    if vendor == "dlink":
        findings = check_dlink_vulns(client, target_host, fingerprint)
    elif vendor == "zte":
        findings = check_zte_vulns(client, target_host, fingerprint,
                                    probe_upnp=probe_upnp)
    elif vendor == "tplink":
        findings = check_tplink_vulns(client, target_host, fingerprint,
                                       probe_rom0=probe_rom0)
    else:
        findings = []

    print(f"    Found {len(findings)} vendor-specific issue(s)")

    # Step 4: Generic checks
    print(f"\n[*] Running generic security checks...")
    gen_findings = check_generic_vulns(
        client, target_host, fingerprint,
        result["open_ports"], probe_rom0=probe_rom0,
        probe_udp=probe_udp,
    )
    findings.extend(gen_findings)
    print(f"    Found {len(gen_findings)} generic issue(s)")

    # --- v2 Step 5: credentialed HTTP audit (owner creds and/or defaults) ---
    creds: Optional[Tuple[str, str]] = None
    creds_source = ""
    auth_client = None
    auth_method = ""
    if username and password:
        creds = (username, password)
        creds_source = "operator"
    if check_defaults:
        print(f"\n[*] Checking well-known default HTTP credentials (slow, explicit)...")
        if _auth_mod is None:
            print("    auth_audit.py not found next to bug_hunter.py — skipping.")
        else:
            hit = None
            for default_u, default_p in _auth_mod.DEFAULT_CREDS:
                attempt = _auth_mod.attempt_http_login(
                    resolved, default_u, default_p, port=target_port,
                    tls=(target_port == 443), timeout=timeout, verbose=verbose)
                if attempt["ok"]:
                    hit = (default_u, attempt)
                    break
                time.sleep(1.0)
            if hit:
                default_u, attempt = hit
                auth_client = attempt["client"]
                auth_method = attempt["method"]
                print(f"    [!] DEFAULT CREDENTIALS WORK: user '{default_u}' "
                      f"via {auth_method}")
                findings.append({
                    "id": "AUTH-001",
                    "title": f"Default HTTP credentials active (user '{default_u}')",
                    "severity": SEV_CRITICAL,
                    "confidence": "CONFIRMED",
                    "cve": "N/A (default-credential class)",
                    "description": (
                        f"Login as '{default_u}' with a factory-default password "
                        f"was accepted via {auth_method}. Anyone on the LAN gets "
                        "the same admin session. (The password itself is not "
                        "shown here by design.)"
                    ),
                    "url": f"http://{target_host}/",
                    "impact": ("Full admin UI access for any LAN client; the "
                               "deep-audit phases below ran with these defaults."),
                    "fix": ("1. Change the admin password NOW (long, unique)\n"
                            "2. Disable any default/guest accounts\n"
                            "3. Re-run with --username/--password to verify"),
                    "urls": [],
                })
                if creds is None:
                    for du, dp in _auth_mod.DEFAULT_CREDS:
                        if du == default_u:
                            # Re-verify this exact pair to bind user->password.
                            verify = _auth_mod.attempt_http_login(
                                resolved, du, dp, port=target_port,
                                tls=(target_port == 443), timeout=timeout)
                            if verify["ok"]:
                                creds = (du, dp)
                                creds_source = "default"
                                auth_client = verify["client"]
                                auth_method = verify["method"]
                                break
            else:
                print("    No well-known default credential worked.")
    if creds is not None and _auth_mod is not None:
        if auth_client is None:
            print(f"\n[*] Logging in with operator credentials (user '{creds[0]}')...")
            login = _auth_mod.attempt_http_login(
                resolved, creds[0], creds[1], port=target_port,
                tls=(target_port == 443), timeout=timeout, verbose=verbose)
            if login["ok"]:
                auth_client = login["client"]
                auth_method = login["method"]
                print(f"    Login OK via {auth_method}.")
            else:
                print(f"    Login failed: {login['evidence']}")
                result["auth"] = {"ok": False, "username": creds[0],
                                  "source": creds_source,
                                  "evidence": login["evidence"]}
        else:
            print(f"\n[*] Authenticated session ready (user '{creds[0]}', "
                  f"source: {creds_source}, via {auth_method}).")
        if auth_client is not None:
            print(f"[*] Running post-login enumeration...")
            try:
                auth_facts, auth_findings = _auth_mod.authenticated_enum(
                    auth_client, resolved, verbose=verbose)
            except Exception as exc:  # noqa: BLE001 — keep the audit going
                auth_facts, auth_findings = {"error": str(exc)}, []
            findings.extend(auth_findings)
            print(f"    Post-login: {len(auth_findings)} finding(s), "
                  f"{auth_facts.get('pages_fetched', 0)} page(s) read")
            result["auth"] = {"ok": True, "username": creds[0],
                              "source": creds_source, "method": auth_method,
                              "facts": auth_facts}
            if dump_config:
                print(f"[*] Downloading config backup (local file, mode 0600)...")
                try:
                    cfg_path = _auth_mod.download_config_backup(
                        auth_client, resolved,
                        audit_dir or AUDIT_DIR)
                except Exception as exc:  # noqa: BLE001
                    cfg_path = None
                    print(f"    Config download error: {exc}")
                if cfg_path:
                    print(f"    [+] Config backup saved: {cfg_path}")
                    result["auth"]["config_backup"] = cfg_path
                    result["dumps"].append({"kind": "config-backup",
                                            "path": cfg_path})
                    findings.append({
                        "id": "AUTH-006",
                        "title": "Config backup saved locally for offline review",
                        "severity": SEV_INFO,
                        "confidence": "CONFIRMED",
                        "cve": "N/A (audit artifact)",
                        "description": (
                            "The authenticated backup endpoint was downloaded "
                            "to the local audits/ directory (mode 0600). "
                            "Treat it as SECRET — it contains credentials."),
                        "url": cfg_path,
                        "impact": "None — local audit artifact.",
                        "fix": "Review offline, store encrypted, delete when done.",
                        "urls": [],
                    })
                else:
                    print("    No backup endpoint answered with binary content.")
    elif (username or password) and not (username and password):
        print("\n[!] --username needs --password too (or use --check-defaults). "
              "Credentialed phases skipped.")
    elif dump_config and creds is None:
        print("\n[!] --dump-config needs --username/--password (or --check-defaults).")

    # --- v2 Step 6: credentialed shell audit + low-level MTD dump ---
    want_shell = shell.strip().lower() if shell else ""
    if dump_mtd and not want_shell:
        want_shell = "auto"  # dump implies a shell session for the MTD layout
    if want_shell:
        if _shell_mod is None:
            print("\n[!] shell_audit.py not found next to bug_hunter.py — skipping.")
        elif creds is None:
            print("\n[!] --shell needs --username/--password (or --check-defaults).")
        else:
            transport = want_shell
            if transport == "auto":
                telnet_open = any(p["port"] == 23 for p in result["open_ports"])
                ssh_open = any(p["port"] == 22 for p in result["open_ports"])
                transport = ("telnet" if telnet_open else
                             "ssh" if ssh_open else "telnet")
            print(f"\n[*] Opening {transport} shell as '{creds[0]}' "
                  f"(read-only commands)...")
            via_defaults = (creds_source == "default")
            shell_res: Dict[str, Any] = {}
            try:
                if transport == "ssh":
                    shell_res = _shell_mod.run_ssh_audit(
                        resolved, creds[0], password=creds[1],
                        timeout=int(timeout), verbose=verbose,
                        via_defaults=via_defaults)
                else:
                    shell_res = _shell_mod.run_telnet_audit(
                        resolved, creds[0], creds[1],
                        timeout=timeout, verbose=verbose,
                        via_defaults=via_defaults)
            except Exception as exc:  # noqa: BLE001
                shell_res = {"ok": False, "transport": transport,
                             "error": str(exc), "facts": {}, "findings": []}
            if shell_res.get("ok"):
                print(f"    Shell OK: uid={shell_res['facts'].get('uid')} "
                      f"({shell_res['facts'].get('shell_user')})")
                if shell_res["facts"].get("mtd_partitions"):
                    print(f"    MTD: {len(shell_res['facts']['mtd_partitions'])} "
                          f"partitions, "
                          f"{shell_res['facts'].get('mtd_total_bytes', 0)} bytes total")
                try:
                    tpath = _shell_mod.save_shell_transcript(
                        audit_dir or AUDIT_DIR, resolved, transport,
                        shell_res.get("transcript", ""))
                    shell_res["transcript_path"] = tpath
                    print(f"    Transcript (redacted): {tpath}")
                except OSError as exc:
                    print(f"    Could not save transcript: {exc}")
                findings.extend(shell_res.get("findings", []))
            else:
                print(f"    Shell failed: {shell_res.get('error')}")
            shell_res.pop("transcript", None)  # file holds it; keep JSON lean
            result["shell"] = shell_res

            # --- v2 Step 7: MTD dump (explicit + confirmed) ---
            if dump_mtd and shell_res.get("ok"):
                parts = shell_res.get("facts", {}).get("mtd_partitions", [])
                if dump_mtd.strip().lower() == "all":
                    wanted = [p["dev"] for p in parts]
                else:
                    wanted = [d.strip() for d in dump_mtd.split(",") if d.strip()]
                if not wanted:
                    print("    No MTD partitions known — dump skipped.")
                else:
                    total = sum(next((p["size"] for p in parts
                                      if p["dev"] == w), 0) for w in wanted)
                    ok_to_dump = confirm
                    if not ok_to_dump:
                        try:
                            import sys as _sys
                            if _sys.stdin.isatty():
                                ans = input(
                                    f"    Dump {len(wanted)} partition(s) "
                                    f"(~{total // 1024} KiB) to audits/? [y/N] "
                                ).strip().lower()
                                ok_to_dump = ans in ("y", "yes")
                            else:
                                print("    Non-interactive: pass --yes to confirm --dump-mtd.")
                        except (EOFError, KeyboardInterrupt):
                            ok_to_dump = False
                    if not ok_to_dump:
                        print("    MTD dump not confirmed — skipped.")
                    else:
                        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                        outdir = audit_dir or AUDIT_DIR
                        os.makedirs(outdir, exist_ok=True)
                        for dev in wanted:
                            outpath = os.path.join(
                                outdir,
                                f"mtd_{resolved.replace(':', '_')}_{dev}_{stamp}.bin")
                            print(f"    [*] dumping /dev/{dev} -> {outpath} ...")
                            try:
                                if transport == "ssh":
                                    dres = _shell_mod.dump_mtd_via_ssh(
                                        resolved, creds[0], dev, outpath,
                                        password=creds[1], verbose=verbose)
                                else:
                                    dres = _shell_mod.dump_mtd_via_telnet(
                                        resolved, creds[0], creds[1], dev, outpath,
                                        verbose=verbose)
                            except Exception as exc:  # noqa: BLE001
                                dres = {"ok": False, "error": str(exc)}
                            if dres.get("ok"):
                                print(f"    [+] {dev}: {dres['bytes']} bytes, "
                                      f"sha256 {dres['sha256'][:16]}…")
                                result["dumps"].append(
                                    {"kind": "mtd", "partition": dev,
                                     "path": outpath, "bytes": dres["bytes"],
                                     "sha256": dres["sha256"]})
                            else:
                                print(f"    [!] {dev} failed: {dres.get('error')}")
                        if any(d.get("kind") == "mtd" for d in result["dumps"]):
                            findings.append({
                                "id": "SHELL-002",
                                "title": "Low-level MTD dump saved locally",
                                "severity": SEV_INFO,
                                "confidence": "CONFIRMED",
                                "cve": "N/A (audit artifact)",
                                "description": (
                                    "MTD partition(s) were read over the "
                                    "owner-credentialed shell and saved under "
                                    "audits/ (mode 0600, SHA-256 recorded). "
                                    "Analyse offline with: python3 bug_hunter.py "
                                    "--analyze-firmware <file>"),
                                "url": outdir,
                                "impact": "None — local audit artifact.",
                                "fix": "Store encrypted; delete when done.",
                                "urls": [],
                            })
            elif dump_mtd and not shell_res.get("ok"):
                print("    MTD dump needs a working shell — skipped.")

    result["findings"] = findings

    # Summary
    total = len(findings)
    crit = len([f for f in findings if f["severity"] == SEV_CRITICAL])
    high = len([f for f in findings if f["severity"] == SEV_HIGH])
    print(f"\n[*] Scan complete: {total} findings ({crit} critical, {high} high)")

    return result


# --------------------------------------------------------------------------- #
# CLI Entry Point
# --------------------------------------------------------------------------- #

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Bug Hunter — Cross-Platform Router Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
PHYSICAL HUNT (the real thing — audit the unit in front of you):
  python bug_hunter.py                      # auto-detect your gateway, audit it
  python bug_hunter.py 192.168.10.1 --audit # audit a PTCL unit, save + drift
  python bug_hunter.py 192.168.10.1 --audit --model DSL-226 \\
      --firmware PT_1.10_J2 --hw J2 --serial <sticker> --mac <sticker>

AUTO-DISCOVERY (v2 — smooth WiFi flow, many routers at once):
  python bug_hunter.py --auto              # WiFi context + subnet sweep + audit best
  python bug_hunter.py --discover          # list every router candidate on the LAN
  python bug_hunter.py --discover --audit  # audit each candidate, save all

CREDENTIALED DEEP AUDIT (v2 — your OWN router, your OWN password):
  python bug_hunter.py 192.168.1.1 -u admin            # prompt for password, deep audit
  python bug_hunter.py --auto -u admin --shell auto    # + read-only root shell audit
  python bug_hunter.py 192.168.1.1 --check-defaults    # well-known defaults only, slow
  python bug_hunter.py 192.168.1.1 -u admin --dump-config
  python bug_hunter.py 192.168.1.1 -u admin --shell telnet --dump-mtd all --yes

OFFLINE FIRMWARE ANALYSIS (v2 — local file, nothing uploaded):
  python bug_hunter.py --analyze-firmware mtd_mtd5_*.bin
  python bug_hunter.py --analyze-firmware vendor-firmware.bin

OTHER EXAMPLES:
  python bug_hunter.py 192.168.1.1         # scan specific router IP
  python bug_hunter.py --report out.txt    # save text report to file
  python bug_hunter.py --json out.json     # save JSON report
  python bug_hunter.py --quick             # fast scan (skip slow probes)
  python bug_hunter.py --probe-upnp        # enable UPnP WLAN key probe (ZTE)
  python bug_hunter.py --probe-rom0        # enable rom-0 backup download (TP-Link)
  python bug_hunter.py --probe-udp         # enable SNMP/DNS UDP probes (read-only)
  python bug_hunter.py --vendor dlink      # force vendor detection
  python bug_hunter.py -v                  # verbose output

SAFETY:
  Unauthenticated phases are READ-ONLY (GET/HEAD, one SNMP GET / DNS TXT with
  --probe-udp). Credentialed phases (--username, --check-defaults, --shell,
  --dump-*) use passwords YOU supply (or well-known defaults with the explicit
  flag), only against LAN addresses, only to READ (enumerate / dump to local
  0600 files). Nothing here brute-forces beyond the short default list,
  cracks, hijacks, or escalates without credentials. Audit only equipment
  you own or are authorised to test.
        """
    )

    parser.add_argument("target", nargs="?", default=None,
                        help="Router/gateway IP (auto-detect if omitted)")
    parser.add_argument("--audit", action="store_true",
                        help="PHYSICAL AUDIT MODE — save the hunt to audits/ "
                             "model-stamped, and diff against the previous "
                             "audit of the same unit (new/resolved/persistent)")
    parser.add_argument("--model",
                        help="model from the unit's sticker (e.g. DSL-226)")
    parser.add_argument("--firmware",
                        help="firmware string from the sticker/UI (e.g. PT_1.10_J2)")
    parser.add_argument("--hw",
                        help="hardware revision from the sticker (e.g. J2)")
    parser.add_argument("--serial",
                        help="serial number from the sticker")
    parser.add_argument("--mac",
                        help="MAC address from the sticker")
    parser.add_argument("--port", type=int, default=80,
                        help="HTTP port (default: 80)")
    parser.add_argument("--report", "-o", metavar="FILE",
                        help="Save text report to file")
    parser.add_argument("--json", metavar="FILE",
                        help="Save JSON report to file")
    parser.add_argument("--quick", action="store_true",
                        help="Quick scan — fewer ports, skip slow probes")
    parser.add_argument("--probe-upnp", action="store_true",
                        help="Enable UPnP WLAN key probe (ZTE devices)")
    parser.add_argument("--probe-rom0", action="store_true",
                        help="Enable rom-0 config backup check (TP-Link)")
    parser.add_argument("--vendor", choices=["dlink", "zte", "tplink", "huawei",
                                              "netgear", "linksys", "fiberhome",
                                              "asus", "tenda", "totolink", "cisco",
                                              "mikrotik", "ubiquiti", "draytek",
                                              "belkin", "trendnet", "xiaomi",
                                              "mercusys", "openwrt", "generic"],
                        help="Force vendor (skip auto-detection)")
    parser.add_argument("--timeout", type=float, default=8.0,
                        help="HTTP timeout in seconds (default: 8)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output")
    parser.add_argument("--no-banner", action="store_true",
                        help="Suppress startup banner")
    # --- v2: discovery / credentialed / dump / firmware flags ---
    parser.add_argument("--auto", action="store_true",
                        help="Smooth flow: WiFi context + subnet sweep + audit "
                             "the best router candidate (falls back from gateway)")
    parser.add_argument("--discover", action="store_true",
                        help="Sweep the LAN, rank router candidates, audit each "
                             "(up to --max-targets)")
    parser.add_argument("--subnet", metavar="CIDR",
                        help="Subnet to sweep (default: derived from interface)")
    parser.add_argument("--max-targets", type=int, default=4,
                        help="Max candidates to audit with --discover (default: 4)")
    parser.add_argument("-u", "--username", metavar="USER",
                        help="Owner's router username for the credentialed audit")
    parser.add_argument("-p", "--password", metavar="PASS",
                        help="Owner's router password (prompted if -u without -p; "
                             "never printed or stored)")
    parser.add_argument("--check-defaults", action="store_true",
                        help="Try the short well-known-default credential list "
                             "(slow, LAN-only, explicit opt-in)")
    parser.add_argument("--shell", choices=["telnet", "ssh", "auto"],
                        default="",
                        help="Credentialed read-only shell audit (needs -u/-p "
                             "or --check-defaults)")
    parser.add_argument("--dump-config", action="store_true",
                        help="Download config backup over the authed session "
                             "(local 0600 file)")
    parser.add_argument("--dump-mtd", nargs="?", const="all", default="",
                        metavar="all|mtdN[,mtdM]",
                        help="Low-level MTD dump over the credentialed shell "
                             "(needs --yes unless interactive)")
    parser.add_argument("--probe-udp", action="store_true",
                        help="Enable read-only SNMP/DNS UDP probes")
    parser.add_argument("--analyze-firmware", metavar="FILE",
                        help="Offline analysis of a local firmware/MTD dump "
                             "(no network use)")
    parser.add_argument("--yes", action="store_true",
                        help="Confirm --dump-mtd without prompting")

    args = parser.parse_args(argv)

    if not args.no_banner:
        print(BANNER)

    print(f"  Platform: {detect_platform()}")

    # --- v2: offline firmware analysis needs no network at all ---
    if args.analyze_firmware:
        if _fw_mod is None:
            print("[!] firmware.py not found next to bug_hunter.py.")
            return 2
        print(f"\n[*] Analyzing local firmware file: {args.analyze_firmware}")
        fw_report = _fw_mod.analyze_firmware(args.analyze_firmware,
                                             outdir=AUDIT_DIR, verbose=True)
        if fw_report.get("error"):
            print(f"[!] {fw_report['error']}")
            return 2
        print("\n" + _fw_mod.render_firmware_text(fw_report))
        print(f"\n[+] Saved: {fw_report.get('saved_txt')}")
        print(f"[+] Saved: {fw_report.get('saved_json')}")
        return 0

    # --- v2: WiFi context (which network are we auditing from?) ---
    wifi_info: Dict[str, Any] = {}
    if _discovery_mod is not None:
        try:
            wifi_info = _discovery_mod.get_wifi_info()
        except Exception:
            wifi_info = {}
    if wifi_info.get("available"):
        print(f"  WiFi SSID : {wifi_info.get('ssid', '?')} "
              f"(BSSID {wifi_info.get('bssid', '?')}, "
              f"signal {wifi_info.get('signal', '?')})")
    else:
        print("  WiFi SSID : (not on WiFi or SSID unreadable — wired LAN is fine)")

    # --- v2: credential handling (prompted, never echoed, never logged) ---
    op_user = args.username or ""
    op_pass = args.password or ""
    if op_user and not op_pass:
        try:
            op_pass = getpass.getpass(f"  Password for '{op_user}': ")
        except (EOFError, KeyboardInterrupt):
            print("\n[!] No password entered — credentialed phases skipped.")
            op_user = ""
    if op_pass and not op_user:
        print("[!] A password without --username is ignored.")
        op_pass = ""
    if op_user and op_pass:
        print(f"  Auth      : credentialed phases armed as '{op_user}' "
              f"(password hidden, LAN-only)")
    elif args.check_defaults:
        print("  Auth      : well-known-default check armed (slow, explicit)")

    # Sticker/label identity of the physical unit under audit (all optional)
    identity = build_identity(
        model=args.model, firmware=args.firmware, hardware=args.hw,
        serial=args.serial, mac=args.mac,
    )

    # Determine target(s) — single IP, gateway auto-detect, or LAN sweep.
    discovery_table: List[Dict[str, Any]] = []
    gateway_ip: Optional[str] = None
    targets: List[str] = []
    local_ip_now = get_local_ip()

    if args.target:
        targets = [args.target]
        gateway_ip = args.target
    else:
        print("\n[*] Detecting default gateway...")
        net_info = get_network_info()
        gateway_ip = net_info.get("gateway")
        if gateway_ip:
            print(f"    Gateway found: {gateway_ip}")

        if args.discover or args.auto:
            if _discovery_mod is None:
                print("    [!] discovery.py missing — cannot sweep; gateway only.")
                if not gateway_ip:
                    print("    Could not auto-detect gateway.")
                    print("    Please specify the router IP as an argument.")
                    return 1
                targets = [gateway_ip]
            else:
                cidr = args.subnet or _discovery_mod.get_interface_cidr(local_ip_now)
                print(f"    Subnet: {cidr or '(unknown — pass --subnet a.b.c.d/24)'}")
                if not cidr:
                    if not gateway_ip:
                        print("    No subnet and no gateway — specify a target IP.")
                        return 1
                    targets = [gateway_ip]
                else:
                    print("    Sweeping LAN for router candidates (TCP + ARP)...")
                    hosts = _discovery_mod.discover_lan_hosts(
                        cidr=cidr, local_ip=local_ip_now, gateway=gateway_ip,
                        verbose=args.verbose)
                    print(f"    Live hosts: {len(hosts)}")
                    discovery_table = _discovery_mod.rank_router_candidates(
                        hosts, gateway=gateway_ip, verbose=args.verbose)
                    if not discovery_table:
                        print("    No web hosts found.")
                        if not gateway_ip:
                            return 1
                        targets = [gateway_ip]
                    else:
                        print("    Candidates (best first):")
                        for entry in discovery_table[:8]:
                            print(f"      {entry['ip']:15} score={entry['router_score']}  "
                                  f"{(entry.get('title') or entry.get('server') or entry.get('oui_vendor') or 'no banner')[:52]}")
                        if args.auto and not args.discover:
                            targets = [discovery_table[0]["ip"]]
                            if gateway_ip and targets[0] != gateway_ip:
                                print(f"    Gateway web seems wrong/dead; auditing best "
                                      f"candidate {targets[0]} instead.")
                        else:
                            shortlist = [e for e in discovery_table
                                         if e.get("router_score", 0) > 0]
                            shortlist = shortlist or discovery_table[:1]
                            targets = [e["ip"] for e in
                                       shortlist[:max(1, args.max_targets)]]
                            print(f"    Auditing {len(targets)} target(s).")
        else:
            if not gateway_ip:
                print("    Could not auto-detect gateway.")
                print("    Please specify the router IP as an argument, or try --auto.")
                print("    Common IPs: 192.168.1.1, 192.168.0.1, 192.168.10.1")
                return 1
            targets = [gateway_ip]
            # v2 smooth fallback: gateway has no web at all? sweep once and
            # switch to the best candidate instead of failing the audit.
            if _discovery_mod is not None and not (
                    is_port_open(gateway_ip, 80, timeout=2)
                    or is_port_open(gateway_ip, 443, timeout=2)
                    or is_port_open(gateway_ip, 8080, timeout=2)):
                print(f"    Gateway {gateway_ip} has no web port — sweeping once "
                      f"for the real router...")
                try:
                    cidr = _discovery_mod.get_interface_cidr(local_ip_now)
                    hosts = _discovery_mod.discover_lan_hosts(
                        cidr=cidr, local_ip=local_ip_now, gateway=gateway_ip)
                    ranked = _discovery_mod.rank_router_candidates(
                        hosts, gateway=gateway_ip)
                except Exception:
                    ranked = []
                if ranked and ranked[0].get("router_score", 0) >= 4 \
                        and ranked[0]["ip"] != gateway_ip:
                    discovery_table = ranked
                    targets = [ranked[0]["ip"]]
                    print(f"    Switching to {ranked[0]['ip']} "
                          f"({(ranked[0].get('title') or ranked[0].get('server') or 'router-like')[:48]}).")
                else:
                    print("    No better candidate — auditing the gateway anyway.")

    for entry in discovery_table:
        entry["audited"] = entry["ip"] in targets

    # Audit every target (usually exactly one) and keep the worst exit code.
    worst_code = 0
    multi = len(targets) > 1
    for index, target in enumerate(targets):
        if multi:
            print("\n" + "#" * 78)
            print(f"# TARGET {index + 1}/{len(targets)}: {target}")
            print("#" * 78)
        code = _audit_single_target(
            target, args, identity, wifi_info, discovery_table,
            op_user, op_pass)
        worst_code = max(worst_code, code)

    if multi:
        print("\n" + "=" * 78)
        print(f"  MULTI-TARGET SUMMARY: {len(targets)} unit(s) audited "
              f"({', '.join(targets)})")
        print("  See the per-target reports above (and audits/ if --audit).")
        print("=" * 78)
    return worst_code


def _audit_single_target(target: str, args, identity: Dict[str, str],
                         wifi_info: Dict[str, Any],
                         discovery_table: List[Dict[str, Any]],
                         op_user: str, op_pass: str) -> int:
    """Audit one unit: scan, drift, report, save. Returns the exit code."""
    if args.audit:
        print(f"\n[*] PHYSICAL AUDIT MODE — hunting the unit at {target}")
        if identity:
            print("    Sticker identity loaded; it will be cross-checked "
                  "against the unit.")
        else:
            print("    Tip: pass --model/--firmware/--hw/--serial/--mac from "
                  "the sticker to anchor the audit to the physical unit.")

    # Run the scan against the live, physical device
    result = run_scan(
        target_host=target,
        target_port=args.port,
        probe_upnp=args.probe_upnp,
        probe_rom0=args.probe_rom0,
        quick=args.quick,
        force_vendor=args.vendor or "",
        verbose=args.verbose,
        timeout=args.timeout,
        identity=identity,
        username=op_user,
        password=op_pass,
        check_defaults=args.check_defaults,
        shell=args.shell or "",
        dump_config=args.dump_config,
        dump_mtd=args.dump_mtd or "",
        probe_udp=args.probe_udp,
        confirm=args.yes,
    )

    if result.get("error"):
        print(f"\n[!] Error: {result['error']}")
        return 2

    # In audit mode, diff against the previous hunt of this same unit FIRST so
    # the drift lands inside the report that is about to be saved.
    drift = None
    prev_audit = None
    if args.audit:
        prev_audit = load_previous_audit(target)
        if prev_audit:
            drift = diff_findings(prev_audit.get("findings", []),
                                  result["findings"])
            print(f"\n[*] Previous audit found ({prev_audit.get('timestamp', '?')}) — "
                  f"new: {len(drift['new'])}, resolved: {len(drift['resolved'])}, "
                  f"persistent: {len(drift['persistent'])}")
        else:
            print("\n[*] No previous audit for this unit — this run becomes "
                  "the baseline.")

    # v2 deep-audit artefacts ride along into both report formats.
    extra = {
        "wifi": wifi_info,
        "discovery": discovery_table,
        "auth": result.get("auth") or {},
        "shell": result.get("shell") or {},
        "dumps": result.get("dumps") or [],
    }

    # Generate and display report
    report_text = generate_text_report(
        result["network_info"],
        result["fingerprint"],
        result["open_ports"],
        result["findings"],
        result["vendor"],
        identity=identity,
        drift=drift,
        prev_audit=prev_audit,
        extra=extra,
    )
    print("\n" + report_text)

    json_report = generate_json_report(
        result["network_info"],
        result["fingerprint"],
        result["open_ports"],
        result["findings"],
        result["vendor"],
        identity=identity,
        drift=drift,
        prev_audit=prev_audit,
        extra=extra,
    )

    # Audit mode: save model-stamped artifacts under audits/
    if args.audit:
        try:
            txt_path, json_path = save_audit(result, report_text, json_report)
            print(f"\n[+] Audit text report saved: {txt_path}")
            print(f"[+] Audit JSON saved:        {json_path}")
            print(f"    (next --audit run of {target} will diff against this one)")
        except OSError as exc:
            print(f"\n[!] Could not save audit artifacts ({exc}). The report above "
                  "is still valid — use --report/--json to save a copy elsewhere.")

    # Save text report
    if args.report:
        with open(args.report, "w", encoding="utf-8") as f:
            f.write(report_text)
        print(f"\n[+] Text report saved to: {args.report}")

    # Save JSON report
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(json_report, f, indent=2, ensure_ascii=False)
        print(f"[+] JSON report saved to: {args.json}")

    # Exit code based on severity
    crit = len([f for f in result["findings"] if f["severity"] == SEV_CRITICAL])
    high = len([f for f in result["findings"] if f["severity"] == SEV_HIGH])
    if crit > 0:
        return 3  # Critical findings
    elif high > 0:
        return 2  # High findings
    elif result["findings"]:
        return 1  # Some findings
    return 0  # Clean


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user.")
        sys.exit(130)
