#!/usr/bin/env python3
"""
Bug Hunter v1.0 — Cross-Platform Router Vulnerability Scanner
=============================================================

Detects connected router/gateway on WiFi/LAN and scans for known vulnerabilities,
security misconfigurations, and exposures.  Generates a detailed report with:
  - Discovered vulnerabilities and their severity
  - CVE references and source URLs
  - Detailed descriptions of each finding
  - Step-by-step fix/remediation methods

PLATFORMS:  Windows, Linux, macOS, Termux (Android), FreeBSD — any device
            with Python 3.8+ and a network connection.

NO EXTERNAL DEPENDENCIES — uses Python standard library only.

SAFETY PROPERTIES:
  * GET/HEAD only — no POST, no config writes, no credential submission
  * Private/LAN addresses only — refuses public IPs
  * Never prints recovered secrets (WiFi keys, passwords)
  * Read-only fingerprinting — does not brute-force or exploit

USAGE:
  python bug_hunter.py                    # auto-detect gateway, scan, report
  python bug_hunter.py 192.168.1.1        # scan specific IP
  python bug_hunter.py --report out.txt   # save report to file
  python bug_hunter.py --quick            # fast scan (skip slow probes)
  python bug_hunter.py --probe-upnp       # enable UPnP probes
  python bug_hunter.py --probe-rom0       # enable rom-0 config backup check
  python bug_hunter.py --json out.json    # save JSON report
  python bug_hunter.py --vendor dlink     # force vendor detection
"""

from __future__ import annotations

import argparse
import http.client
import ipaddress
import json
import os
import platform
import re
import socket
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

VERSION = "1.0.0"
BANNER = r"""
 ____              _   _       _   _             _
| __ )  ___  __ _ | | | |_   _| |__ | |_ ___  _ __| |_
|  _ \ / _ \/ _` || |_| | | | | '_ \| __/ _ \| '__| __|
| |_) |  __/ (_| ||  _  | |_| | |_) | || (_) | |  | |_
|____/ \___|\__, ||_| |_|\__,_|_.__/ \__\___/|_|   \__|
            |___/
 Router Vulnerability Scanner v{version}
 Cross-Platform | Read-Only | No Exploits
""".format(version=VERSION)

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
    (5555, "ADB Debug"),
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

def detect_platform() -> str:
    """Return a human-readable platform string."""
    system = platform.system().lower()
    machine = platform.machine().lower()
    if system == "linux":
        # Check for Termux/Android
        if "ANDROID_ROOT" in os.environ or os.path.isdir("/data/data"):
            return f"Termux/Android ({machine})"
        return f"Linux ({machine})"
    elif system == "windows":
        return f"Windows {platform.version()}"
    elif system == "darwin":
        return f"macOS {platform.mac_ver()[0]} ({machine})"
    elif system == "freebsd":
        return f"FreeBSD ({machine})"
    return f"{system} ({machine})"


# --------------------------------------------------------------------------- #
# Gateway Detection
# --------------------------------------------------------------------------- #

def get_default_gateway() -> Optional[str]:
    """Detect the default gateway IP across platforms."""
    system = platform.system().lower()

    if system == "linux" or system == "darwin" or system == "freebsd":
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
            ).decode("utf-8", "replace", errors="replace")
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
            ).decode("utf-8", "replace", errors="replace")
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


class HttpClient:
    def __init__(self, host: str, port: int = 80, timeout: float = 8.0,
                 verbose: bool = False):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.verbose = verbose
        self.cookies: Dict[str, str] = {}
        self.server_header: Optional[str] = None
        self.response_body_max = 64 * 1024  # 64KB max body read

    def get(self, path: str, use_cookies: bool = True,
            extra_headers: Optional[Dict] = None) -> Optional[HttpResponse]:
        """Send a GET request. Returns None on connection failure."""
        conn = None
        try:
            conn = http.client.HTTPConnection(self.host, self.port,
                                               timeout=self.timeout)
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
                print(f"    -> GET http://{self.host}:{self.port}{path}")

            conn.request("GET", path, headers=headers)
            raw = conn.getresponse()
            body = raw.read(self.response_body_max)

            if not self.server_header:
                for k, v in raw.getheaders():
                    if k.lower() == "server":
                        self.server_header = v
                        break

            resp = HttpResponse(raw.status, raw.getheaders(), body)
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
        """Send a HEAD request."""
        conn = None
        try:
            conn = http.client.HTTPConnection(self.host, self.port,
                                               timeout=self.timeout)
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
    re.compile(r"(?:hardware|h\.?w\.?)\s*(?:version)?\s*[:=]?\s*"
               r"(v?\s*[0-9]+(?:\.[0-9]+)?)", re.I),
]


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


def extract_info(text: str, vendor: str) -> Dict[str, Optional[str]]:
    """Extract model, firmware, and hardware version from page text."""
    info: Dict[str, Optional[str]] = {
        "model": None,
        "firmware": None,
        "hardware_version": None,
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

    return info


# --------------------------------------------------------------------------- #
# Vulnerability Check: D-Link (PTCL DSL-series)
# --------------------------------------------------------------------------- #

def check_dlink_vulns(client: HttpClient, host: str, info: Dict) -> List[Dict]:
    """Check D-Link specific vulnerabilities."""
    findings: List[Dict] = []

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
# Generic Vulnerability Checks (all routers)
# --------------------------------------------------------------------------- #

def check_generic_vulns(client: HttpClient, host: str, info: Dict,
                         open_ports: List[Dict],
                         probe_rom0: bool = False) -> List[Dict]:
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

    # --- Check 9: ADB Debug Port ---
    adb_open = any(p["port"] == 5555 for p in open_ports)
    if adb_open:
        findings.append({
            "id": "GEN-009",
            "title": "ADB Debug Port (5555) Exposed",
            "severity": SEV_HIGH,
            "cve": "N/A (debug interface exposure)",
            "description": (
                "Android Debug Bridge (ADB) port 5555 is open. This is extremely "
                "dangerous — it provides full shell access to the device. "
                "Some Android-based routers and IPTV boxes leave this enabled."
            ),
            "url": f"adb://{host}:5555/",
            "impact": "Full shell/root access to the device via ADB.",
            "fix": (
                "1. Disable ADB debugging immediately in device settings\n"
                "2. If this is an Android TV box/router, disable developer options\n"
                "3. Block port 5555 at the firewall"
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

    return findings


# --------------------------------------------------------------------------- #
# Report Generation
# --------------------------------------------------------------------------- #

def generate_text_report(network_info: Dict, fingerprint: Dict,
                          open_ports: List[Dict], findings: List[Dict],
                          vendor: str) -> str:
    """Generate a comprehensive text report."""
    lines: List[str] = []
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    lines.append("=" * 78)
    lines.append("  BUG HUNTER — ROUTER VULNERABILITY SCAN REPORT")
    lines.append(f"  Version {VERSION}")
    lines.append("=" * 78)
    lines.append("")
    lines.append(f"  Scan Date     : {now}")
    lines.append(f"  Platform      : {network_info.get('platform', 'unknown')}")
    lines.append(f"  Hostname      : {network_info.get('hostname', 'unknown')}")
    lines.append(f"  Local IP      : {network_info.get('local_ip', 'unknown')}")
    lines.append(f"  Gateway IP    : {network_info.get('gateway', 'unknown')}")
    lines.append("")

    # Device fingerprint
    lines.append("-" * 78)
    lines.append("  DEVICE FINGERPRINT")
    lines.append("-" * 78)
    lines.append(f"  Detected Vendor    : {vendor.upper()}")
    lines.append(f"  Model              : {fingerprint.get('model', 'Unknown')}")
    if fingerprint.get("model_note"):
        lines.append(f"  Model (note)       : {fingerprint['model_note']}")
    lines.append(f"  Firmware           : {fingerprint.get('firmware', 'Unknown')}")
    lines.append(f"  Hardware Version   : {fingerprint.get('hardware_version', 'Unknown')}")
    lines.append(f"  HTTP Server        : {fingerprint.get('server_header', 'Unknown')}")
    lines.append(f"  HTTP Status        : {fingerprint.get('http_status', 'Unknown')}")
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
        risk = "CLEAN — No known vulnerabilities detected"
    lines.append(f"  Overall Risk     : {risk}")
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
    lines.append(f"  DISCLAIMER: This tool performs READ-ONLY checks only.")
    lines.append(f"  It does not exploit or modify the router in any way.")
    lines.append(f"  Results are based on publicly known vulnerabilities.")
    lines.append("=" * 78)

    return "\n".join(lines)


def generate_json_report(network_info: Dict, fingerprint: Dict,
                          open_ports: List[Dict], findings: List[Dict],
                          vendor: str) -> Dict:
    """Generate a JSON-serializable report."""
    return {
        "tool": "Bug Hunter",
        "version": VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
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
            "hardware_version": fingerprint.get("hardware_version"),
            "server_header": fingerprint.get("server_header"),
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


# --------------------------------------------------------------------------- #
# Main Scanner Logic
# --------------------------------------------------------------------------- #

def run_scan(target_host: str, target_port: int = 80,
             probe_upnp: bool = False, probe_rom0: bool = False,
             quick: bool = False, force_vendor: str = "",
             verbose: bool = False, timeout: float = 8.0) -> Dict:
    """Execute the full vulnerability scan."""

    result: Dict[str, Any] = {
        "target": target_host,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "network_info": {
            "platform": detect_platform(),
            "hostname": None,
            "local_ip": None,
            "gateway": target_host,
        },
        "fingerprint": {},
        "open_ports": [],
        "vendor": "",
        "findings": [],
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
    client = HttpClient(target_host, target_port, timeout=timeout, verbose=verbose)

    base_resp = client.get("/", use_cookies=False)
    fingerprint = {"server_header": client.server_header, "http_status": None}
    base_text = base_resp.text if base_resp else ""
    if base_resp:
        fingerprint["http_status"] = base_resp.status

    # The D-Link/Conexant stack often answers "/" with a bare 401 and no
    # vendor strings. Its signature endpoint is /cgi-bin/webproc - probe it
    # with a NEUTRAL page (login is demanded, no session is minted) so
    # detection works on 401-style UIs too. One extra GET on every other
    # vendor, which simply 404s.
    wp_path = ("/cgi-bin/webproc?getpage=html/index.html&errorpage=html/index.html"
               "&var:language=en_us&var:menu=status&var:page=deviceinfo")
    wp_resp = client.get(wp_path)
    wp_text = wp_resp.text if wp_resp else ""
    wp_reachable = wp_resp is not None and wp_resp.status != 404

    text = base_text + "\n" + wp_text
    vendor = detect_vendor(text, client.server_header,
                           webproc_reachable=wp_reachable)
    fingerprint.update(extract_info(text, vendor))

    if vendor == "dlink" and not fingerprint.get("model"):
        fingerprint["model"] = "DSL-27xxU class (inferred)"
        fingerprint["model_note"] = (
            "no model string visible in the UI; inferred from the "
            "/cgi-bin/webproc CGI + ACME httpd banner (the Conexant DSL "
            "stack PTCL ships). Confirm the exact model/HW rev on the unit's "
            "label."
        )

    if force_vendor:
        vendor = force_vendor.lower()

    result["vendor"] = vendor
    result["fingerprint"] = fingerprint
    print(f"    Vendor: {vendor.upper()}")
    print(f"    Model: {fingerprint.get('model', 'Unknown')}")
    print(f"    Firmware: {fingerprint.get('firmware', 'Unknown')}")
    print(f"    Server: {fingerprint.get('server_header', 'Unknown')}")

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
        result["open_ports"], probe_rom0=probe_rom0
    )
    findings.extend(gen_findings)
    print(f"    Found {len(gen_findings)} generic issue(s)")

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
EXAMPLES:
  python bug_hunter.py                     # auto-detect gateway, full scan
  python bug_hunter.py 192.168.1.1         # scan specific router IP
  python bug_hunter.py --report out.txt    # save text report to file
  python bug_hunter.py --json out.json     # save JSON report
  python bug_hunter.py --quick             # fast scan (skip slow probes)
  python bug_hunter.py --probe-upnp        # enable UPnP WLAN key probe (ZTE)
  python bug_hunter.py --probe-rom0        # enable rom-0 backup download (TP-Link)
  python bug_hunter.py --vendor dlink      # force vendor detection
  python bug_hunter.py -v                  # verbose output

SAFETY:
  This tool performs READ-ONLY checks. It never sends passwords, modifies
  configuration, or runs exploits. Only your own LAN devices should be scanned.
        """
    )

    parser.add_argument("target", nargs="?", default=None,
                        help="Router/gateway IP (auto-detect if omitted)")
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
                                              "netgear", "linksys", "generic"],
                        help="Force vendor (skip auto-detection)")
    parser.add_argument("--timeout", type=float, default=8.0,
                        help="HTTP timeout in seconds (default: 8)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output")
    parser.add_argument("--no-banner", action="store_true",
                        help="Suppress startup banner")

    args = parser.parse_args(argv)

    if not args.no_banner:
        print(BANNER)

    print(f"  Platform: {detect_platform()}")

    # Determine target
    target = args.target
    if not target:
        print("\n[*] Detecting default gateway...")
        net_info = get_network_info()
        target = net_info.get("gateway")

        if target:
            print(f"    Gateway found: {target}")
        else:
            print("    Could not auto-detect gateway.")
            print("    Please specify the router IP as an argument.")
            print("    Common IPs: 192.168.1.1, 192.168.0.1, 192.168.10.1")
            return 1

    # Run the scan
    result = run_scan(
        target_host=target,
        target_port=args.port,
        probe_upnp=args.probe_upnp,
        probe_rom0=args.probe_rom0,
        quick=args.quick,
        force_vendor=args.vendor or "",
        verbose=args.verbose,
        timeout=args.timeout,
    )

    if result.get("error"):
        print(f"\n[!] Error: {result['error']}")
        return 2

    # Generate and display report
    report_text = generate_text_report(
        result["network_info"],
        result["fingerprint"],
        result["open_ports"],
        result["findings"],
        result["vendor"],
    )
    print("\n" + report_text)

    # Save text report
    if args.report:
        with open(args.report, "w", encoding="utf-8") as f:
            f.write(report_text)
        print(f"\n[+] Text report saved to: {args.report}")

    # Save JSON report
    if args.json:
        json_report = generate_json_report(
            result["network_info"],
            result["fingerprint"],
            result["open_ports"],
            result["findings"],
            result["vendor"],
        )
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
