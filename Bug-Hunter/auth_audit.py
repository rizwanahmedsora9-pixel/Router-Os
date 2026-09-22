#!/usr/bin/env python3
"""
Bug Hunter v2 — authenticated HTTP audit module (zero dependencies)
==================================================================

Deep audit *with the owner's own admin credentials*. This is what turns the
tool from "document matching" into a real audit:

  * HTTP Basic / Digest / form login using credentials the operator types
    (never guessed, never brute-forced, never sent off-LAN),
  * post-login enumeration: real firmware/model/uptime/WAN/DNS/WiFi/WPS
    state read from the unit's own pages,
  * config-backup download to local disk (0600) for offline review,
  * opt-in default-credential check (--check-defaults): a short, slow,
    well-known-defaults-only list, LAN-only, explicit flag required.

NON-GOALS (deliberately absent): credential brute-forcing beyond the small
well-known-default list, session hijacking, CSRF/token theft, password
cracking of downloaded configs, or any unauthenticated privilege
escalation. Root shells are only ever opened with credentials the owner
supplied (see shell_audit.py).

LAN-only is enforced by the caller (bug_hunter.resolve_private).
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import os
import re
import stat
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple


# --------------------------------------------------------------------------- #
# Well-known defaults — tried ONLY with explicit --check-defaults, slowly.
# --------------------------------------------------------------------------- #

DEFAULT_CREDS: List[Tuple[str, str]] = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "1234"),
    ("admin", ""),
    ("root", "admin"),
    ("root", "root"),
    ("support", "support"),
    ("user", "user"),
]

SEV_CRITICAL = "CRITICAL"
SEV_HIGH = "HIGH"
SEV_MEDIUM = "MEDIUM"
SEV_LOW = "LOW"
SEV_INFO = "INFO"


# --------------------------------------------------------------------------- #
# Digest auth (RFC 2617, MD5) — implemented with hashlib, no deps.
# --------------------------------------------------------------------------- #

def parse_digest_challenge(header: str) -> Dict[str, str]:
    """Parse 'Digest realm=\"..\", nonce=\"..\", qop=\"..\"' into a dict."""
    out: Dict[str, str] = {}
    if not header:
        return out
    # Strip leading scheme name.
    body = re.sub(r"^\s*Digest\s+", "", header.strip(), flags=re.I)
    for m in re.finditer(r'(\w+)\s*=\s*(?:"([^"]*)"|([^,\s]+))', body):
        out[m.group(1).lower()] = m.group(2) if m.group(2) is not None else m.group(3)
    return out


def build_digest_header(username: str, password: str, method: str, uri: str,
                        challenge: Dict[str, str],
                        cnonce: str = "bughunter2",
                        nc: str = "00000001") -> str:
    realm = challenge.get("realm", "")
    nonce = challenge.get("nonce", "")
    qop = (challenge.get("qop") or "").split(",")[0].strip().strip('"')
    algorithm = (challenge.get("algorithm") or "MD5").strip()

    def H(s: str) -> str:
        return hashlib.md5(s.encode("utf-8")).hexdigest()

    ha1 = H(f"{username}:{realm}:{password}")
    ha2 = H(f"{method}:{uri}")
    if qop in ("auth", "auth-int"):
        resp = H(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}")
    else:
        resp = H(f"{ha1}:{nonce}:{ha2}")

    parts = [f'username="{username}"', f'realm="{realm}"', f'nonce="{nonce}"',
             f'uri="{uri}"', f'response="{resp}"']
    if algorithm.upper() != "MD5":
        parts.append(f"algorithm={algorithm}")
    if challenge.get("opaque"):
        parts.append(f'opaque="{challenge["opaque"]}"')
    if qop in ("auth", "auth-int"):
        parts.extend([f"qop={qop}", f"nc={nc}", f'cnonce="{cnonce}"'])
    return "Digest " + ", ".join(parts)


def build_basic_header(username: str, password: str) -> str:
    raw = f"{username}:{password}".encode("utf-8")
    return "Basic " + base64.b64encode(raw).decode("ascii")


# --------------------------------------------------------------------------- #
# Minimal authenticated HTTP client (Basic/Digest/form). Wraps http.client so
# this module also works standalone, without importing bug_hunter.
# --------------------------------------------------------------------------- #

class AuthHttpClient:
    def __init__(self, host: str, port: int = 80, timeout: float = 8.0,
                 verbose: bool = False, tls: bool = False):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.verbose = verbose
        self.tls = tls
        self.cookies: Dict[str, str] = {}
        self.auth_header: Optional[str] = None
        self.server_header: Optional[str] = None
        self.body_max = 128 * 1024

    def origin(self) -> str:
        scheme = "https" if self.tls else "http"
        if (self.tls and self.port == 443) or (not self.tls and self.port == 80):
            return f"{scheme}://{self.host}"
        return f"{scheme}://{self.host}:{self.port}"

    def _connect(self):
        if self.tls:
            import ssl
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            return http.client.HTTPSConnection(
                self.host, self.port, timeout=self.timeout, context=ctx)
        return http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)

    def _headers(self) -> Dict[str, str]:
        headers = {
            "User-Agent": "BugHunter/2.0 (credentialed LAN audit)",
            "Accept": "text/html,application/xhtml+xml,*/*",
            "Connection": "close",
        }
        if self.cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        if self.auth_header:
            headers["Authorization"] = self.auth_header
        return headers

    def _store(self, resp) -> None:
        for key, value in resp.getheaders():
            low = key.lower()
            if low == "server" and not self.server_header:
                self.server_header = value
            if low == "set-cookie":
                pair = value.split(";", 1)[0].strip()
                if "=" in pair:
                    name, _, val = pair.partition("=")
                    self.cookies[name.strip()] = val.strip()

    def request(self, method: str, path: str,
                body: Optional[bytes] = None,
                content_type: Optional[str] = None,
                extra: Optional[Dict[str, str]] = None):
        conn = None
        try:
            conn = self._connect()
            headers = self._headers()
            if content_type:
                headers["Content-Type"] = content_type
            if extra:
                headers.update(extra)
            if self.verbose:
                print(f"    -> {method} {self.origin()}{path}")
            conn.request(method, path, body=body, headers=headers)
            raw = conn.getresponse()
            data = raw.read(self.body_max)
            self._store(raw)
            return raw.status, raw.getheaders(), data
        except (OSError, http.client.HTTPException) as exc:
            if self.verbose:
                print(f"    !! {type(exc).__name__}: {exc}")
            return None, [], b""
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass

    def get(self, path: str):
        status, headers, body = self.request("GET", path)
        return _SimpleResp(status, headers, body)

    def post_form(self, path: str, fields: Dict[str, str]):
        encoded = urllib.parse.urlencode(fields).encode("utf-8")
        status, headers, body = self.request(
            "POST", path, body=encoded,
            content_type="application/x-www-form-urlencoded")
        return _SimpleResp(status, headers, body)


class _SimpleResp:
    def __init__(self, status, headers, body: bytes):
        self.status = status
        self.headers = headers or []
        self.body = body or b""

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")

    def header(self, name: str) -> Optional[str]:
        for key, value in self.headers:
            if key.lower() == name.lower():
                return value
        return None


LOGIN_FORM_RE = re.compile(
    r'name\s*=\s*["\']?:password|:action\s*=\s*["\']?Login|'
    r'Username\s+or\s+Password|pwdLogin|login_password|'
    r'name\s*=\s*["\']?(?:password|passwd|pwd|loginpass)["\']?',
    re.I)


def _looks_like_login(text: str) -> bool:
    return bool(LOGIN_FORM_RE.search(text or ""))


# Common form-login endpoints: (path, user_field, pass_field).
FORM_LOGINS: List[Tuple[str, str, str]] = [
    ("/login.cgi", "username", "password"),
    ("/login.cgi", "UserName", "Password"),
    ("/Login.cgi", "username", "password"),
    ("/goform/login", "username", "password"),
    ("/goform/login", "UserName", "Password"),
    ("/cgi-bin/login", "username", "password"),
    ("/cgi-bin/luci", "luci_username", "luci_password"),
    ("/login.html", "username", "password"),
    ("/index/login", "username", "password"),
    ("/", "username", "password"),
]


def _login_success(resp: _SimpleResp, had_cookies_before: int,
                   client: AuthHttpClient) -> bool:
    if resp.status in (302, 303, 307, 308):
        loc = (resp.header("Location") or "").lower()
        if "login" not in loc and "error" not in loc:
            return True
    if resp.status == 200 and not _looks_like_login(resp.text):
        # Session cookie newly set + no login form = logged in.
        if len(client.cookies) > had_cookies_before and len(resp.body) > 300:
            return True
        # Some firmwares return JSON {"success": true} / "status":"ok".
        low = resp.text.lower()
        if re.search(r'"success"\s*:\s*true|"status"\s*:\s*"?(ok|success)',
                     low):
            return True
    return False


def attempt_http_login(host: str, username: str, password: str,
                       port: int = 80, tls: bool = False,
                       timeout: float = 8.0,
                       verbose: bool = False) -> Dict[str, Any]:
    """Try owner-supplied credentials: Basic → Digest → form logins.

    Returns {ok, method, client, evidence}. Never logs the password.
    """
    result: Dict[str, Any] = {"ok": False, "method": None, "client": None,
                              "evidence": ""}
    client = AuthHttpClient(host, port, timeout=timeout, verbose=verbose, tls=tls)

    # 1. Baseline GET: what auth does the box want?
    base = client.get("/")
    if base.status is None:
        result["evidence"] = "no HTTP response"
        return result
    www_auth = base.header("WWW-Authenticate") or ""

    # 2. HTTP Basic.
    if re.match(r"\s*Basic\b", www_auth, re.I):
        client.auth_header = build_basic_header(username, password)
        probe = client.get("/")
        if probe.status == 200 and not _looks_like_login(probe.text):
            result.update(ok=True, method="http-basic", client=client,
                          evidence=f"HTTP 200 on / with Basic as '{username}'")
            return result
        if probe.status in (301, 302, 303, 307, 308):
            result.update(ok=True, method="http-basic", client=client,
                          evidence=f"HTTP {probe.status} redirect after Basic login")
            return result
        result["evidence"] = f"Basic rejected (HTTP {probe.status})"
        client.auth_header = None

    # 3. HTTP Digest.
    if re.match(r"\s*Digest\b", www_auth, re.I):
        challenge = parse_digest_challenge(www_auth)
        if challenge.get("nonce"):
            client.auth_header = build_digest_header(
                username, password, "GET", "/", challenge)
            probe = client.get("/")
            if probe.status == 200 and not _looks_like_login(probe.text):
                result.update(ok=True, method="http-digest", client=client,
                              evidence=f"HTTP 200 on / with Digest as '{username}'")
                return result
            result["evidence"] = f"Digest rejected (HTTP {probe.status})"
            client.auth_header = None

    # 4. Cookie/form logins (POST, only with owner-supplied creds).
    tried = 0
    for path, user_field, pass_field in FORM_LOGINS:
        before = len(client.cookies)
        try:
            resp = client.post_form(path, {user_field: username,
                                           pass_field: password})
        except Exception:
            continue
        tried += 1
        if resp.status is None:
            continue
        if _login_success(resp, before, client):
            result.update(ok=True, method=f"form:{path}", client=client,
                          evidence=f"form login at {path} accepted '{username}'")
            return result
        if tried >= 6:
            break  # keep the login sweep short and polite

    if not result["evidence"]:
        result["evidence"] = "no Basic/Digest challenge and no form login accepted"
    return result


def check_default_credentials(host: str, port: int = 80, tls: bool = False,
                              timeout: float = 6.0, delay: float = 1.0,
                              verbose: bool = False) -> Dict[str, Any]:
    """Try the short well-known-default list. Explicit flag only.

    Slow (delay between attempts), stops at the first success, LAN-only
    (enforced by caller). Returns {tried, success: {username, method} | None}.
    Passwords are never returned, printed, or stored.
    """
    tried = 0
    for username, password in DEFAULT_CREDS:
        tried += 1
        res = attempt_http_login(host, username, password, port=port,
                                 tls=tls, timeout=timeout, verbose=verbose)
        if res["ok"]:
            return {"tried": tried,
                    "success": {"username": username, "method": res["method"]}}
        time.sleep(delay)
    return {"tried": tried, "success": None}


# --------------------------------------------------------------------------- #
# Post-login enumeration
# --------------------------------------------------------------------------- #

AUTH_ENUM_PATHS = [
    "/", "/status", "/StatusRpm.htm", "/userRpm/StatusRpm.htm",
    "/cgi-bin/status", "/home/status", "/admin/status.asp",
    "/Status_Router.asp", "/st_poe.asp", "/DevInfo", "/deviceinfo",
    "/systemlog", "/SysLog", "/system_log", "/dhcp_clients", "/lan_clients",
    "/wlan_clients", "/wireless", "/wlan", "/wps", "/wifisettings",
    "/management", "/remote_mgmt", "/upnp", "/dns", "/ddns", "/wan",
    "/internet", "/advanced/status",
]

BACKUP_ENDPOINTS = [
    "/rom-0",
    "/backupsettings.conf",
    "/config.bin",
    "/config.dat",
    "/settings.cfg",
    "/backup.cgi",
    "/goform/backup",
    "/cgi-bin/config.bin",
    "/BackupConfig",
    "/downloadconfig",
    "/system_backup",
    "/conf.bin",
    "/router.conf",
    "/config.xml",
    "/backup/config.bin",
    "/userRpm/BackupRpm.htm",
]

_WAN_RE = re.compile(r"\bwan\s*(?:ip|address)[^0-9]{0,20}(\d+\.\d+\.\d+\.\d+)", re.I)
_UPTIME_RE = re.compile(r"up\s*time[^0-9]{0,20}([\ddayshrs, :]+)", re.I)
_DNS_RE = re.compile(r"\bdns[^0-9]{0,30}(\d+\.\d+\.\d+\.\d+)", re.I)
_FW_RES = [
    re.compile(r"(?:firmware|software)\s*(?:version)?\s*[:=]?\s*"
               r"([A-Za-z0-9()._/-]{2,80})", re.I),
]
_MODEL_RES = [
    re.compile(r"(?:model\s*(?:name)?|device\s*name|product\s*model)\s*:?\s*"
               r"([A-Za-z0-9][A-Za-z0-9\-_/\. ]{1,40})", re.I),
]


def _looks_binary(data: bytes) -> bool:
    if len(data) < 256:
        return False
    head = data[:2048]
    if b"<html" in head.lower() or b"<!doctype" in head.lower():
        return False
    nontext = sum(1 for b in head if b < 9 or (13 < b < 32 and b not in (10, 13)))
    return nontext > max(8, len(head) // 64)


def authenticated_enum(client: AuthHttpClient, host: str,
                       verbose: bool = False) -> Tuple[Dict[str, Any], List[Dict]]:
    """Fetch post-login pages and extract real device state + findings."""
    facts: Dict[str, Any] = {"pages_fetched": 0, "backup_endpoints": []}
    findings: List[Dict] = []
    blob_parts: List[str] = []

    for path in AUTH_ENUM_PATHS:
        resp = client.get(path)
        if resp.status != 200 or len(resp.body) < 200:
            continue
        facts["pages_fetched"] += 1
        text = resp.text
        blob_parts.append(text)

        if not facts.get("firmware"):
            for rx in _FW_RES:
                m = rx.search(text)
                if m and len(m.group(1)) > 2:
                    facts["firmware"] = m.group(1).strip()[:80]
                    break
        if not facts.get("model"):
            for rx in _MODEL_RES:
                m = rx.search(text)
                if m:
                    facts["model"] = re.sub(r"\s+", " ", m.group(1)).strip()[:48]
                    break
        if not facts.get("wan_ip"):
            m = _WAN_RE.search(text)
            if m:
                facts["wan_ip"] = m.group(1)
        if not facts.get("uptime"):
            m = _UPTIME_RE.search(text)
            if m:
                facts["uptime"] = m.group(1).strip()[:48]
        dns_hits = _DNS_RE.findall(text)
        if dns_hits:
            seen = facts.setdefault("dns_servers", [])
            for hit in dns_hits[:4]:
                if hit not in seen:
                    seen.append(hit)
        if facts.get("pages_fetched") >= 6 and facts.get("model") and facts.get("firmware"):
            break  # enough for identity; the rest is finding-specific
        if verbose:
            print(f"    [+] auth page {path}: {len(resp.body)} bytes")

    blob = "\n".join(blob_parts)
    low = blob.lower()

    # --- AUTH-002: config backup downloadable post-login (expected, but note it).
    for endpoint in BACKUP_ENDPOINTS:
        resp = client.get(endpoint)
        if resp.status == 200 and _looks_binary(resp.body):
            facts["backup_endpoints"].append(
                {"path": endpoint, "bytes": len(resp.body)})
            findings.append({
                "id": "AUTH-002",
                "title": f"Config backup downloadable post-login ({endpoint})",
                "severity": SEV_INFO,
                "confidence": "CONFIRMED",
                "cve": "N/A (administrative function)",
                "description": (
                    f"GET {endpoint} returned {len(resp.body)} bytes of "
                    "non-HTML content in the authenticated session. That is "
                    "the normal backup function — noted so the operator can "
                    "pull it with --dump-config for offline review. The file "
                    "itself is never printed or embedded in this report."),
                "url": f"{client.origin()}{endpoint}",
                "impact": "None by itself; the backup contains credentials — handle as secret.",
                "fix": ("Store any downloaded backup encrypted; delete it when done."),
                "urls": [],
            })
            break

    # --- AUTH-003: remote / WAN management enabled.
    if re.search(r"remote\s*(?:management|admin|access)[^<]{0,60}enabl", low):
        findings.append({
            "id": "AUTH-003",
            "title": "Remote (WAN-side) management appears ENABLED",
            "severity": SEV_HIGH,
            "confidence": "LIKELY",
            "cve": "N/A (configuration issue)",
            "description": (
                "An authenticated settings page states remote management is "
                "enabled. If true, the admin UI is reachable from the "
                "internet — every LAN finding becomes a WAN finding."),
            "url": f"{client.origin()}/",
            "impact": "Internet-exposed admin panel; automated scanners will find it.",
            "fix": ("1. Disable remote/WAN management now\n"
                    "2. Verify from outside (port scan your public IP)\n"
                    "3. Re-run this audit to confirm"),
            "urls": [],
        })

    # --- AUTH-004: WPS enabled.
    if re.search(r"\bwps[^<]{0,60}enabl", low) and "disable" not in low[max(0, low.find("wps") - 40):low.find("wps")]:
        findings.append({
            "id": "AUTH-004",
            "title": "WPS appears ENABLED",
            "severity": SEV_MEDIUM,
            "confidence": "LIKELY",
            "cve": "N/A (weak protocol)",
            "description": (
                "A settings page indicates Wi-Fi Protected Setup is enabled. "
                "WPS PIN is brute-forceable (PixieDust / online PIN attacks) "
                "on many implementations."),
            "url": f"{client.origin()}/",
            "impact": "Wi-Fi passphrase recoverable via WPS attacks.",
            "fix": "Disable WPS (both PIN and push-button) in wireless settings.",
            "urls": ["https://nvd.nist.gov/vuln/detail/CVE-2011-5053"],
        })

    # --- AUTH-005: weak WiFi encryption (WEP / WPA-TKIP only).
    if re.search(r"\bwep\b[^<]{0,40}(64|128|enabl|selected|checked)", low):
        findings.append({
            "id": "AUTH-005",
            "title": "Weak Wi-Fi encryption in use (WEP)",
            "severity": SEV_HIGH,
            "confidence": "LIKELY",
            "cve": "N/A (broken protocol)",
            "description": "A wireless page references WEP as the active mode. "
                           "WEP is broken in minutes with public tools.",
            "url": f"{client.origin()}/",
            "impact": "Wi-Fi traffic decryptable; passphrase recoverable.",
            "fix": "Switch to WPA2-PSK (AES) or WPA3; use a fresh passphrase.",
            "urls": [],
        })
    elif re.search(r"wpa[^<]{0,30}tkip", low) and "aes" not in low:
        findings.append({
            "id": "AUTH-005",
            "title": "Weak Wi-Fi encryption in use (WPA-TKIP only)",
            "severity": SEV_MEDIUM,
            "confidence": "LIKELY",
            "cve": "N/A (weak protocol)",
            "description": "Wireless mode is WPA with TKIP and no AES/CCMP in "
                           "sight. TKIP is deprecated and attackable.",
            "url": f"{client.origin()}/",
            "impact": "Reduced Wi-Fi security; downgrade-compatible attacks.",
            "fix": "Switch to WPA2-PSK (AES) or WPA3.",
            "urls": [],
        })

    return facts, findings


def download_config_backup(client: AuthHttpClient, host: str,
                           outdir: str) -> Optional[str]:
    """Download the first working backup endpoint. Returns path or None.

    The file is written with mode 0600 and its contents are never printed.
    """
    from datetime import datetime, timezone
    os.makedirs(outdir, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe_host = host.replace(":", "_")
    for endpoint in BACKUP_ENDPOINTS:
        resp = client.get(endpoint)
        if resp.status == 200 and _looks_binary(resp.body):
            name = endpoint.strip("/").replace("/", "_") or "backup"
            path = os.path.join(outdir, f"config_{safe_host}_{stamp}_{name}.bin")
            with open(path, "wb") as fh:
                fh.write(resp.body)
            try:
                os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
            except OSError:
                pass
            return path
    return None
