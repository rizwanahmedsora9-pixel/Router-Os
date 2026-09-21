#!/usr/bin/env python3
"""
Read-only LAN checker for the PTCL-linked ZTE ZXHN H168N findings.

The checker deliberately does not implement the public passphrase-change request.  It
only fingerprints the web root and, when --probe-upnp is explicitly requested, sends
one documented GetSecurityKeys SOAP action.  A vulnerable response may contain a WLAN
key; the response is inspected in memory and never printed, decoded, or saved.

Standard library only.  Python 3.8+.
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
from typing import Dict, List, Optional, Tuple


_ALLOWED_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
]

SOAP_PATH = "/control/igd/wlanc_1_1"
SOAP_ACTION = '"urn:dslforum-org:service:WLANConfiguration:1#GetSecurityKeys"'
SOAP_BODY = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
    's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
    '<s:Body><u:GetSecurityKeys '
    'xmlns:u="urn:dslforum-org:service:WLANConfiguration:1">'
    '</u:GetSecurityKeys></s:Body></s:Envelope>'
).encode("utf-8")

MODEL_RE = re.compile(
    r"(?:model\s*(?:name)?|device\s*name)\s*[:=]?\s*"
    r"((?:ZXHN\s+[A-Za-z0-9][A-Za-z0-9._/-]*|[A-Za-z0-9][A-Za-z0-9._/-]*))",
    re.I,
)
FW_RE = re.compile(
    r"(?:software|firmware)\s*version\s*[:=]?\s*"
    r"([A-Za-z0-9][A-Za-z0-9._/-]{1,79})",
    re.I,
)
TAG_RE = re.compile(r"<[^>]*>")
KEY_TAG_RE = re.compile(
    rb"<(?:NewPreSharedKey|NewKeyPassphrase|NewWEPKey[0-3])\b[^>]*>\s*[^<\s]",
    re.I,
)


def resolve_private(host: str) -> str:
    """Resolve host and return one LAN-local address; reject public targets."""
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ValueError("cannot resolve %r: %s" % (host, exc)) from exc
    if not infos:
        raise ValueError("cannot resolve %r" % host)

    addresses = []
    for info in infos:
        raw = info[4][0]
        try:
            addr = ipaddress.ip_address(raw.split("%", 1)[0])
        except ValueError:
            continue
        addresses.append(addr)
    if not addresses:
        raise ValueError("cannot resolve %r to an IP address" % host)

    # Do not choose a private address from a mixed public/private answer.  The
    # hostname must be unambiguously local before the tool opens a socket.
    if not all(any(addr in net for net in _ALLOWED_NETS) for addr in addresses):
        raise ValueError(
            "%s resolves to a public or otherwise non-LAN address; "
            "this checker only probes private/link-local targets" % host
        )
    return str(addresses[0])


class Response:
    def __init__(self, status: int, headers: List[Tuple[str, str]], body: bytes):
        self.status = status
        self.headers = headers
        self.body = body

    def header(self, name: str) -> Optional[str]:
        for key, value in self.headers:
            if key.lower() == name.lower():
                return value
        return None

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")


class Client:
    def __init__(self, host: str, port: int, timeout: float, verbose: bool = False):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.verbose = verbose

    def request(self, method: str, path: str, body: Optional[bytes] = None,
                headers: Optional[Dict[str, str]] = None) -> Response:
        conn = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        request_headers = {
            "User-Agent": "ptcl_zte_check/1.0 (read-only LAN audit)",
            "Accept": "text/html, text/xml, */*",
            "Connection": "close",
        }
        if headers:
            request_headers.update(headers)
        if self.verbose:
            print("    -> %s %s:%d%s" % (method, self.host, self.port, path))
        try:
            conn.request(method, path, body=body, headers=request_headers)
            raw = conn.getresponse()
            response = Response(raw.status, raw.getheaders(), raw.read())
        finally:
            conn.close()
        if self.verbose:
            print("    <- %d (%d bytes)" % (response.status, len(response.body)))
        return response


def strip_tags(text: str) -> str:
    return re.sub(r"\s+", " ", TAG_RE.sub(" ", text)).strip()


def extract_first(regex: re.Pattern, text: str) -> Optional[str]:
    match = regex.search(strip_tags(text))
    return match.group(1).strip() if match else None


def version_findings(firmware: Optional[str]) -> List[Dict[str, str]]:
    if not firmware:
        return []
    value = firmware.lower().replace(" ", "")
    findings: List[Dict[str, str]] = []

    affected_2018 = (
        "v2.2.0_pk1.2t5",
        "v2.2.0_pk1.2t2",
        "v2.2.0_pk11t7",
        # ZTE's affected-version table renders this as PK11T4; the NVD/CVE
        # description normalizes the same branch as PK11T. Match both forms by
        # using the shared PK11T prefix.
        "v2.2.0_pk11t",
    )
    if any(item in value for item in affected_2018):
        findings.extend([
            {
                "id": "CVE-2018-7357",
                "status": "VULNERABLE",
                "evidence": "firmware matches ZTE's affected H168N PK version list",
            },
            {
                "id": "CVE-2018-7358",
                "status": "VULNERABLE",
                "evidence": "firmware matches ZTE's affected H168N PK version list",
            },
        ])
    elif "v2.2.0_pk1.2t6" in value:
        findings.extend([
            {
                "id": "CVE-2018-7357/7358",
                "status": "NOT VULNERABLE",
                "evidence": "firmware matches ZTE's listed fixed target V2.2.0_PK1.2T6",
            },
        ])

    if "v3.5.0_eg1t4_te" in value:
        findings.append({
            "id": "CVE-2021-21735",
            "status": "VULNERABLE",
            "evidence": "exact firmware is at or below the ZTE EG1T4_TE affected boundary",
        })
    if "v3.5.0_eg1t5_te" in value:
        findings.append({
            "id": "CVE-2021-21729",
            "status": "VULNERABLE",
            "evidence": "exact firmware is the ZTE-listed affected EG1T5_TE build",
        })
    if "v3.5.0_ty.t6" in value or "v3.5.0_ty_t6" in value:
        findings.append({
            "id": "CVE-2021-21730",
            "status": "VULNERABLE",
            "evidence": "exact firmware is the ZTE-listed affected TY.T6 build",
        })
    return findings


def upnp_probe(host: str, port: int, timeout: float, verbose: bool) -> Dict[str, object]:
    client = Client(host, port, timeout, verbose)
    try:
        response = client.request(
            "POST",
            SOAP_PATH,
            body=SOAP_BODY,
            headers={
                "Content-Type": "text/xml; charset=utf-8",
                "SOAPAction": SOAP_ACTION,
                "Content-Length": str(len(SOAP_BODY)),
            },
        )
    except (OSError, http.client.HTTPException) as exc:
        return {
            "ran": True,
            "reachable": False,
            "status": None,
            "error": "%s: %s" % (type(exc).__name__, exc),
            "key_fields_present": False,
            "verdict": "UNASSESSED",
        }

    key_fields = bool(KEY_TAG_RE.search(response.body))
    if key_fields and response.status == 200:
        verdict = "VULNERABLE"
    elif response.status in (401, 403, 404, 405) or not key_fields:
        verdict = "NOT VULNERABLE" if response.status < 500 else "UNASSESSED"
    else:
        verdict = "UNASSESSED"

    # Deliberately omit response.body.  It may contain the real WLAN secret.
    return {
        "ran": True,
        "reachable": True,
        "status": response.status,
        "response_bytes": len(response.body),
        "content_type": response.header("Content-Type"),
        "key_fields_present": key_fields,
        "verdict": verdict,
    }


def urls(host: str, web_port: int, upnp_port: int) -> None:
    web = "http://%s:%d/" % (host, web_port)
    upnp = "http://%s:%d%s" % (host, upnp_port, SOAP_PATH)
    print(web)
    print(upnp)
    print("SOAP action: dslforum-org:service:WLANConfiguration:1#GetSecurityKeys")
    print("No network request was made.")


def collect(host: str, web_port: int, upnp_port: int, timeout: float,
            probe: bool, verbose: bool) -> Dict[str, object]:
    report: Dict[str, object] = {
        "target": "%s:%d" % (host, web_port),
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "checks": {},
        "findings": [],
    }
    web = Client(host, web_port, timeout, verbose)
    try:
        root = web.request("GET", "/")
    except (OSError, http.client.HTTPException) as exc:
        report["reachable"] = False
        report["error"] = "%s: %s" % (type(exc).__name__, exc)
        report["verdict"] = "UNASSESSED"
        return report

    report["reachable"] = True
    model = extract_first(MODEL_RE, root.text)
    firmware = extract_first(FW_RE, root.text)
    report["checks"]["web_root"] = {
        "status": root.status,
        "server": root.header("Server"),
        "model": model,
        "firmware": firmware,
        "body_bytes": len(root.body),
    }

    findings = version_findings(firmware)
    report["findings"] = findings
    if probe:
        upnp = upnp_probe(host, upnp_port, timeout, verbose)
    else:
        upnp = {
            "ran": False,
            "verdict": "UNASSESSED",
            "note": "pass --probe-upnp to make the documented read-only SOAP request",
        }
    report["checks"]["upnp_get_security_keys"] = upnp

    if upnp.get("verdict") == "VULNERABLE":
        findings.extend([
            {
                "id": "CVE-2018-7357/7358",
                "status": "VULNERABLE",
                "evidence": "anonymous GetSecurityKeys response contained WLAN-key fields",
            },
        ])

    statuses = [item.get("status") for item in findings]
    if "VULNERABLE" in statuses:
        report["verdict"] = "VULNERABLE"
    elif statuses and all(status == "NOT VULNERABLE" for status in statuses):
        report["verdict"] = "NOT VULNERABLE"
    elif upnp.get("verdict") == "NOT VULNERABLE" and not findings:
        report["verdict"] = "NOT VULNERABLE"
    else:
        report["verdict"] = "UNASSESSED"
    return report


def print_report(report: Dict[str, object]) -> None:
    print("PTCL ZTE read-only LAN check")
    print("Target: %s" % report.get("target"))
    if not report.get("reachable", False):
        print("VERDICT: UNASSESSED (unreachable)")
        print("Error: %s" % report.get("error", "unknown error"))
        return

    web = report.get("checks", {}).get("web_root", {})
    print("Model: %s" % (web.get("model") or "(not identified)"))
    print("Firmware: %s" % (web.get("firmware") or "(not identified)"))
    for finding in report.get("findings", []):
        print("%s: %s — %s" % (
            finding.get("id"), finding.get("status"), finding.get("evidence")))
    upnp = report.get("checks", {}).get("upnp_get_security_keys", {})
    if not upnp.get("ran"):
        print("UPnP read probe: not run (use --probe-upnp)")
    else:
        print("UPnP read probe: %s" % upnp.get("verdict"))
        if upnp.get("key_fields_present"):
            print("  WLAN-key fields were present; the key itself was discarded and is not shown.")
    print("VERDICT: %s" % report.get("verdict", "UNASSESSED"))


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only PTCL ZTE H168N LAN checker")
    parser.add_argument("host")
    parser.add_argument("--port", type=int, default=80)
    parser.add_argument("--upnp-port", type=int, default=52869)
    parser.add_argument("--timeout", type=float, default=6.0)
    parser.add_argument("--probe-upnp", action="store_true",
                        help="send one read-only GetSecurityKeys SOAP request")
    parser.add_argument("--json", metavar="PATH", help="write a sanitized JSON report")
    parser.add_argument("--urls", action="store_true",
                        help="print endpoints and make no network request")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    if args.urls:
        urls(args.host, args.port, args.upnp_port)
        return 0

    try:
        host = resolve_private(args.host)
    except ValueError as exc:
        print("REFUSED: %s" % exc, file=sys.stderr)
        return 2

    report = collect(
        host, args.port, args.upnp_port, args.timeout, args.probe_upnp, args.verbose)
    print_report(report)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2, sort_keys=True)
            handle.write("\n")
        print("Sanitized JSON report: %s" % args.json)
    return 1 if report.get("verdict") == "VULNERABLE" else 0


if __name__ == "__main__":
    raise SystemExit(main())
