#!/usr/bin/env python3
"""
Read-only LAN checker for the PTCL-associated TP-Link research branches.

It fingerprints GET /, performs a safe HEAD /rom-0 check, and optionally performs a
body-discarding GET /rom-0.  It never sends exploit payloads, configuration writes, or
credential submissions.  A /rom-0 response may contain secrets; this process does not
print, decode, save, or include that body in JSON.

Standard library only. Python 3.8+.
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

TAG_RE = re.compile(r"<[^>]*>")
MODEL_RE = re.compile(
    r"(?:model\s*(?:name)?|device\s*name)\s*[:=]?\s*"
    r"([A-Za-z][A-Za-z0-9-]{2,31})", re.I,
)
HARDWARE_RE = re.compile(
    r"(?:hardware|h\.?w\.?)\s*(?:version)?\s*[:=]?\s*"
    r"(v?\s*[0-9]+(?:\.[0-9]+)?)", re.I,
)
FIRMWARE_RE = re.compile(
    r"(?:firmware|software)\s*(?:version)?\s*[:=]?\s*"
    r"([A-Za-z0-9()._-]+(?:\s+Build\s+[A-Za-z0-9._-]+)?)", re.I,
)
ROMAGER_RE = re.compile(r"rompager", re.I)
HTML_RE = re.compile(rb"<\s*(?:html|!doctype|head|body)\b", re.I)

KNOWN_MODELS = (
    "TD-W8961ND",
    "TD-W8961N",
    "TD-W8951ND",
    "TD-W9970V3",
    "TD-W9970",
    "TL-WR840N",
)


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


def resolve_private(host: str) -> str:
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ValueError("cannot resolve %r: %s" % (host, exc)) from exc
    if not infos:
        raise ValueError("cannot resolve %r" % host)

    addresses = []
    for info in infos:
        try:
            addresses.append(ipaddress.ip_address(info[4][0].split("%", 1)[0]))
        except ValueError:
            pass
    if not addresses:
        raise ValueError("cannot resolve %r to an IP address" % host)
    if not all(any(addr in net for net in _ALLOWED_NETS) for addr in addresses):
        raise ValueError(
            "%s resolves to a public or otherwise non-LAN address; "
            "this checker only probes private/link-local targets" % host
        )
    return str(addresses[0])


class Client:
    def __init__(self, host: str, port: int, timeout: float, verbose: bool = False):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.verbose = verbose

    def request(self, method: str, path: str) -> Response:
        conn = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        headers = {
            "User-Agent": "ptcl_tplink_check/1.0 (read-only LAN audit)",
            "Accept": "text/html, application/octet-stream, */*",
            "Connection": "close",
        }
        if self.verbose:
            print("    -> %s %s:%d%s" % (method, self.host, self.port, path))
        try:
            conn.request(method, path, headers=headers)
            raw = conn.getresponse()
            body = raw.read()
            response = Response(raw.status, raw.getheaders(), body)
        finally:
            conn.close()
        if self.verbose:
            print("    <- %d (%d bytes)" % (response.status, len(response.body)))
        return response


def clean_text(text: str) -> str:
    return re.sub(r"\s+", " ", TAG_RE.sub(" ", text)).strip()


def field(regex: re.Pattern, text: str) -> Optional[str]:
    match = regex.search(clean_text(text))
    if not match:
        return None
    value = match.group(1).strip(" :\t\r\n")
    return value[:100]


def infer_model(text: str) -> Optional[str]:
    upper = clean_text(text).upper()
    for model in KNOWN_MODELS:
        if model in upper:
            return model
    match = MODEL_RE.search(upper)
    return match.group(1) if match else None


def infer_hardware(text: str) -> Optional[str]:
    # Prefer explicit hardware/version labels.  Do not treat a firmware build number
    # as hardware unless the page actually labels it as such.
    value = field(HARDWARE_RE, text)
    return value.replace(" ", "") if value else None


def normalize_model(value: Optional[str]) -> str:
    return re.sub(r"\s+", "", value or "").upper()


def normalize_hardware(value: Optional[str]) -> str:
    return re.sub(r"\s+", "", value or "").upper().replace(".", "")


def dated_build(value: str, prefix: str) -> Optional[int]:
    match = re.search(r"%s[_-]([0-9]{6})\b" % re.escape(prefix), value.upper())
    return int(match.group(1)) if match else None


def add_finding(findings: List[Dict[str, str]], identifier: str, status: str,
                evidence: str) -> None:
    findings.append({"id": identifier, "status": status, "evidence": evidence})


def assess_versions(model: Optional[str], hardware: Optional[str],
                    firmware: Optional[str]) -> List[Dict[str, str]]:
    m = normalize_model(model)
    h = normalize_hardware(hardware)
    f = (firmware or "").upper().replace(" ", "")
    findings: List[Dict[str, str]] = []

    if m == "TL-WR840N":
        if h in ("V2", "V3"):
            add_finding(
                findings, "CVE-2023-50224", "VULNERABLE",
                "TP-Link's 2026 advisory lists TL-WR840N %s as unpatched" % h,
            )
        elif h in ("V6", "V620", "V6_20"):
            build = dated_build(f, "V6")
            if build is not None and build >= 260304:
                add_finding(
                    findings, "CVE-2026-3227", "NOT VULNERABLE",
                    "firmware build is at or after TP-Link's listed V6_260304 fix",
                )
            elif build is not None:
                add_finding(
                    findings, "CVE-2026-3227", "VULNERABLE",
                    "explicit TL-WR840N v6 build is below the listed V6_260304 fix",
                )
            else:
                add_finding(
                    findings, "CVE-2026-3227", "UNASSESSED",
                    "TL-WR840N v6 identified but no comparable V6_YYMMDD build was found",
                )

    if m.startswith("TD-W8961N") and not m.startswith("TD-W8961ND"):
        if h in ("V4", "V40"):
            build = dated_build(f, "V4")
            if build is not None and build >= 250925:
                add_finding(
                    findings, "CVE-2025-15606", "NOT VULNERABLE",
                    "firmware build is at or after TP-Link's listed V4_250925 fix",
                )
            elif build is not None:
                add_finding(
                    findings, "CVE-2025-15606", "VULNERABLE",
                    "explicit TD-W8961N v4 build is below the listed V4_250925 fix",
                )
            else:
                add_finding(
                    findings, "CVE-2025-15606", "UNASSESSED",
                    "TD-W8961N v4 identified but comparable branch/build is missing",
                )

    if m == "TD-W8961ND":
        if "1.0.1" in f or "1_0_1" in f:
            add_finding(
                findings, "CVE-2018-20372", "VULNERABLE",
                "firmware string matches the public TD-W8961ND 1.0.1 XSS report",
            )
        else:
            add_finding(
                findings, "CVE-2018-20372", "UNASSESSED",
                "TD-W8961ND family is in scope, but the XSS report is firmware-specific",
            )
        add_finding(
            findings, "CVE-2014-9222 / RomPager", "UNASSESSED",
            "Misfortune Cookie and related RomPager fixes depend on exact retail/ISP build",
        )

    if m == "TD-W8951ND":
        add_finding(
            findings, "CVE-2014-9222 / RomPager", "UNASSESSED",
            "TP-Link historical firmware notes list a Misfortune Cookie fix; exact build is unknown",
        )

    if m in ("TD-W9970", "TD-W9970V3"):
        add_finding(
            findings, "CVE-2023-6437", "UNASSESSED",
            "TD-W9970 is listed in an other-ISP advisory; PTCL firmware/date is not confirmed",
        )
    return findings


def rom0_probe(client: Client, full_get: bool) -> Dict[str, object]:
    result: Dict[str, object] = {"head": {}, "get": None}
    try:
        head = client.request("HEAD", "/rom-0")
    except (OSError, http.client.HTTPException) as exc:
        result["head"] = {
            "reachable": False,
            "error": "%s: %s" % (type(exc).__name__, exc),
            "verdict": "UNASSESSED",
        }
        return result

    head_type = (head.header("Content-Type") or "").lower()
    head_length = head.header("Content-Length")
    try:
        length_value = int(head_length) if head_length else None
    except ValueError:
        length_value = None
    candidate = (
        head.status in (200, 206)
        and "html" not in head_type
        and (length_value is None or length_value >= 512)
    )
    result["head"] = {
        "reachable": True,
        "status": head.status,
        "content_type": head.header("Content-Type"),
        "content_length": length_value,
        "binary_candidate": candidate,
        "verdict": "UNASSESSED" if candidate else "NOT VULNERABLE",
    }

    if not full_get:
        return result

    try:
        response = client.request("GET", "/rom-0")
    except (OSError, http.client.HTTPException) as exc:
        result["get"] = {
            "reachable": False,
            "error": "%s: %s" % (type(exc).__name__, exc),
            "verdict": "UNASSESSED",
        }
        return result

    looks_binary = (
        response.status == 200
        and len(response.body) >= 512
        and not HTML_RE.search(response.body[:1024])
    )
    result["get"] = {
        "reachable": True,
        "status": response.status,
        "content_type": response.header("Content-Type"),
        "response_bytes": len(response.body),
        "binary_configuration_candidate": looks_binary,
        "verdict": "VULNERABLE" if looks_binary else "NOT VULNERABLE",
    }
    # response.body goes out of scope here and is deliberately absent from result.
    return result


def urls(host: str, port: int) -> None:
    print("http://%s:%d/" % (host, port))
    print("http://%s:%d/rom-0" % (host, port))
    print("Server header: RomPager/... (fingerprint only)")
    print("No network request was made.")


def collect(host: str, port: int, timeout: float, probe_rom0: bool,
            labels: Dict[str, Optional[str]], verbose: bool) -> Dict[str, object]:
    report: Dict[str, object] = {
        "target": "%s:%d" % (host, port),
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "checks": {},
        "findings": [],
    }
    client = Client(host, port, timeout, verbose)
    try:
        root = client.request("GET", "/")
    except (OSError, http.client.HTTPException) as exc:
        report["reachable"] = False
        report["error"] = "%s: %s" % (type(exc).__name__, exc)
        report["verdict"] = "UNASSESSED"
        return report

    report["reachable"] = True
    root_text = root.text
    model = labels.get("model") or infer_model(root_text)
    hardware = labels.get("hardware") or infer_hardware(root_text)
    firmware = labels.get("firmware") or field(FIRMWARE_RE, root_text)
    report["checks"]["web_root"] = {
        "status": root.status,
        "server": root.header("Server"),
        "rompager_header": bool(ROMAGER_RE.search(root.header("Server") or "")),
        "model": model,
        "hardware": hardware,
        "firmware": firmware,
        "body_bytes": len(root.body),
    }

    findings = assess_versions(model, hardware, firmware)
    report["findings"] = findings
    rom0 = rom0_probe(client, probe_rom0)
    report["checks"]["rom0"] = rom0
    get_result = rom0.get("get") or {}
    if get_result.get("verdict") == "VULNERABLE":
        add_finding(
            findings, "ROM-0 configuration disclosure", "VULNERABLE",
            "GET /rom-0 returned a binary-looking configuration backup; body was discarded",
        )
    elif rom0.get("head", {}).get("verdict") == "UNASSESSED":
        add_finding(
            findings, "ROM-0 configuration disclosure", "UNASSESSED",
            "HEAD /rom-0 looked like a possible binary backup; use --probe-rom0 to confirm",
        )

    statuses = [item.get("status") for item in findings]
    if "VULNERABLE" in statuses:
        report["verdict"] = "VULNERABLE"
    elif statuses and all(status == "NOT VULNERABLE" for status in statuses):
        report["verdict"] = "NOT VULNERABLE"
    elif not statuses and rom0.get("head", {}).get("verdict") == "NOT VULNERABLE":
        report["verdict"] = "UNASSESSED"
    else:
        report["verdict"] = "UNASSESSED"
    return report


def print_report(report: Dict[str, object]) -> None:
    print("PTCL TP-Link read-only LAN check")
    print("Target: %s" % report.get("target"))
    if not report.get("reachable", False):
        print("VERDICT: UNASSESSED (unreachable)")
        print("Error: %s" % report.get("error", "unknown error"))
        return

    web = report.get("checks", {}).get("web_root", {})
    print("Model: %s" % (web.get("model") or "(not identified)"))
    print("Hardware: %s" % (web.get("hardware") or "(not identified)"))
    print("Firmware: %s" % (web.get("firmware") or "(not identified)"))
    if web.get("rompager_header"):
        print("Server: RomPager fingerprint seen (not itself proof of a vulnerable build)")
    for finding in report.get("findings", []):
        print("%s: %s — %s" % (
            finding.get("id"), finding.get("status"), finding.get("evidence")))
    rom0 = report.get("checks", {}).get("rom0", {})
    head = rom0.get("head", {})
    print("HEAD /rom-0: %s" % head.get("verdict", "UNASSESSED"))
    get_result = rom0.get("get")
    if get_result:
        print("GET /rom-0: %s" % get_result.get("verdict", "UNASSESSED"))
        if get_result.get("binary_configuration_candidate"):
            print("  binary-looking response observed; body was discarded and is not shown.")
    else:
        print("GET /rom-0: not run (use --probe-rom0)")
    print("VERDICT: %s" % report.get("verdict", "UNASSESSED"))


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only PTCL TP-Link LAN checker")
    parser.add_argument("host")
    parser.add_argument("--port", type=int, default=80)
    parser.add_argument("--model")
    parser.add_argument("--hardware")
    parser.add_argument("--firmware")
    parser.add_argument("--probe-rom0", action="store_true",
                        help="GET /rom-0 once; response body is discarded")
    parser.add_argument("--timeout", type=float, default=6.0)
    parser.add_argument("--json", metavar="PATH", help="write a sanitized JSON report")
    parser.add_argument("--urls", action="store_true",
                        help="print endpoint references and make no network request")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    if args.urls:
        urls(args.host, args.port)
        return 0

    try:
        host = resolve_private(args.host)
    except ValueError as exc:
        print("REFUSED: %s" % exc, file=sys.stderr)
        return 2

    report = collect(
        host,
        args.port,
        args.timeout,
        args.probe_rom0,
        {"model": args.model, "hardware": args.hardware, "firmware": args.firmware},
        args.verbose,
    )
    print_report(report)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2, sort_keys=True)
            handle.write("\n")
        print("Sanitized JSON report: %s" % args.json)
    return 1 if report.get("verdict") == "VULNERABLE" else 0


if __name__ == "__main__":
    raise SystemExit(main())
