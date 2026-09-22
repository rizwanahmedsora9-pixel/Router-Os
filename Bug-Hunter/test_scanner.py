#!/usr/bin/env python3
"""
Quick test/demo for Bug Hunter — runs against a mock router or localhost.
This demonstrates the tool's functionality without needing a real router.
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from bug_hunter import (
    detect_platform,
    get_network_info,
    detect_vendor,
    extract_info,
    generate_text_report,
    SEV_CRITICAL, SEV_HIGH, SEV_MEDIUM
)


def test_platform_detection():
    """Test platform detection."""
    print("\n=== Test 1: Platform Detection ===")
    plat = detect_platform()
    print(f"Detected platform: {plat}")
    assert plat, "Platform detection failed"
    print("✓ Platform detection works")


def test_network_info():
    """Test network information gathering."""
    print("\n=== Test 2: Network Info Detection ===")
    info = get_network_info()
    print(f"Local IP: {info.get('local_ip', 'Not detected')}")
    print(f"Gateway: {info.get('gateway', 'Not detected')}")
    print(f"Hostname: {info.get('hostname', 'Not detected')}")
    print("✓ Network info detection works")


def test_vendor_detection():
    """Test vendor detection with sample responses."""
    print("\n=== Test 3: Vendor Detection ===")

    dlink_html = """
    <html>
    <title>D-Link DSL-2750U</title>
    <body>
    Model Name: DSL-2750U
    Firmware Version: PT_2.00
    </body>
    </html>
    """

    zte_html = """
    <html>
    <title>ZTE ZXHN H168N</title>
    <body>
    Model: ZXHN H168N
    Software Version: V2.2.0_PK1.2T5
    </body>
    </html>
    """

    tplink_html = """
    <html>
    <title>TP-Link TL-WR840N</title>
    <body>
    Model Name: TL-WR840N
    Firmware Version: 3.16.4 Build 191125
    </body>
    </html>
    """

    # Test D-Link (body + banner)
    vendor = detect_vendor(dlink_html, "micro_httpd")
    print(f"D-Link HTML → Vendor: {vendor}")
    assert vendor == "dlink", f"Expected dlink, got {vendor}"
    info = extract_info(dlink_html, vendor)
    print(f"  Model: {info.get('model')}, Firmware: {info.get('firmware')}")

    # Test ZTE
    vendor = detect_vendor(zte_html, None)
    print(f"ZTE HTML → Vendor: {vendor}")
    assert vendor == "zte", f"Expected zte, got {vendor}"
    info = extract_info(zte_html, vendor)
    print(f"  Model: {info.get('model')}, Firmware: {info.get('firmware')}")

    # Test TP-Link
    vendor = detect_vendor(tplink_html, "RomPager")
    print(f"TP-Link HTML → Vendor: {vendor}")
    assert vendor == "tplink", f"Expected tplink, got {vendor}"
    info = extract_info(tplink_html, vendor)
    print(f"  Model: {info.get('model')}, Firmware: {info.get('firmware')}")

    # --- Real-world case from a PTCL field scan (2026-09-22):
    # GET / answers a bare 401 (no vendor strings in the body), but the
    # Server banner is the ACME underscore spelling and webproc answers.
    vendor = detect_vendor("", "micro_httpd", webproc_reachable=True)
    print(f"401 root + 'micro_httpd' banner → Vendor: {vendor}")
    assert vendor == "dlink", f"Expected dlink, got {vendor}"

    vendor = detect_vendor("", "Conexant/1.0", webproc_reachable=True)
    print(f"401 root + 'Conexant/1.0' banner → Vendor: {vendor}")
    assert vendor == "dlink", f"Expected dlink, got {vendor}"

    # webproc reachable but NO corroborating banner: a router that returns
    # 401 for every unknown path must NOT be classified as D-Link.
    vendor = detect_vendor("", None, webproc_reachable=True)
    print(f"webproc reachable, no banner → Vendor: {vendor}")
    assert vendor == "generic", f"Expected generic, got {vendor}"

    # hyphenated spelling (as it appears in some writeups) still matches
    vendor = detect_vendor("", "micro-httpd")
    print(f"'micro-httpd' (hyphen) banner → Vendor: {vendor}")
    assert vendor == "dlink", f"Expected dlink, got {vendor}"

    # nothing at all
    vendor = detect_vendor("", None)
    print(f"No text, no banner → Vendor: {vendor}")
    assert vendor == "generic", f"Expected generic, got {vendor}"

    print("✓ Vendor detection works")


def test_dlink_micro_httpd_finding():
    """Test that a micro_httpd banner raises the CVE-2014-4927 finding."""
    print("\n=== Test 5: D-Link ACME banner finding (DLINK-006) ===")

    from bug_hunter import check_dlink_vulns

    class StubClient:
        """No network: every GET returns None; only the banner is set."""
        server_header = "micro_httpd"

        def get(self, path, **kwargs):
            return None

    findings = check_dlink_vulns(StubClient(), "192.168.10.1", {})
    ids = [f["id"] for f in findings]
    print(f"  findings with all-None probes + banner: {ids}")
    assert ids == ["DLINK-006"], f"Expected only DLINK-006, got {ids}"
    assert "CVE-2014-4927" in findings[0]["cve"]
    print("✓ ACME banner → CVE-2014-4927 finding works")


def test_dsl226_label_fields():
    """DSL-226 / PT_1.10_J2 / J2 sticker values must be parsed end-to-end."""
    print("\n=== Test 6: DSL-226 sticker-field extraction ===")

    from bug_hunter import extract_info, classify_firmware_build

    # The device-info page of a DSL-226 class unit
    page = """
    <html><body>
    <table>
    <tr><td>Model Name</td><td>DSL-226</td></tr>
    <tr><td>Firmware Version</td><td>PT_1.10_J2</td></tr>
    <tr><td>Hardware Version</td><td>J2</td></tr>
    <tr><td>Serial Number</td><td>UL0E156046674</td></tr>
    <tr><td>MAC Address</td><td>88:76:B9:17:34:61</td></tr>
    </table>
    </body></html>
    """

    info = extract_info(page, "dlink")
    print(f"  model={info['model']} fw={info['firmware']} hw={info['hardware_version']}")
    print(f"  serial={info['serial']} macs={info['mac_addresses']}")
    assert info["model"] == "DSL-226", f"model: {info['model']}"
    assert info["firmware"] == "PT_1.10_J2", f"firmware: {info['firmware']}"
    assert info["hardware_version"] == "J2", f"hw: {info['hardware_version']}"
    assert info["serial"] == "UL0E156046674", f"serial: {info['serial']}"
    assert "88:76:B9:17:34:61" in info["mac_addresses"], info["mac_addresses"]

    note = classify_firmware_build("PT_1.10_J2")
    assert note and "PTCL" in note, f"firmware note missing: {note}"
    assert classify_firmware_build("SEA_1.07") is None
    print(f"  PT_1.10_J2 -> {note}")
    print("✓ DSL-226 sticker extraction + PTCL build note work")


def test_dnscfg_probe():
    """dnscfg.cgi check: 200 unauth -> HIGH, login-gated -> INFO, 404 -> none."""
    print("\n=== Test 7: dnscfg.cgi exposure probe (DLINK-007, read-only) ===")

    from bug_hunter import check_dlink_vulns, HttpResponse

    def client_answering(status, body=b"", location=None):
        class StubClient:
            server_header = "micro_httpd"

            def get(self, path, **kwargs):
                if path == "/dnscfg.cgi":
                    headers = [("Location", location)] if location else []
                    return HttpResponse(status, headers, body)
                return None  # the webproc checks all miss, keeping output focused

        return StubClient()

    # exposed without auth
    findings = check_dlink_vulns(client_answering(200), "192.168.10.1", {})
    dns = [f for f in findings if f["id"] == "DLINK-007"]
    assert dns and dns[0]["severity"] == "HIGH", [f["severity"] for f in dns]
    print("  200 without auth      -> HIGH finding")

    # CGI that dies on the bare GET still executed without a session: HIGH shape
    findings = check_dlink_vulns(client_answering(500), "192.168.10.1", {})
    dns = [f for f in findings if f["id"] == "DLINK-007"]
    assert dns and dns[0]["severity"] == "HIGH"
    print("  500 on bare GET       -> HIGH finding (CGI ran unauthenticated)")

    # gated by 401
    findings = check_dlink_vulns(client_answering(401), "192.168.10.1", {})
    dns = [f for f in findings if f["id"] == "DLINK-007"]
    assert dns and dns[0]["severity"] == "INFO"
    print("  401 gated             -> INFO finding")

    # gated by a login form in the body
    login_body = b'<form><input type="password" name=":password"></form>'
    findings = check_dlink_vulns(client_answering(200, login_body), "192.168.10.1", {})
    dns = [f for f in findings if f["id"] == "DLINK-007"]
    assert dns and dns[0]["severity"] == "INFO"
    print("  200 + login form      -> INFO finding")

    # absent endpoint: no finding at all
    findings = check_dlink_vulns(client_answering(404), "192.168.10.1", {})
    assert not [f for f in findings if f["id"] == "DLINK-007"]
    print("  404 absent            -> no DLINK-007 finding")
    print("✓ dnscfg.cgi reachability-only probe works")


def test_identity_merge_and_drift():
    """Sticker merge: fills gaps, flags mismatches, verifies MAC; drift diffing."""
    print("\n=== Test 8: sticker identity merge + audit drift ===")

    from bug_hunter import build_identity, merge_identity, diff_findings

    identity = build_identity(
        model="DSL-226", firmware="PT_1.10_J2", hardware="J2",
        serial="UL0E156046674", mac="88-76-b9-17-34-61",  # hyphens/lowercase on purpose
    )
    assert identity["mac"] == "88:76:B9:17:34:61", identity["mac"]
    print(f"  normalized identity mac: {identity['mac']}")

    # Case 1: device UI silent -> label fills the gap, MAC confirmed
    fp = {"model": None, "firmware": None, "hardware_version": None,
          "serial": None, "mac_addresses": ["88:76:B9:17:34:61", "AA:BB:CC:DD:EE:FF"]}
    merge_identity(fp, identity)
    assert fp["model"] == "DSL-226" and fp["firmware"] == "PT_1.10_J2"
    assert not fp.get("label_mismatches")
    assert fp["mac_label_match"] is True
    print("  silent UI -> label fills, MAC confirmed")

    # Case 2: device disagrees with the sticker -> mismatch flagged
    fp2 = {"model": "DSL-2750U", "firmware": "PT_2.00", "hardware_version": "D1",
           "serial": "OTHER123", "mac_addresses": ["11:22:33:44:55:66"]}
    merge_identity(fp2, identity)
    fields = {m["field"] for m in fp2["label_mismatches"]}
    assert fields == {"model", "firmware", "hardware_version", "serial"}, fields
    assert fp2["mac_label_match"] is False
    print(f"  contradictory UI -> {len(fields)} mismatches flagged, MAC not found")

    # Drift
    prev = [{"id": "DLINK-006"}, {"id": "GEN-005"}, {"id": "GEN-010"}]
    now = [{"id": "DLINK-006"}, {"id": "DLINK-007"}]
    d = diff_findings(prev, now)
    assert d["new"] == ["DLINK-007"], d
    assert d["resolved"] == ["GEN-005", "GEN-010"], d
    assert d["persistent"] == ["DLINK-006"], d
    print(f"  drift new={d['new']} resolved={d['resolved']} persistent={d['persistent']}")
    print("✓ identity merge + drift diff work")


def test_boa_401_field_shape():
    """2026-09-22 field scan: Boa/0.94.13, HTTP 401, open 5555, no model.

    A 401 body that only echoes the probe URL is not D-Link evidence.
    Port 5555 with no ADB banner is not a shell. Boa 0.94.13 is named
    as CVE-2022-45956 from the banner only.
    """
    print("\n=== Test 9: Boa/401 field-scan shape ===")
    import ssl
    from bug_hunter import (
        HttpResponse, classify_http_identity, annotate_missing_model,
        check_generic_vulns, check_dlink_vulns, classify_tcp_5555,
        describe_platform, boa_version_in_cve_range, NEUTRAL_WEBPROC,
        HttpClient, router_ssl_context, extract_info,
    )

    assert describe_platform("Android", "aarch64") == "Termux/Android (aarch64)"
    assert describe_platform("Linux", "x86_64") == "Linux (x86_64)"
    assert describe_platform("Linux", "aarch64", env={"TERMUX_VERSION": "0.118"}) \
        == "Termux/Android (aarch64)"
    print("  Android platform label -> Termux/Android")

    echo = (
        "<html><title>401 Unauthorized</title><body>"
        "401 Unauthorized "
        + NEUTRAL_WEBPROC
        + "</body></html>"
    )
    # The old detector treated the echoed probe path as the CGI.
    from bug_hunter import detect_vendor
    assert detect_vendor(echo, "Boa/0.94.13") == "dlink"
    resp = HttpResponse(
        401,
        [("Server", "Boa/0.94.13"), ("WWW-Authenticate", 'Basic realm="admin"')],
        echo.encode(),
    )
    ident = classify_http_identity(resp, resp, NEUTRAL_WEBPROC, "Boa/0.94.13")
    assert ident["vendor"] == "generic", ident["vendor"]
    assert ident["webproc_evidence"] is False
    assert ident["auth_scheme"] == "Basic"
    assert ident["auth_realm"] == "admin"
    fp = {
        "server_header": "Boa/0.94.13",
        "webproc_evidence": False,
        "model": None,
    }
    annotate_missing_model(fp, ident["vendor"])
    assert fp["model"] == "unidentified Boa-fronted CPE", fp
    assert "ACME" not in fp["model_note"] or "not the Conexant/ACME" in fp["model_note"]
    assert "micro_httpd" not in fp.get("model", "")
    print("  401 echo of webproc + Boa -> generic, not inferred D-Link/ACME")

    # Realm can still name a model without inventing an ACME stack.
    realm_resp = HttpResponse(
        401,
        [("Server", "Boa/0.94.13"),
         ("WWW-Authenticate", 'Basic realm="DSL-2640B"')],
        echo.encode(),
    )
    realm_ident = classify_http_identity(
        realm_resp, realm_resp, NEUTRAL_WEBPROC, "Boa/0.94.13")
    assert realm_ident["vendor"] == "dlink", realm_ident["vendor"]
    model = extract_info(realm_ident["auth_realm"], "dlink")["model"]
    assert model and "DSL-2640B" in model, model
    fp_realm = {"server_header": "Boa/0.94.13", "model": model,
                "webproc_evidence": False}
    annotate_missing_model(fp_realm, "dlink")
    assert "model_note" not in fp_realm or "ACME httpd" not in fp_realm.get("model_note", "")
    print(f"  realm DSL-2640B -> model {model}, no ACME invention")

    assert boa_version_in_cve_range("0.94.13")
    assert boa_version_in_cve_range("0.94.14")
    assert not boa_version_in_cve_range("0.94.12")
    assert classify_tcp_5555(b"") == "unknown"
    assert classify_tcp_5555(b"CNXN") == "adb"
    assert classify_tcp_5555(b"SSH-2.0-dropbear") == "other"
    print("  5555 classifier: empty != ADB; CNXN banner == ADB")

    ports = [
        {"port": 21, "service": "FTP"},
        {"port": 22, "service": "SSH"},
        {"port": 23, "service": "Telnet"},
        {"port": 53, "service": "DNS"},
        {"port": 80, "service": "HTTP"},
        {"port": 443, "service": "HTTPS"},
        {"port": 5555, "service": "TCP 5555"},
        {"port": 7547, "service": "TR-069/CWMP"},
    ]

    class FieldClient:
        server_header = "Boa/0.94.13"
        tls = False
        www_authenticate = 'Basic realm="admin"'

        def get(self, path, **kwargs):
            if path == "/dnscfg.cgi":
                return HttpResponse(404, [], b"not found")
            return HttpResponse(401, [("Server", "Boa/0.94.13")], b"401 Unauthorized")

        def origin(self):
            return "http://192.168.10.1"

    info = {
        "server_header": "Boa/0.94.13",
        "auth_scheme": "Basic",
        "auth_realm": "admin",
        "basic_on_cleartext": True,
        "_port_banners": {5555: b""},
    }
    findings = check_generic_vulns(FieldClient(), "192.168.10.1", info, ports)
    ids = [f["id"] for f in findings]
    print(f"  generic findings: {ids}")
    assert "GEN-001" in ids and "GEN-003" in ids and "GEN-008" in ids
    assert "GEN-006" not in ids, "HTTPS is open; GEN-006 must stay absent"
    assert "GEN-009" not in ids, ids
    assert "GEN-012" in ids
    boa = next(f for f in findings if f["id"] == "GEN-011")
    assert "CVE-2022-45956" in boa["cve"]
    assert "2005" in boa["description"]
    assert "arbitrary file read" not in boa["description"].lower()
    assert boa["cve"] != "CVE-2017-9833"
    assert "HEAD" in boa["description"] and "does not send" in boa["description"]
    assert any(f["id"] == "GEN-013" for f in findings)
    telnet = next(f for f in findings if f["id"] == "GEN-001")
    assert "credentials in plaintext" in telnet["description"]
    print("  Boa banner -> GEN-011 (CVE-2022-45956), 5555 -> GEN-012 not GEN-009")

    class RejectClient:
        server_header = "Boa/0.94.13"

        def get(self, path, **kwargs):
            return HttpResponse(401, [("Server", "Boa/0.94.13")], b"401 Unauthorized")

        def origin(self):
            return "http://192.168.10.1"

    vendor_findings = check_dlink_vulns(RejectClient(), "192.168.10.1", {})
    vendor_ids = [f["id"] for f in vendor_findings]
    print(f"  forced dlink + 401 probes: {vendor_ids}")
    assert "DLINK-008" in vendor_ids
    assert "DLINK-001" not in vendor_ids
    assert "DLINK-006" not in vendor_ids
    assert any(f["id"] == "DLINK-007" and f["severity"] == "INFO" for f in vendor_findings)
    print("  401 vendor probes -> INFO inconclusive, not a silent zero")

    ctx = router_ssl_context()
    assert ctx.verify_mode == ssl.CERT_NONE
    assert ctx.check_hostname is False
    https = HttpClient("192.168.10.1", 443, tls=True)
    assert https.tls and https.origin() == "https://192.168.10.1"
    print("  HTTPS fingerprint client does not verify the CPE cert")
    print("✓ Boa/401 field-scan classification works")


def test_report_generation():
    """Test report generation."""
    print("\n=== Test 4: Report Generation ===")

    network_info = {
        "platform": "Test Platform",
        "hostname": "test-host",
        "local_ip": "192.168.1.100",
        "gateway": "192.168.1.1",
    }

    fingerprint = {
        "model": "DSL-2750U",
        "firmware": "PT_2.00",
        "hardware_version": "V1",
        "server_header": "micro-httpd",
        "http_status": 200,
    }

    open_ports = [
        {"port": 23, "service": "Telnet"},
        {"port": 80, "service": "HTTP"},
    ]

    findings = [
        {
            "id": "TEST-001",
            "title": "Test Critical Vulnerability",
            "severity": SEV_CRITICAL,
            "cve": "CVE-2025-99999",
            "cvss": "9.8",
            "description": "This is a test vulnerability for demonstration.",
            "url": "http://192.168.1.1/test",
            "impact": "This would be critical if real.",
            "fix": "1. Fix step one\n2. Fix step two",
            "urls": ["https://nvd.nist.gov/vuln/detail/CVE-2025-99999"],
        },
        {
            "id": "TEST-002",
            "title": "Test High Vulnerability",
            "severity": SEV_HIGH,
            "cve": "CVE-2025-88888",
            "description": "Another test finding.",
            "url": "http://192.168.1.1/test2",
            "impact": "High severity impact.",
            "fix": "Apply the patch.",
            "urls": [],
        },
    ]

    report = generate_text_report(network_info, fingerprint, open_ports, findings, "dlink")

    print("Report preview (first 30 lines):")
    print("\n".join(report.split("\n")[:30]))
    print("...")

    assert "BUG HUNTER" in report
    assert "TEST-001" in report
    assert "CVE-2025-99999" in report
    assert "CRITICAL" in report
    assert "192.168.1.1" in report

    print("✓ Report generation works")


def main():
    """Run all tests."""
    print("\n" + "=" * 70)
    print("  Bug Hunter — Test Suite")
    print("=" * 70)

    try:
        test_platform_detection()
        test_network_info()
        test_vendor_detection()
        test_report_generation()
        test_dlink_micro_httpd_finding()
        test_dsl226_label_fields()
        test_dnscfg_probe()
        test_identity_merge_and_drift()
        test_boa_401_field_shape()

        print("\n" + "=" * 70)
        print("  ✓ ALL TESTS PASSED")
        print("=" * 70)
        print("\nBug Hunter is ready to use!")
        print("Run: python bug_hunter.py --help")
        return 0

    except Exception as e:
        print(f"\n✗ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
