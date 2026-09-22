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
