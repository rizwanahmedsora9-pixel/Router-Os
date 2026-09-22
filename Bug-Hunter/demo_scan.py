#!/usr/bin/env python3
"""
Bug Hunter — Demo/Mock Scan  (PLAY MODE — not the real audit)
==============================================================

⚠  THIS IS THE PLAYGROUND, NOT THE HUNT.  Everything below happens against a
   fake router on localhost. Nothing here touches your physical device.

To audit the REAL router on your network, use bug_hunter.py instead:

    python3 bug_hunter.py                      # auto-detect your gateway
    python3 bug_hunter.py 192.168.10.1 --audit # physical audit, saved + drift
    python3 bug_hunter.py 192.168.10.1 --audit \\
        --model DSL-226 --firmware PT_1.10_J2 --hw J2 \\
        --serial <sticker> --mac <sticker>

This demo only exists for:
  - Testing the tool without a real router
  - Demonstrating the report format
  - CI/CD testing
  - Educational purposes

USAGE:
  python demo_scan.py
"""

import sys
import os
import http.server
import socketserver
import threading
import time
from datetime import datetime

# Import from the main tool
from bug_hunter import (
    run_scan,
    generate_text_report,
    BANNER,
    VERSION
)


# --------------------------------------------------------------------------- #
# Mock Router HTTP Server
# --------------------------------------------------------------------------- #

MOCK_DLINK_RESPONSE = {
    "/": """<!DOCTYPE html>
<html>
<head><title>D-Link DSL-2750U</title></head>
<body>
<form action="/login" method="post">
<input type="text" name=":action" value="Login">
<input type="password" name=":password">
</form>
</body>
</html>""",

    "/cgi-bin/webproc?getpage=html/index.html&errorpage=html/main.html&var:language=en_us&var:menu=setup&var:subpage=wizentrance&var:page=wizard": """<!DOCTYPE html>
<html>
<head><title>Setup Wizard</title></head>
<body>
<h1>Welcome to Setup Wizard</h1>
<p>Model Name: DSL-2750U</p>
<p>Firmware Version: PT_2.00 090811</p>
<p>Hardware Version: D1</p>
</body>
</html>""",

    "/cgi-bin/webproc?getpage=html/index.html&var:menu=setup&var:page=wizard": """<!DOCTYPE html>
<html>
<head><title>Setup Wizard</title></head>
<body>
<h1>Setup Wizard</h1>
<p>Model Name: DSL-2750U</p>
<p>Firmware Version: PT_2.00</p>
</body>
</html>""",

    "/cgi-bin/webproc?getpage=html/index.html&errorpage=html/index.html&var:language=en_us&var:menu=setup&var:subpage=wizwl&var:page=wizard": """<!DOCTYPE html>
<html>
<head><title>Wireless Setup</title></head>
<body>
<script>
var wireless_name = "PTCL-Broadband";
var randomWPAKEY = "secret12345";
</script>
<h1>Wireless Setup</h1>
<p>SSID: <input type="password" value="PTCL-Broadband"></p>
<p>WPA Key: <input type="password" value="secret12345"></p>
</body>
</html>""",

    "/cgi-bin/webproc?getpage=/proc/version&errorpage=html/main.html&var:language=en_us&var:menu=setup&var:page=wizard": """Linux version 2.6.30.9 (build@server) (gcc version 4.3.4) #1 Wed Aug 11 10:08:01 PDT 2009""",

    "/cgi-bin/webproc?getpage=html/index.html&errorpage=html/index.html&var:language=en_us&var:menu=status&var:page=deviceinfo": """<!DOCTYPE html>
<html>
<head><title>Device Info</title></head>
<body>
<h1>Device Information</h1>
<table>
<tr><td>Model Name</td><td>DSL-2750U</td></tr>
<tr><td>Hardware Version</td><td>D1</td></tr>
<tr><td>Firmware Version</td><td>PT_2.00 090811</td></tr>
</table>
</body>
</html>""",
}


class MockRouterHandler(http.server.BaseHTTPRequestHandler):
    """Mock HTTP handler that simulates a vulnerable D-Link router."""

    def log_message(self, format, *args):
        """Suppress default logging."""
        pass

    def do_GET(self):
        """Handle GET requests."""
        # Check if we have a mock response for this path
        response = MOCK_DLINK_RESPONSE.get(self.path)

        if response:
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.send_header("Server", "micro-httpd/1.1")
            self.end_headers()
            self.wfile.write(response.encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def do_HEAD(self):
        """Handle HEAD requests."""
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.send_header("Server", "micro-httpd/1.1")
        self.end_headers()


def start_mock_server(port=18080):
    """Start a mock router HTTP server in a background thread."""
    handler = MockRouterHandler
    httpd = socketserver.TCPServer(("127.0.0.1", port), handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd, port


# --------------------------------------------------------------------------- #
# Demo Execution
# --------------------------------------------------------------------------- #

def main():
    print(BANNER)
    print("\n" + "=" * 70)
    print("  DEMO MODE (PLAY) — Simulating a vulnerable D-Link router")
    print("=" * 70)
    print()
    print("This demo starts a mock router on localhost:18080 that simulates")
    print("a PTCL D-Link DSL-2750U with known vulnerabilities.")
    print()
    print("Nothing here touches your physical device. To hunt the real unit:")
    print("    python3 bug_hunter.py <router-ip> --audit --model <sticker> ...")
    print()

    # Start mock server
    print("[*] Starting mock router server...")
    httpd, port = start_mock_server(18080)
    print(f"    Mock server running on http://127.0.0.1:{port}")
    time.sleep(0.5)

    try:
        # Run the scan against the mock server
        print("\n[*] Running Bug Hunter scan against mock router...")
        result = run_scan(
            target_host="127.0.0.1",
            target_port=port,
            probe_upnp=False,
            probe_rom0=False,
            quick=False,
            force_vendor="dlink",
            verbose=False,
            timeout=5.0,
        )

        if result.get("error"):
            print(f"\n[!] Error: {result['error']}")
            return 1

        # Generate and display report
        report = generate_text_report(
            result["network_info"],
            result["fingerprint"],
            result["open_ports"],
            result["findings"],
            result["vendor"],
        )

        print("\n" + report)

        # Save demo report
        demo_report_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "demo_report.txt"
        )
        with open(demo_report_path, "w", encoding="utf-8") as f:
            f.write(report)

        print(f"\n[+] Demo report saved to: {demo_report_path}")

        # Summary
        print("\n" + "=" * 70)
        print("  DEMO SUMMARY")
        print("=" * 70)
        print(f"  Total findings: {len(result['findings'])}")
        crit = len([f for f in result["findings"] if f["severity"] == "CRITICAL"])
        high = len([f for f in result["findings"] if f["severity"] == "HIGH"])
        med = len([f for f in result["findings"] if f["severity"] == "MEDIUM"])
        low = len([f for f in result["findings"] if f["severity"] == "LOW"])
        info = len([f for f in result["findings"] if f["severity"] == "INFO"])
        print(f"    CRITICAL : {crit}")
        print(f"    HIGH     : {high}")
        print(f"    MEDIUM   : {med}")
        print(f"    LOW      : {low}")
        print(f"    INFO     : {info}")
        print()
        print("  The demo successfully detected:")
        print("    ✓ webproc authentication bypass")
        print("    ✓ Wi-Fi credential disclosure")
        print("    ✓ File traversal vulnerability")
        print("    ✓ Persistent session issue")
        print("    ✓ Legacy micro-httpd server")
        print()
        print("  In a real scenario, these findings would indicate that the")
        print("  router is critically vulnerable and requires immediate remediation.")
        print("=" * 70)

        return 0

    finally:
        # Stop mock server
        httpd.shutdown()
        print("\n[*] Mock server stopped.")


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\n[!] Demo interrupted.")
        sys.exit(130)
