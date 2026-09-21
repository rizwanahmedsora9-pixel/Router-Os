#!/usr/bin/env python3
"""Local, loopback-only mock for the PTCL ZTE checker.

The vulnerable mode imitates the version and anonymous GetSecurityKeys response from
the public H168N report. The response contains a fabricated secret so tests can prove
that the checker never prints or saves it. The secure mode reports the listed fixed
version and returns a SOAP fault without a key.
"""

from __future__ import annotations

import argparse
import http.server
import threading

SOAP_KEY_RESPONSE = b'''<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>
<u:GetSecurityKeysResponse xmlns:u="urn:dslforum-org:service:WLANConfiguration:1">
<NewPreSharedKey>FAKE_MOCK_KEY_DO_NOT_PRINT</NewPreSharedKey>
<NewKeyPassphrase>FAKE_MOCK_KEY_DO_NOT_PRINT</NewKeyPassphrase>
</u:GetSecurityKeysResponse></s:Body></s:Envelope>'''
SOAP_FAULT = b'''<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>
<s:Fault><faultcode>s:Client</faultcode><faultstring>Action not authorized</faultstring></s:Fault>
</s:Body></s:Envelope>'''


class QuietHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        if getattr(self.server, "verbose", False):
            super().log_message(fmt, *args)


class WebHandler(QuietHandler):
    def do_GET(self):
        if self.path != "/":
            self.send_error(404)
            return
        firmware = "V2.2.0_PK1.2T6" if self.server.secure else "V2.2.0_PK1.2T5"
        body = ("<html><body><div>Model Name: ZXHN H168N</div>"
                "<div>Software Version: %s</div></body></html>" % firmware).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class UpnpHandler(QuietHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(length)
        action = self.headers.get("SOAPAction", "")
        if self.server.secure or "GetSecurityKeys" not in action:
            body = SOAP_FAULT
            status = 401 if self.server.secure else 405
        else:
            body = SOAP_KEY_RESPONSE
            status = 200
        self.send_response(status)
        self.send_header("Content-Type", "text/xml; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.send_error(405)


class TestServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    secure = False
    verbose = False


def main():
    parser = argparse.ArgumentParser(description="Loopback-only ZTE H168N test fixture")
    parser.add_argument("--port", type=int, default=8099)
    parser.add_argument("--upnp-port", type=int, default=8100)
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--secure", action="store_true",
                        help="report the fixed version and deny GetSecurityKeys")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    TestServer.secure = args.secure
    TestServer.verbose = args.verbose
    web = TestServer((args.bind, args.port), WebHandler)
    upnp = TestServer((args.bind, args.upnp_port), UpnpHandler)
    thread = threading.Thread(target=upnp.serve_forever, daemon=True)
    thread.start()
    mode = "PATCHED / secure" if args.secure else "VULNERABLE"
    print("mock ZTE H168N on http://%s:%d/ and port %d [%s]" %
          (args.bind, args.port, args.upnp_port, mode))
    print("  Ctrl-C to stop")
    try:
        web.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        web.shutdown()
        upnp.shutdown()
        web.server_close()
        upnp.server_close()


if __name__ == "__main__":
    main()
