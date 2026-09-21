#!/usr/bin/env python3
"""Loopback-only TP-Link fixture for the read-only checker.

The default fixture exposes a fabricated binary-looking /rom-0 response. --secure
returns 404 for that path. The body includes a marker to verify that the checker does
not print or serialize it.
"""

from __future__ import annotations

import argparse
import http.server

ROM0_BODY = b"ROM0\x00FAKE_ROM0_SECRET_DO_NOT_PRINT\x00" + (b"x" * 2048)


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "RomPager/4.07"

    def log_message(self, fmt, *args):
        if self.server.verbose:
            super().log_message(fmt, *args)

    def root_body(self) -> bytes:
        return ("<html><body>"
                "<div>Model Name: %s</div>"
                "<div>Hardware Version: %s</div>"
                "<div>Firmware Version: %s</div>"
                "</body></html>" % (
                    self.server.model, self.server.hardware, self.server.firmware
                )).encode("utf-8")

    def send_bytes(self, status: int, body: bytes, content_type: str):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self):
        if self.path == "/":
            self.send_bytes(200, self.root_body(), "text/html")
        elif self.path == "/rom-0" and not self.server.secure:
            self.send_bytes(200, ROM0_BODY, "application/octet-stream")
        else:
            self.send_bytes(404, b"not found", "text/plain")

    def do_HEAD(self):
        self.do_GET()


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    verbose = False
    secure = False
    model = "TD-W8961ND"
    hardware = "V3"
    firmware = "1.0.1"


def main():
    parser = argparse.ArgumentParser(description="Loopback-only TP-Link test fixture")
    parser.add_argument("--port", type=int, default=8099)
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--model", default="TD-W8961ND")
    parser.add_argument("--hardware", default="V3")
    parser.add_argument("--firmware", default="1.0.1")
    parser.add_argument("--secure", action="store_true",
                        help="return 404 for /rom-0")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    Server.verbose = args.verbose
    Server.secure = args.secure
    Server.model = args.model
    Server.hardware = args.hardware
    Server.firmware = args.firmware
    httpd = Server((args.bind, args.port), Handler)
    mode = "PATCHED / no rom-0" if args.secure else "VULNERABLE / rom-0 exposed"
    print("mock TP-Link on http://%s:%d/ [%s]" % (args.bind, args.port, mode))
    print("  Ctrl-C to stop")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
