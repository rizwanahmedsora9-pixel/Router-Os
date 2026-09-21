#!/usr/bin/env python3
"""
selftest_mock.py - a local stand-in for a vulnerable PTCL D-Link webproc.

This is NOT a router and NOT an exploit. It is a tiny HTTP server that imitates the
*behaviour* the checker looks for, so ptcl_check.py can be validated end-to-end
without pointing it at real hardware:

  * GET /                      -> a login form            (correct behaviour)
  * GET /cgi-bin/webproc?...var:page=wizard
                               -> the wizard page, no auth required, and it hands
                                  out ':sessionid'       (the bug)
  * any request carrying that :sessionid
                               -> treated as logged in     (the "keeps open" bug)
  * getpage=/proc/version      -> served unauthenticated   (the traversal bug)

It binds to loopback by default and refuses to bind anywhere else unless you pass
--bind explicitly. Nothing here touches a real device.

    python3 selftest_mock.py --port 8099 &
    python3 ptcl_check.py 127.0.0.1 --port 8099
"""

from __future__ import annotations

import argparse
import http.server
import re
from urllib.parse import urlparse, parse_qs

SESSION_VALUE = "8f3a1c0d77e4"

LOGIN_PAGE = """<!DOCTYPE html>
<html><head><title>D-Link DSL Router</title></head><body>
<h1>DSL-2750U</h1>
<form method="post" action="/cgi-bin/webproc">
  <input type="text"     name=":username" value="admin">
  <input type="password" name=":password">
  <input type="submit"   name=":action"   value="Login">
</form>
<!-- Username or Password incorrect -->
</body></html>"""

WIZARD_PAGE = """<!DOCTYPE html>
<html><head><title>Setup Wizard</title></head><body>
<script>
  var wireless_name = "PTCL-Home-4F2A";
  var randomWPAKEY  = "Kx7Pm2Qw9Lt4";
  var var_language  = "en_us";
</script>
<form action="/cgi-bin/webproc" method="post">
  <select name="var:menu"><option>setup</option></select>
  Wireless Network Name <input type="text"     name="ssid"     value="PTCL-Home-4F2A">
  Pre-Shared Key        <input type="password" name="wpa_psk"  value="Kx7Pm2Qw9Lt4">
  <input type="submit" value="Next">
</form>
</body></html>"""

DASHBOARD_PAGE = """<!DOCTYPE html>
<html><head><title>Device Info</title></head><body>
<table>
  <tr><td>Model Name</td><td>DSL-2750U</td></tr>
  <tr><td>Firmware Version</td><td>PT_2.00 20161209</td></tr>
</table>
<a href="/cgi-bin/webproc?var:menu=setup&amp;var:page=wizard">Setup</a>
<a href="/cgi-bin/webproc?var:menu=advanced&amp;var:page=accessctl">Access Control</a>
</body></html>"""

VERSION_PAGE = "Linux version 2.6.30 (root@ptclbuild) (gcc 4.3.3) #1 SMP\n"


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "Conexant/1.0"

    def log_message(self, fmt, *args):  # quiet by default
        if self.server.verbose:
            super().log_message(fmt, *args)

    def _cookie_session(self) -> str | None:
        raw = self.headers.get("Cookie", "")
        m = re.search(r"(?:^|;\s*):sessionid=([^;]+)", raw)
        return m.group(1) if m else None

    def _send(self, body: str, *, session: str | None = None, status: int = 200):
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(payload)))
        if session:
            # note: illegal cookie name, exactly like the real device
            self.send_header("Set-Cookie", f":sessionid={session}; path=/")
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        path = parsed.path
        secure = self.server.secure

        if path == "/" or path in ("/index.htm", "/index.html"):
            self._send(LOGIN_PAGE)
            return

        if path != "/cgi-bin/webproc":
            self._send("<html>404</html>", status=404)
            return

        getpage = (query.get("getpage") or [""])[0]
        page = (query.get("var:page") or [""])[0]
        authed = self._cookie_session() == SESSION_VALUE

        # -- the traversal bug: getpage is served straight off the filesystem
        if getpage.startswith("/"):
            if secure:
                self._send(LOGIN_PAGE)          # patched builds refuse and re-prompt
            elif getpage == "/proc/version":
                self._send(VERSION_PAGE)
            else:
                self._send("<html>no such file</html>", status=404)
            return

        # -- the wizard bug: no auth required, and it mints a session
        if page == "wizard":
            if secure:
                self._send(LOGIN_PAGE)          # patched builds demand login first
            else:
                self._send(WIZARD_PAGE, session=SESSION_VALUE)
            return

        # -- anything else is a normal authenticated page
        if authed:
            self._send(DASHBOARD_PAGE)
        else:
            self._send(LOGIN_PAGE, status=200)


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    verbose = False
    secure = False


def main():
    ap = argparse.ArgumentParser(description="Local mock of a vulnerable PTCL D-Link webproc.")
    ap.add_argument("--port", type=int, default=8099)
    ap.add_argument("--bind", default="127.0.0.1",
                    help="loopback by default; this is a test fixture, not a service")
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--secure", action="store_true",
                    help="simulate a PATCHED unit: wizard requires auth, getpage is restricted")
    args = ap.parse_args()

    Server.verbose = args.verbose
    Server.secure = args.secure
    httpd = Server((args.bind, args.port), Handler)
    mode = "PATCHED / secure" if args.secure else "VULNERABLE"
    print(f"mock PTCL D-Link webproc on http://{args.bind}:{args.port}/  [{mode}]")
    print("  login page   : /")
    print("  bypass URL   : /cgi-bin/webproc?getpage=html/index.html&var:menu=setup&var:page=wizard")
    print("  Ctrl-C to stop")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
