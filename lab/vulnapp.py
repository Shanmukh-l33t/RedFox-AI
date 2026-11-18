#!/usr/bin/env python3
"""RedFox lab target — intentionally vulnerable, loopback only.

Every flaw here is real in this process: the SQL string really is concatenated,
`/search` really does echo the parameter unescaped, `/.env` really is served, and
the login really does accept the documented credentials. That is what makes it a
valid validation target: findings against it are observations, not props.

It binds 127.0.0.1 unless you pass --host, and it refuses a non-loopback host
without --i-understand-this-is-exposed.

    python lab/vulnapp.py --port 8080
"""

from __future__ import annotations

import argparse
import os
import sqlite3
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

LOOPBACK = {"127.0.0.1", "::1", "localhost"}

PAGES = {
    "/files/report-q3.txt": "Quarterly report. Internal use only.\n",
    "/files/notes.txt": "TODO: remove debug endpoints before production.\n",
    "/files/backup.sql": "-- schema dump (fake)\nCREATE TABLE users(id INTEGER, name TEXT);\n",
}

GIT_CONFIG = """[core]
\trepositoryformatversion = 0
\tfilemode = true
\tbare = false
\tlogallrefupdates = true
[remote "origin"]
\turl = https://git.internal.example.com/payments/portal.git
\tfetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
\tremote = origin
\tmerge = refs/heads/main
"""

DOT_ENV = """APP_ENV=production
DB_HOST=db.internal
DB_USER=portal_app
DB_PASSWORD=lab-only-not-a-real-password
STRIPE_KEY=sk_test_lab_placeholder_value
DEBUG_UPLOADS=true
"""

INDEX = """<html><head><title>Portal</title></head><body>
<h1>Payments Portal</h1>
<ul>
<li><a href="/search?q=invoice">Search invoices</a></li>
<li><a href="/product?id=1">Product detail</a></li>
<li><a href="/files/">File browser</a></li>
<li><a href="/admin/">Admin</a></li>
<li><a href="/login">Sign in</a></li>
</ul></body></html>"""

LOGIN_FORM = """<html><head><title>Sign in</title></head><body>
<h1>Sign in</h1>
<form method="post" action="/login">
<input name="username"><input name="password" type="password">
<button>Sign in</button></form></body></html>"""

ADMIN_PANEL = """<html><head><title>Admin</title></head><body>
<h1>Admin console</h1><p>No authentication is enforced on this path.</p>
<p>Users: 4. Orders: 91. <a href="/logout">Sign out</a></p></body></html>"""

PHPINFO = """<html><head><title>phpinfo()</title></head><body>
<h1>PHP Version 7.4.3</h1>
<table><tr><td>System</td><td>Linux portal 5.4.0</td></tr>
<tr><td>Server API</td><td>Apache 2.4 Handler</td></tr></table></body></html>"""

SERVER_STATUS = """<html><head><title>Apache Status</title></head><body>
<h1>Apache Server Status for localhost</h1>
<p>Server Version: Apache/2.4.41 (Ubuntu)</p>
<p>Total accesses: 1284</p></body></html>"""


class LabHandler(BaseHTTPRequestHandler):
    server_version = "labhttp/1.0"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    # ---- helpers -----------------------------------------------------
    def _send(self, code: int, body: str, ctype: str = "text/html; charset=utf-8",
              extra: dict[str, str] | None = None) -> None:
        payload = body.encode("utf-8", "replace")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt: str, *args: object) -> None:  # quieter console
        sys.stderr.write("[lab] %s\n" % (fmt % args))

    # ---- routes ------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802
        parts = urlparse(self.path)
        path = unquote(parts.path)
        query = parse_qs(parts.query)

        if path == "/":
            return self._send(200, INDEX)
        if path == "/.git/config":
            return self._send(200, GIT_CONFIG, "text/plain")
        if path == "/.env":
            return self._send(200, DOT_ENV, "text/plain")
        if path == "/phpinfo.php":
            return self._send(200, PHPINFO)
        if path == "/server-status":
            return self._send(200, SERVER_STATUS)
        if path == "/admin/":
            return self._send(200, ADMIN_PANEL)
        if path == "/login":
            return self._send(200, LOGIN_FORM)
        if path == "/logout":
            return self._send(200, "<html><body>Signed out.</body></html>")
        if path == "/search":
            q = query.get("q", [""])[0]
            # Deliberately unescaped reflection.
            return self._send(200, f"<html><body><h1>Results for {q}</h1>"
                                   f"<p>No invoices matched {q}.</p></body></html>")
        if path == "/product":
            return self._product(query.get("id", ["1"])[0])
        if path == "/files/":
            rows = "".join(f'<li><a href="{p}">{p.split("/")[-1]}</a></li>' for p in PAGES)
            return self._send(200, f"<html><body><h1>Index of /files</h1><ul>{rows}</ul>"
                                   "</body></html>")
        if path in PAGES:
            return self._send(200, PAGES[path], "text/plain")
        if path == "/backup.zip":
            return self._send(200, "PK\x03\x04fake-archive", "application/zip")
        return self._send(404, "<html><body>Not found</body></html>")

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace")
        form = parse_qs(raw)
        if urlparse(self.path).path == "/login":
            user = form.get("username", [""])[0]
            password = form.get("password", [""])[0]
            # Deliberately weak, deliberately hardcoded.
            if user == "admin" and password == "admin":
                return self._send(
                    200,
                    "<html><body><h1>Dashboard</h1><p>Welcome, admin.</p>"
                    '<a href="/logout">Sign out</a></body></html>',
                    extra={"Set-Cookie": "session=lab-admin-token; Path=/"},
                )
            return self._send(401, "<html><body>Login failed: invalid credentials"
                                   "</body></html>")
        return self._send(404, "<html><body>Not found</body></html>")

    def _product(self, product_id: str) -> None:
        # Deliberately concatenated SQL over a real database file.
        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE TABLE products(id INTEGER, name TEXT)")
        conn.execute("INSERT INTO products VALUES(1,'Widget'),(2,'Gadget')")
        sql = f"SELECT id, name FROM products WHERE id = {product_id}"
        try:
            rows = conn.execute(sql).fetchall()
        except sqlite3.Error as exc:
            return self._send(
                500,
                f"<html><body><h1>Database error</h1><pre>{exc}</pre>"
                f"<p>Query: {sql}</p></body></html>",
            )
        finally:
            conn.close()
        body = "".join(f"<li>{r[0]}: {r[1]}</li>" for r in rows) or "<li>none</li>"
        self._send(200, f"<html><body><ul>{body}</ul></body></html>")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="RedFox deliberately vulnerable lab target")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--admin-port", type=int, default=8081,
                        help="second service so port discovery has something to find")
    parser.add_argument("--i-understand-this-is-exposed", action="store_true")
    args = parser.parse_args(argv)

    if args.host not in LOOPBACK and not args.i_understand_this_is_exposed:
        print("refusing to bind a non-loopback address without "
              "--i-understand-this-is-exposed", file=sys.stderr)
        return 2

    main_server = ThreadingHTTPServer((args.host, args.port), LabHandler)
    admin = ThreadingHTTPServer((args.host, args.admin_port), AdminOnlyHandler)
    threading.Thread(target=admin.serve_forever, daemon=True).start()
    print(f"RedFox lab target on http://{args.host}:{args.port} "
          f"(admin service on :{args.admin_port})", flush=True)
    try:
        main_server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopping", flush=True)
    finally:
        main_server.server_close()
        admin.shutdown()
    return 0


class AdminOnlyHandler(LabHandler):
    """Second port: an unauthenticated internal panel."""

    def do_GET(self) -> None:  # noqa: N802
        if urlparse(self.path).path in {"/", "/internal"}:
            return self._send(200, "<html><head><title>Internal</title></head><body>"
                                   "<h1>Internal metrics</h1><p>Requests: 91</p></body></html>")
        return super().do_GET()


if __name__ == "__main__":
    raise SystemExit(main())