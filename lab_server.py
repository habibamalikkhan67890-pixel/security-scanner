"""lab_server.py - local practice target (SIRF testing ke liye).

Yeh chhota web server jaan boojh kar MISCONFIGURED hai (missing headers, insecure cookie, fake .env, directory
listing...). Isme koi asli vulnerability, asli secret ya exploit nahi hai - saara content nakli/static hai.
Sirf 127.0.0.1 par bind hota hai. Scanner ko is par chalane ke liye .env mein ALLOW_LAB_TARGETS=true chahiye.

Profiles:
  vulnerable (default) : kai misconfigurations
  hardened             : wahi site, security headers/cookie flags/CSRF token ke saath (compare feature ke liye)

Run:  python lab_server.py --profile vulnerable --port 5001
"""
import argparse
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

VULNERABLE_HOME = b"""<!doctype html>
<html><head><title>Lab Shop (deliberately misconfigured)</title>
<meta name="generator" content="FakeCMS 2.4.1">
<script src="https://cdn.example.invalid/lib.js"></script></head>
<body><h1>Lab Shop</h1>
<p>Practice target for the Security Scanner. All content is fake.</p>
<form action="/login" method="get">
  <input type="text" name="user"><input type="password" name="pass"><button>Login</button>
</form>
<form action="/subscribe" method="post"><input type="email" name="email"><button>Subscribe</button></form>
</body></html>"""

HARDENED_HOME = b"""<!doctype html>
<html><head><title>Lab Shop (hardened profile)</title></head>
<body><h1>Lab Shop</h1>
<p>Practice target for the Security Scanner. All content is fake.</p>
<form action="/login" method="post">
  <input type="hidden" name="csrf_token" value="lab-token">
  <input type="text" name="user"><input type="password" name="pass"><button>Login</button>
</form>
</body></html>"""

LISTING = (b"<html><head><title>Index of /uploads/</title></head><body><h1>Index of /uploads/</h1>"
           b"<a href=\"../\">Parent Directory</a><ul><li>photo1.jpg</li></ul></body></html>")


class LabHandler(BaseHTTPRequestHandler):
    profile = "vulnerable"
    server_version = "LabServer/1.0.3"
    sys_version = ""
    protocol_version = "HTTP/1.0"

    def log_message(self, fmt, *args):   # console shor kam
        pass

    def version_string(self):
        # hardened profile Server header mein version nahi dikhata
        return self.server_version if self.profile == "vulnerable" else "LabServer"

    # -- helpers
    def _send(self, status, body=b"", content_type="text/html; charset=utf-8", extra=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for key, value in (extra or []):
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _common_headers(self):
        if self.profile == "hardened":
            return [
                ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
                ("X-Content-Type-Options", "nosniff"),
                ("Referrer-Policy", "strict-origin-when-cross-origin"),
                ("Permissions-Policy", "camera=(), microphone=()"),
                ("Cache-Control", "no-store"),
            ]
        return [("X-Powered-By", "PHP/7.4.3")]

    # -- routes
    def do_GET(self):
        path = urlsplit(self.path).path
        vulnerable = self.profile == "vulnerable"
        headers = self._common_headers()

        if path in ("/", "/index.html"):
            if vulnerable:
                headers += [("Set-Cookie", "PHPSESSID=lab-session-value; Path=/"),
                            ("Set-Cookie", "theme=dark; Path=/")]
                body = VULNERABLE_HOME
            else:
                headers += [("Set-Cookie", "sessionid=lab-session-value; Path=/; HttpOnly; SameSite=Lax")]
                body = HARDENED_HOME
            return self._send(200, body, extra=headers)
        if vulnerable and path == "/.git/HEAD":
            return self._send(200, b"ref: refs/heads/main\n", "text/plain", headers)
        if vulnerable and path == "/.env":
            return self._send(200, b"APP_ENV=lab\nDB_PASSWORD=not-a-real-secret\n", "text/plain", headers)
        if vulnerable and path == "/uploads/":
            return self._send(200, LISTING, extra=headers)
        if path == "/big":   # body size limit test ke liye
            return self._send(200, b"A" * 200000, "text/plain", headers)
        if path == "/slow":
            time.sleep(4)
            return self._send(200, b"slow response", "text/plain", headers)
        if path == "/redirect-metadata":
            return self._send(302, b"", extra=[("Location", "http://169.254.169.254/latest/meta-data/")])
        if path == "/redirect-mapped":
            return self._send(302, b"", extra=[("Location", "http://[::ffff:169.254.169.254]/")])
        if path == "/redirect-loop":
            return self._send(302, b"", extra=[("Location", "/redirect-loop")])
        if path == "/redirect-ok":
            return self._send(302, b"", extra=[("Location", "/")])
        return self._send(404, b"<html><body><h1>Not Found</h1></body></html>", extra=headers)

    do_HEAD = do_GET

    def do_OPTIONS(self):
        allow = "GET, POST, PUT, DELETE, TRACE, OPTIONS" if self.profile == "vulnerable" else "GET, POST, OPTIONS"
        self._send(204, b"", extra=[("Allow", allow)] + self._common_headers())

    def do_TRACE(self):
        if self.profile != "vulnerable":
            return self._send(405, b"", extra=[("Allow", "GET, POST, OPTIONS")])
        echo = f"TRACE {self.path} HTTP/1.0\r\n".encode()
        self._send(200, echo, "message/http")


def make_server(profile: str = "vulnerable", port: int = 5001, host: str = "127.0.0.1") -> ThreadingHTTPServer:
    handler = type("ProfileHandler", (LabHandler,), {"profile": profile})
    server = ThreadingHTTPServer((host, port), handler)
    server.daemon_threads = True
    return server


def main():
    parser = argparse.ArgumentParser(description="Local misconfigured lab target (testing only).")
    parser.add_argument("--profile", choices=("vulnerable", "hardened"), default="vulnerable")
    parser.add_argument("--port", type=int, default=5001)
    args = parser.parse_args()
    server = make_server(args.profile, args.port)
    print(f"Lab server ({args.profile}) running on http://127.0.0.1:{args.port}/  (Ctrl+C to stop)")
    print("Scan it from the app with ALLOW_LAB_TARGETS=true in your .env file.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
