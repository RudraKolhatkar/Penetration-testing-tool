"""Mock vulnerable web server for demonstration and academic testing.

Simulates all security misconfigurations and vulnerabilities recognized by the auditor:
1. Critical Exposures: /.env, /.aws/credentials, /id_rsa, /actuator/env, /wp-config.php.bak
2. High-Risk Exposures: /.git/HEAD, /backup.zip, /config.php.bak, /phpinfo.php
3. High-Risk Misconfigurations: Insecure CORS with credentials, Directory Indexing (<title>Index of /</title>)
4. Insecure Cookies: Session cookies missing HttpOnly flag
5. Medium / Info Misconfigurations: TRACE method enabled, Server technology disclosure, missing headers
6. Public Standards: /robots.txt, /.well-known/security.txt
7. Rate Limiting: HTTP 429 when burst threshold exceeds 10 requests / 5 seconds
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import sys
import threading
import time

REQUEST_WINDOW_SECONDS = 5.0
MAX_BURST_REQUESTS = 10
request_timestamps = []
lock = threading.Lock()


class MockVulnerableHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Suppress verbose terminal log spam during testing
        return

    def do_HEAD(self):
        self.send_response(200)
        self._add_misconfigured_headers()
        self.end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET, HEAD, POST, OPTIONS, TRACE")
        self._add_misconfigured_headers()
        self.end_headers()

    def do_GET(self):
        path = self.path.split("?")[0]

        # 1. Critical credential and environment exposures
        if path == "/.env":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self._add_misconfigured_headers()
            self.end_headers()
            self.wfile.write(b"DB_HOST=127.0.0.1\nDB_USER=root\nDB_PASSWORD=SuperSecretPass123!\nAPI_KEY=live_sk_948834710\n")
            return

        if path == "/.aws/credentials":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self._add_misconfigured_headers()
            self.end_headers()
            self.wfile.write(b"[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n")
            return

        if path == "/id_rsa":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self._add_misconfigured_headers()
            self.end_headers()
            self.wfile.write(b"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn\n-----END OPENSSH PRIVATE KEY-----\n")
            return

        if path == "/actuator/env":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._add_misconfigured_headers()
            self.end_headers()
            self.wfile.write(b'{"activeProfiles":["production"],"propertySources":[{"name":"systemEnvironment","properties":{"SECRET_KEY":{"value":"h4ckm3_1f_u_c4n"}}}]}')
            return

        if path == "/wp-config.php.bak":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self._add_misconfigured_headers()
            self.end_headers()
            self.wfile.write(b"define('DB_NAME', 'wordpress');\ndefine('DB_USER', 'wp_admin');\ndefine('DB_PASSWORD', 'P@ssword2024!');\n")
            return

        # 2. High-risk repository, diagnostic, and archive exposures
        if path == "/.git/HEAD":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self._add_misconfigured_headers()
            self.end_headers()
            self.wfile.write(b"ref: refs/heads/main\n")
            return

        if path == "/backup.zip":
            self.send_response(200)
            self.send_header("Content-Type", "application/zip")
            self._add_misconfigured_headers()
            self.end_headers()
            self.wfile.write(b"PK\x03\x04(Simulated zip archive content...)")
            return

        if path == "/config.php.bak":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self._add_misconfigured_headers()
            self.end_headers()
            self.wfile.write(b"<?php $db_pass = 'db_secret_backup_pass'; ?>\n")
            return

        if path == "/phpinfo.php":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self._add_misconfigured_headers()
            self.end_headers()
            self.wfile.write(b"<html><head><title>phpinfo()</title></head><body><h1>PHP Version 7.4.3</h1><p>Configuration details leaked</p></body></html>")
            return

        # 3. Informational endpoints & administrative portals
        if path in ("/admin", "/admin.php"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self._add_misconfigured_headers()
            self.end_headers()
            self.wfile.write(b"<html><body><h1>Admin Portal</h1><form><input name='user'/><input name='pass'/></form></body></html>")
            return

        if path == "/robots.txt":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self._add_misconfigured_headers()
            self.end_headers()
            self.wfile.write(b"User-agent: *\nDisallow: /admin\nDisallow: /private\nDisallow: /backups\n")
            return

        if path == "/.well-known/security.txt":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self._add_misconfigured_headers()
            self.end_headers()
            self.wfile.write(b"Contact: mailto:security@example.com\nExpires: 2027-12-31T23:59:59.000Z\nPreferred-Languages: en\n")
            return

        # 4. Rate-limiting check for stress auditor
        with lock:
            now = time.time()
            global request_timestamps
            request_timestamps = [t for t in request_timestamps if now - t < REQUEST_WINDOW_SECONDS]
            request_timestamps.append(now)

            if len(request_timestamps) > MAX_BURST_REQUESTS:
                self.send_response(429)
                self.send_header("Content-Type", "application/json")
                self.send_header("Retry-After", "5")
                self._add_misconfigured_headers()
                self.end_headers()
                self.wfile.write(b'{"error": "Too Many Requests", "message": "Rate limit exceeded"}')
                return

        # 5. Default root web page (simulates Directory Indexing enabled)
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self._add_misconfigured_headers()
        self.end_headers()
        self.wfile.write(
            b"<!DOCTYPE HTML><html><head><title>Index of /</title></head>"
            b"<body><h1>Index of /</h1><ul>"
            b"<li><a href='.env'>.env</a></li>"
            b"<li><a href='backup.zip'>backup.zip</a></li>"
            b"<li><a href='admin/'>admin/</a></li>"
            b"</ul><hr><address>Apache/2.4.41 (Ubuntu) Server at 127.0.0.1</address></body></html>"
        )

    def _add_misconfigured_headers(self):
        """Inject server leaks, insecure cookies, and CORS misconfigurations."""
        # Server banner information leaks
        self.send_header("Server", "Apache/2.4.41 (Ubuntu)")
        self.send_header("X-Powered-By", "PHP/7.4.3")

        # Insecure Session Cookie: Missing HttpOnly flag
        self.send_header("Set-Cookie", "session_token=secret_session_token_abc123; Path=/")

        # Insecure CORS: Reflects arbitrary origin and permits credentials
        client_origin = self.headers.get("Origin")
        if client_origin:
            self.send_header("Access-Control-Allow-Origin", client_origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")


def run_mock_server(port: int = 8888):
    server = HTTPServer(("127.0.0.1", port), MockVulnerableHandler)
    print(f"[*] Mock target server active on http://127.0.0.1:{port}")
    print("[*] Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Stopping mock server...")
        server.server_close()


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8888
    run_mock_server(port)
