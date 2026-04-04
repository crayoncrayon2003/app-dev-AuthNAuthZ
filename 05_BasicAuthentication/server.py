#!/usr/bin/env python3
from http.server import HTTPServer, BaseHTTPRequestHandler
import base64

HOST = "0.0.0.0"
PORT = 8000

USERNAME = "user"
PASSWORD = "pass"

class MyHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        if self.path == "/public":
            self.handle_public()

        elif self.path == "/private":
            self.handle_private()

        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")

    # -------------------------
    # 認証なし
    # -------------------------
    def handle_public(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()

        body = """
        <html>
        <body>
            <h1>Public Page</h1>
            <p>認証不要です</p>
        </body>
        </html>
        """
        self.wfile.write(body.encode("utf-8"))

    # -------------------------
    # Basic認証あり
    # -------------------------
    def handle_private(self):
        auth_header = self.headers.get("Authorization")

        if not auth_header or not self.is_authenticated(auth_header):
            self.request_auth()
            return

        # 認証成功
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()

        body = """
        <html>
        <body>
            <h1>Private Page</h1>
            <p>認証成功</p>
        </body>
        </html>
        """
        self.wfile.write(body.encode("utf-8"))

    # -------------------------
    # 認証チェック
    # -------------------------
    def is_authenticated(self, auth_header):
        try:
            scheme, encoded = auth_header.split(" ", 1)
            if scheme != "Basic":
                return False

            decoded = base64.b64decode(encoded).decode("utf-8")
            user, password = decoded.split(":", 1)

            return user == USERNAME and password == PASSWORD

        except Exception:
            return False

    # -------------------------
    # 認証要求レスポンス
    # -------------------------
    def request_auth(self):
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="Test Realm"')
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()

        body = """
        <html>
        <body>
            <h1>401 Unauthorized</h1>
            <p>認証が必要です</p>
        </body>
        </html>
        """
        self.wfile.write(body.encode("utf-8"))


if __name__ == "__main__":
    server = HTTPServer((HOST, PORT), MyHandler)
    print(f"Server running at http://{HOST}:{PORT}")
    server.serve_forever()