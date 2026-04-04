#!/usr/bin/env python3
"""
case1_response_type_code_with_PKCE_client.py - OAuth2.0 認可コードフロー クライアント

ケース: response_type=code

【シーケンス】
  STEP 1. PKCE（code_verifier / code_challenge）· state を生成
  STEP 2. 認可リクエスト URL を生成
  STEP 3. コールバックサーバを起動し、認可 URL をターミナルに表示
  STEP 4. コールバック受信（code · state）
  STEP 5. state 検証（CSRF 対策）
  STEP 6. トークンエンドポイントへ POST（認可コード → トークン交換）
  STEP 7. トークン受信・表示
  STEP 8〜10. OIDC のみ（JWT検証・UserInfo・sub一致確認）

【実行方法】
  python case1_response_type_code_with_PKCE_client.py

【依存】
  requests
"""

import base64
import hashlib
import json
import secrets
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread

import requests

KEYCLOAK_BASE  = "http://localhost:8080"
REALM          = "sample"
CLIENT_ID      = "oauth2-auth-code"
REDIRECT_URI   = "http://localhost:8888/callback"
SCOPE          = "profile email"   # openid を含めない → id_token が返されない
CALLBACK_PORT  = 8888

AUTH_ENDPOINT  = f"{KEYCLOAK_BASE}/realms/{REALM}/protocol/openid-connect/auth"
TOKEN_ENDPOINT = f"{KEYCLOAK_BASE}/realms/{REALM}/protocol/openid-connect/token"


def print_step(num, title):
    print(f"\n{'='*60}\n STEP {num}: {title}\n{'='*60}")


def print_ok(msg):
    print(f"  [OK] {msg}")


def print_param(key, value):
    print(f"  {key:<28}: {value}")


def pretty_json(obj):
    return json.dumps(obj, ensure_ascii=False, indent=2)


# ============================================================
# STEP 1: PKCE · state の生成
# ============================================================

def generate_pkce():
    code_verifier = secrets.token_urlsafe(32)
    digest = hashlib.sha256(code_verifier.encode()).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return code_verifier, code_challenge


def generate_state():
    return secrets.token_urlsafe(16)


# ============================================================
# STEP 2: 認可リクエスト URL の生成
# ============================================================

def build_auth_url(state, code_challenge):
    params = {
        "response_type":         "code",
        "client_id":             CLIENT_ID,
        "redirect_uri":          REDIRECT_URI,
        "scope":                 SCOPE,
        "state":                 state,
        "code_challenge":        code_challenge,
        "code_challenge_method": "S256",
    }
    return AUTH_ENDPOINT + "?" + urllib.parse.urlencode(params)


# ============================================================
# STEP 3・4: コールバックサーバ
# ============================================================

_callback_result: dict = {}


class CallbackHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != "/callback":
            self.send_response(204)
            self.end_headers()
            return
        params = dict(urllib.parse.parse_qsl(parsed.query))
        print_step(4, "コールバック受信")
        print(f"  リクエストパス: {parsed.path}\n")
        for k, v in params.items():
            print_param(k, v)
        if "code" in params or "error" in params:
            _callback_result.update(params)
        body = "<html><body><h2>認証完了。ターミナルを確認してください。</h2></body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, format, *args):
        pass


def start_callback_server():
    server = HTTPServer(("localhost", CALLBACK_PORT), CallbackHandler)
    Thread(target=server.serve_forever, daemon=True).start()
    return server


# ============================================================
# STEP 5: state 検証（CSRF 対策）
# ============================================================

def verify_state(expected, actual):
    print_step(5, "state パラメータの検証（CSRF 対策）")
    print_param("送信した state", expected)
    print_param("受信した state", actual)
    if expected != actual:
        print("\n  [ERROR] state が一致しません！CSRF 攻撃の可能性があります。")
        sys.exit(1)
    print_ok("state 一致確認（CSRF チェック OK）")


# ============================================================
# STEP 6: トークンエンドポイントへ POST
# ============================================================

def exchange_token(code, code_verifier):
    print_step(6, "トークンエンドポイントへ POST（認可コード → トークン交換）")
    print(f"  URL: {TOKEN_ENDPOINT}\n")
    body_params = {
        "grant_type":    "authorization_code",
        "client_id":     CLIENT_ID,
        "redirect_uri":  REDIRECT_URI,
        "code":          code,
        "code_verifier": code_verifier,
    }
    print("  送信するパラメータ:")
    for k, v in body_params.items():
        print_param(f"    {k}", v)
    resp = requests.post(TOKEN_ENDPOINT, data=body_params)
    if resp.status_code != 200:
        print(f"\n  [ERROR] HTTP {resp.status_code}: {resp.text[:300]}")
        sys.exit(1)
    return resp.json()


# ============================================================
# STEP 7: トークン受信・表示
# ============================================================

def show_tokens(token_resp):
    print_step(7, "トークン受信")
    access_token  = token_resp.get("access_token", "")
    refresh_token = token_resp.get("refresh_token", "")
    print(f"\n  ── アクセストークン (Access Token) ──────────────────")
    print(f"  {access_token[:80]}...")
    print(f"\n  ── リフレッシュトークン (Refresh Token) ─────────────")
    print(f"  {refresh_token[:80]}...")
    print(f"\n  ── トークン情報 ──────────────────────────────────────")
    print_param("  expires_in", str(token_resp.get("expires_in", "-")) + " 秒")
    print_param("  token_type", token_resp.get("token_type", "-"))


# ============================================================
# STEP 8〜10: OIDC のみ（JWT検証・UserInfo・sub一致確認）
# OAuth2.0 ではこれらの STEP はありません
# ============================================================


# ============================================================
# メイン処理
# ============================================================

def main():
    print("\n" + "="*60)
    print(" OAuth2.0 認可コードフロー クライアント")
    print(" Case 1 - response_type=code（OAuth2.0）")
    print("="*60)

    # STEP 1
    print_step(1, "PKCE · state の生成")
    code_verifier, code_challenge = generate_pkce()
    state = generate_state()
    print_param("code_verifier",         code_verifier)
    print_param("code_challenge",        code_challenge)
    print_param("code_challenge_method", "S256")
    print_param("state",                 state)

    # STEP 2
    print_step(2, "認可リクエスト URL の生成")
    auth_url = build_auth_url(state, code_challenge)
    parsed = urllib.parse.urlparse(auth_url)
    print(f"  {parsed.scheme}://{parsed.netloc}{parsed.path}")
    for k, v in urllib.parse.parse_qsl(parsed.query):
        print(f"    &{k}={v}")

    # STEP 3
    print_step(3, "コールバックサーバ起動 & 認可URL の表示")
    server = start_callback_server()
    print(f"  コールバックサーバ起動: http://localhost:{CALLBACK_PORT}/callback")
    print(f"\n  以下の URL をブラウザでコピー&ペーストして開いてください:")
    print(f"\n  {auth_url}")
    print(f"\n  Keycloak のログイン画面:")
    print(f"  ユーザー名: testuser  /  パスワード: password")
    print("\n  （ログイン完了を待機中...）")

    while not _callback_result:
        pass
    server.shutdown()

    if "error" in _callback_result:
        print(f"\n  [ERROR] error: {_callback_result.get('error')}")
        print(f"          error_description: {_callback_result.get('error_description', '')}")
        sys.exit(1)

    code           = _callback_result.get("code")
    received_state = _callback_result.get("state")

    # STEP 5
    verify_state(state, received_state)

    # STEP 6
    token_resp = exchange_token(code, code_verifier)

    # STEP 7
    show_tokens(token_resp)

    # STEP 8〜10: OIDC のみ

    print("\n" + "="*60)
    print(" 実験完了")
    print("="*60 + "\n")


if __name__ == "__main__":
    main()