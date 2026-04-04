#!/usr/bin/env python3
"""
case2_with_PKCE_client.py - OIDC クライアント（OpenLDAP 連携）

【本実験の構成】
  OpenLDAP（IdM）← ユーザー情報を管理
        │ LDAP フェデレーション（ユーザー同期）
        ▼
  Keycloak（IdP）← OpenLDAP のユーザーで認証処理
        │ OIDC（認可コードフロー）
        ▼
  クライアント（このスクリプト）

【case1 との違い】
  case1: Keycloak × 2台（SP ↔ IdP）のフェデレーション
  case2: OpenLDAP（IdM）+ Keycloak（IdP）の連携
         ユーザーは OpenLDAP にのみ存在し、Keycloak がそれを読み込む

【OIDCシーケンス（認可コードフローと同じ）】
  STEP 1〜10: case1 と同じシーケンス
  ※ クライアントから見ると OpenLDAP の存在は透過的
     （LDAP 連携は Keycloak 内部で完結する）

【実行方法】
  python case2_with_PKCE_client.py

【依存】
  requests, PyJWT[crypto]
"""

import base64
import hashlib
import json
import secrets
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread

import jwt
import requests

KEYCLOAK_BASE     = "http://localhost:8080"
REALM             = "sample"
CLIENT_ID         = "oidc-ldap"
REDIRECT_URI      = "http://localhost:8888/callback"
SCOPE             = "openid profile email"
CALLBACK_PORT     = 8888

AUTH_ENDPOINT      = f"{KEYCLOAK_BASE}/realms/{REALM}/protocol/openid-connect/auth"
TOKEN_ENDPOINT     = f"{KEYCLOAK_BASE}/realms/{REALM}/protocol/openid-connect/token"
JWKS_ENDPOINT      = f"{KEYCLOAK_BASE}/realms/{REALM}/protocol/openid-connect/certs"
USERINFO_ENDPOINT  = f"{KEYCLOAK_BASE}/realms/{REALM}/protocol/openid-connect/userinfo"
ISSUER             = f"{KEYCLOAK_BASE}/realms/{REALM}"

def print_step(num, title):
    print(f"\n{'='*60}\n STEP {num}: {title}\n{'='*60}")

def print_ok(msg):    print(f"  [OK] {msg}")
def print_param(k,v): print(f"  {k:<28}: {v}")
def pretty_json(obj): return json.dumps(obj, ensure_ascii=False, indent=2)

def generate_pkce():
    code_verifier = secrets.token_urlsafe(32)
    digest = hashlib.sha256(code_verifier.encode()).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return code_verifier, code_challenge

def generate_state(): return secrets.token_urlsafe(16)
def generate_nonce(): return secrets.token_urlsafe(16)

def build_auth_url(state, code_challenge, nonce):
    params = {
        "response_type":         "code",
        "client_id":             CLIENT_ID,
        "redirect_uri":          REDIRECT_URI,
        "scope":                 SCOPE,
        "state":                 state,
        "code_challenge":        code_challenge,
        "code_challenge_method": "S256",
        "nonce":                 nonce,
    }
    return AUTH_ENDPOINT + "?" + urllib.parse.urlencode(params)

_callback_result: dict = {}

class CallbackHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != "/callback":
            self.send_response(204); self.end_headers(); return
        params = dict(urllib.parse.parse_qsl(parsed.query))
        print_step(4, "コールバック受信")
        print(f"  リクエストパス: {parsed.path}\n")
        for k, v in params.items():
            print_param(k, v)
        if "code" in params or "error" in params:
            _callback_result.update(params)
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write("<html><body><h2>認証完了。ターミナルを確認してください。</h2></body></html>".encode())

    def log_message(self, format, *args): pass

def start_callback_server():
    server = HTTPServer(("localhost", CALLBACK_PORT), CallbackHandler)
    Thread(target=server.serve_forever, daemon=True).start()
    return server

def verify_state(expected, actual):
    print_step(5, "state パラメータの検証（CSRF 対策）")
    print_param("送信した state", expected)
    print_param("受信した state", actual)
    if expected != actual:
        print("\n  [ERROR] state が一致しません！"); sys.exit(1)
    print_ok("state 一致確認（CSRF チェック OK）")

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
    for k, v in body_params.items():
        print_param(f"  {k}", v)
    resp = requests.post(TOKEN_ENDPOINT, data=body_params)
    if resp.status_code != 200:
        print(f"\n  [ERROR] HTTP {resp.status_code}: {resp.text[:300]}"); sys.exit(1)
    return resp.json()

def show_tokens(token_resp):
    print_step(7, "トークン受信")
    access_token  = token_resp.get("access_token", "")
    id_token      = token_resp.get("id_token", "")
    refresh_token = token_resp.get("refresh_token", "")
    print(f"\n  ── アクセストークン ─────────────────────────────────")
    print(f"  {access_token[:80]}...")
    print(f"\n  ── ID トークン ──────────────────────────────────────")
    print(f"  {id_token[:80]}...")
    print(f"\n  ── リフレッシュトークン ─────────────────────────────")
    print(f"  {refresh_token[:80]}...")
    print_param("\n  expires_in", str(token_resp.get("expires_in", "-")) + " 秒")

def verify_id_token(id_token, nonce):
    print_step(8, "ID トークンの検証（OIDC 必須）")
    print("  検証項目: 署名 / iss / aud / exp / nonce\n")
    print("  ⚠️  LDAP 連携固有の注意点:")
    print(f"      JWKs・iss ともに Keycloak（IdP）の情報で検証します")
    print(f"      OpenLDAP（IdM）は認証フローには直接登場しません\n")

    jwks_client = jwt.PyJWKClient(JWKS_ENDPOINT)
    signing_key = jwks_client.get_signing_key_from_jwt(id_token)

    try:
        payload = jwt.decode(
            id_token, signing_key.key,
            algorithms=["RS256"],
            audience=CLIENT_ID,
            issuer=ISSUER,
        )
    except jwt.ExpiredSignatureError:
        print("  [ERROR] exp 検証失敗"); sys.exit(1)
    except jwt.InvalidAudienceError:
        print("  [ERROR] aud 検証失敗"); sys.exit(1)
    except jwt.InvalidIssuerError:
        print("  [ERROR] iss 検証失敗"); sys.exit(1)
    except Exception as e:
        print(f"  [ERROR] {e}"); sys.exit(1)

    if payload.get("nonce") != nonce:
        print(f"  [ERROR] nonce 検証失敗"); sys.exit(1)

    print_ok("署名検証 OK")
    print_ok(f"iss 検証 OK  : {payload.get('iss')}")
    print_ok(f"aud 検証 OK  : {payload.get('aud')}")
    print_ok(f"exp 検証 OK  : 有効期限内")
    print_ok(f"nonce 検証 OK: {payload.get('nonce')}")

    print(f"\n  ── ID トークン ペイロード（検証済み）────────────────")
    print(pretty_json(payload))

    # LDAP 連携固有のクレームを確認
    print(f"\n  ── LDAP 連携固有の確認 ──────────────────────────────")
    print_param("  sub",               payload.get("sub", "-"))
    print_param("  preferred_username", payload.get("preferred_username", "-"))
    print_param("  email",             payload.get("email", "-"))
    print(f"\n  ポイント: ユーザー情報（username・email）は OpenLDAP から同期された値です")
    print(f"            クライアントから見ると LDAP の存在は透過的です")

    return payload

def call_userinfo(access_token):
    print_step(9, "UserInfo エンドポイントの呼び出し")
    print(f"  URL: {USERINFO_ENDPOINT}\n")
    resp = requests.get(USERINFO_ENDPOINT,
                        headers={"Authorization": f"Bearer {access_token}"})
    if resp.status_code != 200:
        print(f"  [ERROR] HTTP {resp.status_code}: {resp.text[:300]}"); sys.exit(1)
    userinfo = resp.json()
    print_ok("UserInfo 取得成功")
    print(pretty_json(userinfo))
    return userinfo

def main():
    print("\n" + "="*60)
    print(" OIDC クライアント（OpenLDAP 連携）")
    print(" Case 2 - OpenLDAP + Keycloak")
    print("="*60)
    print(f"\n  構成: クライアント → Keycloak（IdP）← OpenLDAP（IdM）")
    print(f"  ユーザーは OpenLDAP に存在し、Keycloak が同期して認証します")

    print_step(1, "PKCE · state · nonce の生成")
    code_verifier, code_challenge = generate_pkce()
    state = generate_state()
    nonce = generate_nonce()
    print_param("code_verifier",         code_verifier)
    print_param("code_challenge",        code_challenge)
    print_param("code_challenge_method", "S256")
    print_param("state",                 state)
    print_param("nonce",                 nonce)

    print_step(2, "認可リクエスト URL の生成")
    auth_url = build_auth_url(state, code_challenge, nonce)
    parsed = urllib.parse.urlparse(auth_url)
    print(f"  {parsed.scheme}://{parsed.netloc}{parsed.path}")
    for k, v in urllib.parse.parse_qsl(parsed.query):
        print(f"    &{k}={v}")
    print(f"\n  ポイント: シーケンスは 認可コードフローと同じです")
    print(f"            LDAP 連携は Keycloak 内部で完結するためクライアントから透過的です")

    print_step(3, "コールバックサーバ起動 & 認可URL の表示")
    server = start_callback_server()
    print(f"  コールバックサーバ起動: http://localhost:{CALLBACK_PORT}/callback")
    print(f"\n  以下の URL をブラウザでコピー&ペーストして開いてください:")
    print(f"\n  {auth_url}")
    print(f"\n  Keycloak のログイン画面:")
    print(f"  ユーザー名: testuser  /  パスワード: password")
    print(f"\n  ※ testuser は OpenLDAP（IdM）のユーザーです")
    print("\n  （ログイン完了を待機中...）")

    while not _callback_result:
        pass
    server.shutdown()

    if "error" in _callback_result:
        print(f"\n  [ERROR] error: {_callback_result.get('error')}")
        print(f"          description: {_callback_result.get('error_description', '')}")
        sys.exit(1)

    code           = _callback_result.get("code")
    received_state = _callback_result.get("state")

    verify_state(state, received_state)
    token_resp       = exchange_token(code, code_verifier)
    show_tokens(token_resp)

    access_token     = token_resp.get("access_token", "")
    id_token         = token_resp.get("id_token", "")

    id_token_payload = verify_id_token(id_token, nonce)
    userinfo         = call_userinfo(access_token)

    print_step(10, "sub クレームの一致確認（ID トークン vs UserInfo）")
    sub_id = id_token_payload.get("sub")
    sub_ui = userinfo.get("sub")
    print_param("ID トークンの sub", sub_id)
    print_param("UserInfo の sub",   sub_ui)
    if sub_id != sub_ui:
        print("\n  [ERROR] sub が一致しません！"); sys.exit(1)
    print_ok("sub 一致確認 OK（同一ユーザー）")

    print("\n" + "="*60)
    print(" 実験完了")
    print("="*60 + "\n")

if __name__ == "__main__":
    main()