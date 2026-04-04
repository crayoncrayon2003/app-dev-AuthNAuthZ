#!/usr/bin/env python3
"""
case2_response_type_id_token_client.py - OIDC インプリシットフロー クライアント

ケース: response_type=id_token

【OAuth2.0 と OIDC の違い】
  scope に openid を含める → id_token がフラグメントで返される
  STEP 7〜8 があります（JWT検証は OIDC のみ）
  UserInfo・sub一致確認は access_token が返されないため省略

【シーケンス】
  STEP 1. state · nonce を生成
  STEP 2. 認可リクエスト URL を生成
  STEP 3. コールバックサーバを起動し、認可 URL をターミナルに表示
  STEP 4. フラグメント受信（JavaScript 転送）
  STEP 5. state 検証（CSRF 対策）
  STEP 6. トークン受信・表示（id_token のみ）
  STEP 7. ID トークンの検証（JWT検証）
  STEP 8. UserInfo・sub一致確認は access_token が返されないため省略

【実行方法】
  python case2_response_type_id_token_client.py

【依存】
  requests, PyJWT[crypto]
"""

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
CLIENT_ID         = "oidc-implicit-id-token"
REDIRECT_URI      = "http://localhost:8888/callback"
SCOPE             = "openid profile email"  # openid を含める → id_token が返される
CALLBACK_PORT     = 8888

AUTH_ENDPOINT      = f"{KEYCLOAK_BASE}/realms/{REALM}/protocol/openid-connect/auth"
JWKS_ENDPOINT      = f"{KEYCLOAK_BASE}/realms/{REALM}/protocol/openid-connect/certs"
ISSUER             = f"{KEYCLOAK_BASE}/realms/{REALM}"


def print_step(num, title):
    print(f"\n{'='*60}\n STEP {num}: {title}\n{'='*60}")


def print_ok(msg):
    print(f"  [OK] {msg}")


def print_param(key, value):
    print(f"  {key:<28}: {value}")


def pretty_json(obj):
    return json.dumps(obj, ensure_ascii=False, indent=2)


# ============================================================
# STEP 1: state · nonce の生成
# ============================================================

def generate_state():
    return secrets.token_urlsafe(16)


def generate_nonce():
    return secrets.token_urlsafe(16)


# ============================================================
# STEP 2: 認可リクエスト URL の生成
# ============================================================

def build_auth_url(state, nonce):
    params = {
        "response_type": "id_token",        # id_token をフラグメントで直接返す
        "client_id":     CLIENT_ID,
        "redirect_uri":  REDIRECT_URI,
        "scope":         SCOPE,
        "state":         state,
        "nonce":         nonce,
    }
    return AUTH_ENDPOINT + "?" + urllib.parse.urlencode(params)


# ============================================================
# STEP 3・4: コールバックサーバ
# フラグメントはサーバに届かないため JavaScript で /token に転送する
# ============================================================

_token_result: dict = {}

CALLBACK_HTML = """\
<!DOCTYPE html>
<html><head><meta charset="UTF-8"></head>
<body><p>処理中...</p>
<script>
  const fragment = window.location.hash.substring(1);
  if (fragment) { window.location.href = "/token?" + fragment; }
  else { document.body.innerHTML = "<p>エラー: フラグメントが空です。</p>"; }
</script></body></html>
"""


class CallbackHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/callback":
            print_step(4, "コールバック受信（/callback）")
            print("  フラグメント（#id_token=...）はサーバに届きません。")
            print("  JavaScript が /token に転送します。")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(CALLBACK_HTML.encode())
        elif parsed.path == "/token":
            params = dict(urllib.parse.parse_qsl(parsed.query))
            print_step(4, "トークン受信（/token ← JavaScript 転送）")
            for k, v in params.items():
                print_param(k, v[:60] + "..." if len(v) > 60 else v)
            if "id_token" in params or "error" in params:
                _token_result.update(params)
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write("<html><body><h2>完了。ターミナルを確認してください。</h2></body></html>".encode()) 
        else:
            self.send_response(204)
            self.end_headers()

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
    print_param("受信した state", actual or "（なし）")
    if expected != actual:
        print("\n  [ERROR] state が一致しません！CSRF 攻撃の可能性があります。")
        sys.exit(1)
    print_ok("state 一致確認（CSRF チェック OK）")


# ============================================================
# STEP 6: トークン受信・表示
# ============================================================

def show_tokens(token_result):
    print_step(6, "トークン受信・表示")
    id_token = token_result.get("id_token", "")
    print(f"\n  ── ID トークン (ID Token) ───────────────────────────")
    print(f"  {id_token[:80]}...")
    print(f"\n  ── トークン情報 ──────────────────────────────────────")
    print_param("  expires_in", str(token_result.get("expires_in", "-")) + " 秒")
    print(f"\n  ⚠️  response_type=id_token では access_token・refresh_token は返されません")


# ============================================================
# STEP 7: ID トークンの検証（OIDC のみ）
# ============================================================

def verify_id_token(id_token, nonce):
    print_step(7, "ID トークンの検証（OIDC のみ）")
    print("  検証項目: 署名 / iss / aud / exp / nonce\n")
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
        print("  [ERROR] exp 検証失敗")
        sys.exit(1)
    except jwt.InvalidAudienceError:
        print("  [ERROR] aud 検証失敗")
        sys.exit(1)
    except jwt.InvalidIssuerError:
        print("  [ERROR] iss 検証失敗")
        sys.exit(1)
    except jwt.InvalidSignatureError:
        print("  [ERROR] 署名検証失敗")
        sys.exit(1)
    except Exception as e:
        print(f"  [ERROR] {e}")
        sys.exit(1)
    if payload.get("nonce") != nonce:
        print(f"  [ERROR] nonce 検証失敗")
        sys.exit(1)
    print_ok("署名検証 OK")
    print_ok(f"iss 検証 OK  : {payload.get('iss')}")
    print_ok(f"aud 検証 OK  : {payload.get('aud')}")
    print_ok(f"exp 検証 OK  : 有効期限内")
    print_ok(f"nonce 検証 OK: {payload.get('nonce')}")
    print(f"\n  ── ID トークン ペイロード（検証済み）────────────────")
    print(pretty_json(payload))
    return payload


# ============================================================
# STEP 8: UserInfo・sub一致確認は access_token が返されないため省略
# ============================================================


# ============================================================
# メイン処理
# ============================================================

def main():
    print("\n" + "="*60)
    print(" OIDC インプリシットフロー クライアント")
    print(" Case 2 - response_type=id_token（OIDC）")
    print("="*60)

    # STEP 1
    print_step(1, "state · nonce の生成")
    state = generate_state()
    nonce = generate_nonce()
    print_param("state", state)
    print_param("nonce", nonce)
    print(f"\n  ※ インプリシットフローでは PKCE は使用しません")

    # STEP 2
    print_step(2, "認可リクエスト URL の生成")
    auth_url = build_auth_url(state, nonce)
    parsed = urllib.parse.urlparse(auth_url)
    print(f"  {parsed.scheme}://{parsed.netloc}{parsed.path}")
    for k, v in urllib.parse.parse_qsl(parsed.query):
        print(f"    &{k}={v}")
    print(f"\n  ポイント: response_type=id_token")
    print(f"    → id_token のみがフラグメントで返される")
    print(f"    → access_token は返されない")

    # STEP 3
    print_step(3, "コールバックサーバ起動 & 認可URL の表示")
    server = start_callback_server()
    print(f"  コールバックサーバ起動: http://localhost:{CALLBACK_PORT}/callback")
    print(f"\n  以下の URL をブラウザでコピー&ペーストして開いてください:")
    print(f"\n  {auth_url}")
    print(f"\n  Keycloak のログイン画面:")
    print(f"  ユーザー名: testuser  /  パスワード: password")
    print("\n  （ログイン完了を待機中...）")

    while not _token_result:
        pass
    server.shutdown()

    if "error" in _token_result:
        print(f"\n  [ERROR] error: {_token_result.get('error')}")
        sys.exit(1)

    # STEP 5
    verify_state(state, _token_result.get("state"))

    # STEP 6
    show_tokens(_token_result)

    id_token = _token_result.get("id_token", "")

    # STEP 7
    verify_id_token(id_token, nonce)

    # STEP 8: UserInfo・sub一致確認は access_token が返されないため省略

    print("\n" + "="*60)
    print(" 実験完了")
    print("="*60 + "\n")


if __name__ == "__main__":
    main()