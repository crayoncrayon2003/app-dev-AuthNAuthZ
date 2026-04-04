#!/usr/bin/env python3
"""
case2_response_type_code_token_with_PKCE_client.py - OIDC ハイブリッドフロー クライアント

ケース: response_type=code token

【認可レスポンス（フラグメント）で返るもの】
  code + access_token

【トークンエンドポイントで返るもの】
  access_token + id_token + refresh_token

【Case 1（code id_token）との違い】
  フラグメントに id_token が返されない
  → c_hash 検証は不要
  id_token はトークンエンドポイントからのみ取得する

【シーケンス】
  STEP 1.  PKCE · state · nonce を生成
  STEP 2.  認可リクエスト URL を生成（response_type=code token）
  STEP 3.  コールバックサーバ起動 & 認可URL 表示
  STEP 4.  フラグメント受信（code + access_token）
  STEP 5.  state 検証（CSRF 対策）
  STEP 6.  トークンエンドポイントへ POST（認可コード → トークン交換）
  STEP 7.  トークンエンドポイントの id_token 検証（OIDC のみ）
  STEP 8.  UserInfo エンドポイント呼び出し（OIDC のみ）
  STEP 9.  sub 一致確認（OIDC のみ）

【実行方法】
  python case2_response_type_code_token_with_PKCE_client.py

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
CLIENT_ID         = "oidc-hybrid-code-token"
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


def print_ok(msg):
    print(f"  [OK] {msg}")


def print_param(key, value):
    print(f"  {key:<28}: {value}")


def pretty_json(obj):
    return json.dumps(obj, ensure_ascii=False, indent=2)


# ============================================================
# STEP 1: PKCE · state · nonce の生成
# ============================================================

def generate_pkce():
    code_verifier = secrets.token_urlsafe(32)
    digest = hashlib.sha256(code_verifier.encode()).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return code_verifier, code_challenge


def generate_state():
    return secrets.token_urlsafe(16)


def generate_nonce():
    return secrets.token_urlsafe(16)


# ============================================================
# STEP 2: 認可リクエスト URL の生成
# ============================================================

def build_auth_url(state, code_challenge, nonce):
    params = {
        "response_type":         "code token",
        "client_id":             CLIENT_ID,
        "redirect_uri":          REDIRECT_URI,
        "scope":                 SCOPE,
        "state":                 state,
        "code_challenge":        code_challenge,
        "code_challenge_method": "S256",
        "nonce":                 nonce,
    }
    return AUTH_ENDPOINT + "?" + urllib.parse.urlencode(params)


# ============================================================
# STEP 3・4: コールバックサーバ
# ============================================================

_fragment_result: dict = {}

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
            print("  フラグメント（#code=...&access_token=...）はサーバに届きません。")
            print("  JavaScript が /token に転送します。")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(CALLBACK_HTML.encode())
        elif parsed.path == "/token":
            params = dict(urllib.parse.parse_qsl(parsed.query))
            print_step(4, "フラグメント受信（/token ← JavaScript 転送）")
            print("  ポイント: フラグメントに id_token は含まれません（response_type=code token）\n")
            for k, v in params.items():
                print_param(k, v[:60] + "..." if len(v) > 60 else v)
            if "code" in params or "error" in params:
                _fragment_result.update(params)
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
# STEP 7: トークンエンドポイントの ID トークン検証
# ============================================================

def verify_id_token(id_token, nonce):
    print_step(7, "トークンエンドポイントの ID トークン検証")
    print("  検証項目: 署名 / iss / aud / exp / nonce")
    print("  ※ response_type=code token ではフラグメントに id_token がないため")
    print("     c_hash 検証は不要（Case 1 との違い）\n")
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
    print_ok("署名 · iss · aud · exp · nonce 検証 OK")
    print(f"\n  ── ID トークン ペイロード（検証済み）────────────────")
    print(pretty_json(payload))
    return payload


# ============================================================
# STEP 8: UserInfo エンドポイント呼び出し
# ============================================================

def call_userinfo(access_token):
    print_step(8, "UserInfo エンドポイントの呼び出し")
    print(f"  URL: {USERINFO_ENDPOINT}\n")
    resp = requests.get(
        USERINFO_ENDPOINT,
        headers={"Authorization": f"Bearer {access_token}"},
    )
    if resp.status_code != 200:
        print(f"  [ERROR] HTTP {resp.status_code}: {resp.text[:300]}")
        sys.exit(1)
    userinfo = resp.json()
    print_ok("UserInfo 取得成功")
    print(f"\n  ── UserInfo レスポンス ───────────────────────────────")
    print(pretty_json(userinfo))
    return userinfo


# ============================================================
# STEP 9: sub 一致確認
# ============================================================

def verify_sub(id_token_payload, userinfo):
    print_step(9, "sub クレームの一致確認")
    sub_id = id_token_payload.get("sub")
    sub_ui = userinfo.get("sub")
    print_param("ID トークンの sub", sub_id)
    print_param("UserInfo の sub",   sub_ui)
    if sub_id != sub_ui:
        print("\n  [ERROR] sub が一致しません！")
        sys.exit(1)
    print_ok("sub 一致確認 OK（同一ユーザー）")


# ============================================================
# メイン処理
# ============================================================

def main():
    print("\n" + "="*60)
    print(" OIDC ハイブリッドフロー クライアント")
    print(" Case 2 - response_type=code token（OIDC）")
    print("="*60)

    # STEP 1
    print_step(1, "PKCE · state · nonce の生成")
    code_verifier, code_challenge = generate_pkce()
    state = generate_state()
    nonce = generate_nonce()
    print_param("code_verifier",         code_verifier)
    print_param("code_challenge",        code_challenge)
    print_param("code_challenge_method", "S256")
    print_param("state",                 state)
    print_param("nonce",                 nonce)

    # STEP 2
    print_step(2, "認可リクエスト URL の生成")
    auth_url = build_auth_url(state, code_challenge, nonce)
    parsed = urllib.parse.urlparse(auth_url)
    print(f"  {parsed.scheme}://{parsed.netloc}{parsed.path}")
    for k, v in urllib.parse.parse_qsl(parsed.query):
        print(f"    &{k}={v}")
    print(f"\n  ポイント: response_type=code token")
    print(f"    → フラグメントに code + access_token が返される")
    print(f"    → id_token はトークンエンドポイントからのみ取得（c_hash 検証不要）")

    # STEP 3
    print_step(3, "コールバックサーバ起動 & 認可URL の表示")
    server = start_callback_server()
    print(f"  コールバックサーバ起動: http://localhost:{CALLBACK_PORT}/callback")
    print(f"\n  以下の URL をブラウザでコピー&ペーストして開いてください:")
    print(f"\n  {auth_url}")
    print(f"\n  Keycloak のログイン画面:")
    print(f"  ユーザー名: testuser  /  パスワード: password")
    print("\n  （ログイン完了を待機中...）")

    while not _fragment_result:
        pass
    server.shutdown()

    if "error" in _fragment_result:
        print(f"\n  [ERROR] error: {_fragment_result.get('error')}")
        sys.exit(1)

    code           = _fragment_result.get("code")
    received_state = _fragment_result.get("state")

    # STEP 5
    verify_state(state, received_state)

    # STEP 6
    token_resp = exchange_token(code, code_verifier)

    # STEP 7〜9
    id_token_payload = verify_id_token(token_resp.get("id_token", ""), nonce)
    access_token     = token_resp.get("access_token", "")
    userinfo         = call_userinfo(access_token)
    verify_sub(id_token_payload, userinfo)

    print("\n" + "="*60)
    print(" 実験完了")
    print("="*60 + "\n")


if __name__ == "__main__":
    main()