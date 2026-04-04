"""
case1_with_PKCE_client.py - OIDC IDフェデレーション クライアント

【IDフェデレーションとは】
  複数の認証システム（IdP）を連携させ、ユーザーが一方の IdP の
  アカウントで他のサービス（SP）にログインできる仕組み。

【本実験の構成】
  読者のブラウザ
        │
        ▼
  Keycloak-SP（ポート 8080 / sp-realm）
        │ 認証リクエストを受け取り IdP にリダイレクト
        ▼
  Keycloak-IdP（ポート 8081 / idp-realm）
        │ testuser でログイン
        ▼
  Keycloak-SP（ポート 8080）
        │ IdP から受け取ったトークンを SP のトークンに変換
        ▼
  クライアント（このスクリプト）
        │ SP から access_token / id_token を受け取る

【OIDCシーケンス（認可コードフローと同じ）】
  STEP 1.  PKCE · state · nonce を生成
  STEP 2.  SP への認可リクエスト URL を生成
  STEP 3.  コールバックサーバ起動 & 認可URL 表示
  STEP 4.  コールバック受信（SP からの code · state）
  STEP 5.  state 検証（CSRF 対策）
  STEP 6.  SP のトークンエンドポイントへ POST（code → token 交換）
  STEP 7.  トークン受信・表示
  STEP 8.  ID トークン検証（署名 / iss / aud / exp / nonce）
           ※ JWKs は SP の Keycloak から取得する
           ※ iss は SP のレルム URL になる（IdP ではなく SP が発行）
  STEP 9.  UserInfo エンドポイント呼び出し（SP のエンドポイント）
  STEP 10. sub 一致確認（ID トークン vs UserInfo）

【実行方法】
  python case1_with_PKCE_client.py

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

# クライアントは SP（ポート 8080）に接続する
SP_BASE           = "http://localhost:8080"
SP_REALM          = "sp-realm"
CLIENT_ID         = "oidc-federation"
REDIRECT_URI      = "http://localhost:8888/callback"
SCOPE             = "openid profile email"
CALLBACK_PORT     = 8888

AUTH_ENDPOINT      = f"{SP_BASE}/realms/{SP_REALM}/protocol/openid-connect/auth"
TOKEN_ENDPOINT     = f"{SP_BASE}/realms/{SP_REALM}/protocol/openid-connect/token"
# JWKs は SP の Keycloak から取得する（SP が id_token を発行するため）
JWKS_ENDPOINT      = f"{SP_BASE}/realms/{SP_REALM}/protocol/openid-connect/certs"
USERINFO_ENDPOINT  = f"{SP_BASE}/realms/{SP_REALM}/protocol/openid-connect/userinfo"
# iss は SP のレルム URL（IdP ではなく SP が id_token を発行する）
ISSUER             = f"{SP_BASE}/realms/{SP_REALM}"

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
        # kc_idp_hint: SP に「この IdP を使って認証せよ」と指示する
        # 省略するとSP のログイン画面でIdPを選択する画面が表示される
        "kc_idp_hint":           "idp-oidc",
    }
    return AUTH_ENDPOINT + "?" + urllib.parse.urlencode(params)

# ============================================================
# コールバックサーバ
# ============================================================

_callback_result: dict = {}

class CallbackHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != "/callback":
            self.send_response(204); self.end_headers(); return
        params = dict(urllib.parse.parse_qsl(parsed.query))
        print_step(4, "コールバック受信（SP からのリダイレクト）")
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
    print_step(6, "SP のトークンエンドポイントへ POST（認可コード → トークン交換）")
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
    print(f"\n  ── アクセストークン (Access Token) ──────────────────")
    print(f"  {access_token[:80]}...")
    print(f"\n  ── ID トークン (ID Token) ───────────────────────────")
    print(f"  {id_token[:80]}...")
    print(f"\n  ── リフレッシュトークン (Refresh Token) ─────────────")
    print(f"  {refresh_token[:80]}...")
    print(f"\n  ── トークン情報 ──────────────────────────────────────")
    print_param("  expires_in", str(token_resp.get("expires_in", "-")) + " 秒")
    print_param("  token_type", token_resp.get("token_type", "-"))

def verify_id_token(id_token, nonce):
    print_step(8, "ID トークンの検証（OIDC 必須）")
    print("  検証項目: 署名 / iss / aud / exp / nonce\n")
    print("  ⚠️  IDフェデレーション固有の注意点:")
    print(f"      JWKs の取得先 : SP の Keycloak（{JWKS_ENDPOINT}）")
    print(f"      iss の期待値  : SP のレルム URL（{ISSUER}）")
    print(f"      → id_token は SP が発行するため、IdP ではなく SP の情報で検証する\n")

    print("  [8-1] JWKs（公開鍵セット）の取得")
    jwks_client = jwt.PyJWKClient(JWKS_ENDPOINT)
    signing_key = jwks_client.get_signing_key_from_jwt(id_token)
    print_ok("JWKs 取得成功")

    print(f"\n  [8-2] JWT 署名検証 + クレーム検証")
    print(f"        iss（期待値）  : {ISSUER}")
    print(f"        aud（期待値）  : {CLIENT_ID}")
    print(f"        nonce（期待値）: {nonce}")

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
    except jwt.InvalidSignatureError:
        print("  [ERROR] 署名検証失敗"); sys.exit(1)
    except Exception as e:
        print(f"  [ERROR] ID トークン検証失敗: {e}"); sys.exit(1)

    if payload.get("nonce") != nonce:
        print(f"  [ERROR] nonce 検証失敗"); sys.exit(1)

    print_ok("署名検証 OK")
    print_ok(f"iss 検証 OK  : {payload.get('iss')}")
    print_ok(f"aud 検証 OK  : {payload.get('aud')}")
    print_ok(f"exp 検証 OK  : 有効期限内")
    print_ok(f"nonce 検証 OK: {payload.get('nonce')}")
    print(f"\n  ── ID トークン ペイロード（検証済み）────────────────")
    print(pretty_json(payload))

    # フェデレーション固有のクレームを表示
    print(f"\n  ── フェデレーション固有クレーム ─────────────────────")
    print_param("  iss（発行者）",      payload.get("iss", "-"))
    print_param("  sub（SP側ユーザーID）", payload.get("sub", "-"))
    idp_claims = {k: v for k, v in payload.items()
                  if k.startswith("identity_provider") or k == "brokered_identity_id"}
    if idp_claims:
        for k, v in idp_claims.items():
            print_param(f"  {k}", str(v))
    print(f"\n  ポイント: sub は SP 側で採番されたユーザー ID です")
    print(f"            IdP 側の sub とは異なります（SP が新規ユーザーを作成したため）")

    return payload

def call_userinfo(access_token):
    print_step(9, "UserInfo エンドポイントの呼び出し（SP のエンドポイント）")
    print(f"  URL: {USERINFO_ENDPOINT}\n")
    resp = requests.get(USERINFO_ENDPOINT,
                        headers={"Authorization": f"Bearer {access_token}"})
    if resp.status_code != 200:
        print(f"  [ERROR] HTTP {resp.status_code}: {resp.text[:300]}"); sys.exit(1)
    userinfo = resp.json()
    print_ok("UserInfo 取得成功")
    print(f"\n  ── UserInfo レスポンス ───────────────────────────────")
    print(pretty_json(userinfo))
    return userinfo

def main():
    print("\n" + "="*60)
    print(" OIDC IDフェデレーション クライアント")
    print(" Case 1 - OIDC Federation")
    print("="*60)
    print(f"\n  構成: クライアント → SP（8080）→ IdP（8081）")
    print(f"  ユーザーは IdP 側（8081）に存在します")

    print_step(1, "PKCE · state · nonce の生成")
    code_verifier, code_challenge = generate_pkce()
    state = generate_state()
    nonce = generate_nonce()
    print_param("code_verifier",         code_verifier)
    print_param("code_challenge",        code_challenge)
    print_param("code_challenge_method", "S256")
    print_param("state",                 state)
    print_param("nonce",                 nonce)

    print_step(2, "SP への認可リクエスト URL の生成")
    auth_url = build_auth_url(state, code_challenge, nonce)
    parsed = urllib.parse.urlparse(auth_url)
    print(f"  {parsed.scheme}://{parsed.netloc}{parsed.path}")
    for k, v in urllib.parse.parse_qsl(parsed.query):
        print(f"    &{k}={v}")
    print(f"\n  ポイント: kc_idp_hint=idp-oidc")
    print(f"    → SP は認証を IdP（8081）に自動委譲します")
    print(f"    → ブラウザは SP → IdP の順にリダイレクトされます")

    print_step(3, "コールバックサーバ起動 & 認可URL の表示")
    server = start_callback_server()
    print(f"  コールバックサーバ起動: http://localhost:{CALLBACK_PORT}/callback")
    print(f"\n  以下の URL をブラウザでコピー&ペーストして開いてください:")
    print(f"\n  {auth_url}")
    print(f"\n  Keycloak-IdP（8081）のログイン画面が表示されます:")
    print(f"  ユーザー名: testuser  /  パスワード: password")
    print(f"\n  ※ ログイン先は SP（8080）ではなく IdP（8081）です")
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