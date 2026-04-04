#!/usr/bin/env python3
"""
case1_grant_type_password_client.py - OIDC パスワードフロー クライアント

ケース: grant_type=password

【OAuth2.0 と OIDC の違い】
  scope に openid を含める → id_token が返される
  STEP 4〜6 があります（JWT検証・UserInfo・sub一致確認は OIDC のみ）

【シーケンス】
  STEP 1. ユーザー名・パスワードを取得（引数 or 標準入力）
  STEP 2. トークンエンドポイントへ POST（1回で完結）
  STEP 3. トークン受信・表示（access_token · id_token · refresh_token）
  STEP 4. ID トークンの検証（OIDC のみ）
  STEP 5. UserInfo エンドポイント呼び出し（OIDC のみ）
  STEP 6. sub 一致確認（OIDC のみ）
  STEP 7. リフレッシュトークンでアクセストークンを再取得（オプション）

【注意】
  RFC 9700 により非推奨。学習目的の実験としてのみ使用してください。

【実行方法】
  python case1_grant_type_password_client.py
  python case1_grant_type_password_client.py --username testuser --password password

【依存】
  requests, PyJWT[crypto]
"""

import argparse
import getpass
import json
import sys

import jwt
import requests

KEYCLOAK_BASE     = "http://localhost:8080"
REALM             = "sample"
CLIENT_ID         = "oidc-password"
SCOPE             = "openid profile email"  # openid を含める → id_token が返される

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
# STEP 1: 認証情報の取得
# ============================================================

def get_credentials(args):
    print_step(1, "ユーザー認証情報の入力")
    username = args.username
    password = args.password
    if not username:
        username = input("  ユーザー名: ").strip()
    else:
        print(f"  ユーザー名: {username}  （引数から取得）")
    if not password:
        password = getpass.getpass("  パスワード: ")
    else:
        print(f"  パスワード: {'*' * len(password)}  （引数から取得）")
    return username, password


# ============================================================
# STEP 2: トークンエンドポイントへ POST
# ============================================================

def request_token(username, password):
    print_step(2, "トークンエンドポイントへ POST")
    print(f"  URL: {TOKEN_ENDPOINT}\n")
    body_params = {
        "grant_type": "password",
        "client_id":  CLIENT_ID,
        "username":   username,
        "password":   password,
        "scope":      SCOPE,
    }
    print("  送信するパラメータ:")
    for k, v in body_params.items():
        print_param(f"    {k}", "*" * len(v) if k == "password" else v)
    print(f"\n  ポイント: grant_type=password")
    print(f"    → ブラウザへのリダイレクトなし")
    print(f"    → トークンエンドポイントへの POST 1回で完結")
    print(f"    → 認可リクエストが存在しないため nonce は使用しない")
    resp = requests.post(TOKEN_ENDPOINT, data=body_params)
    if resp.status_code != 200:
        print(f"\n  [ERROR] HTTP {resp.status_code}: {resp.text[:300]}")
        sys.exit(1)
    return resp.json()


# ============================================================
# STEP 3: トークン受信・表示
# ============================================================

def show_tokens(token_resp):
    print_step(3, "トークン受信")
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
# STEP 4: ID トークンの検証（OIDC のみ）
# ============================================================

def verify_id_token(id_token):
    print_step(4, "ID トークンの検証（OIDC のみ）")
    print("  検証項目: 署名 / iss / aud / exp")
    print("  ※ パスワードフローでは認可リクエストが存在しないため nonce 検証は不要\n")
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
    print_ok("署名検証 OK")
    print_ok(f"iss 検証 OK  : {payload.get('iss')}")
    print_ok(f"aud 検証 OK  : {payload.get('aud')}")
    print_ok(f"exp 検証 OK  : 有効期限内")
    print(f"\n  ── ID トークン ペイロード（検証済み）────────────────")
    print(pretty_json(payload))
    return payload


# ============================================================
# STEP 5: UserInfo エンドポイント呼び出し（OIDC のみ）
# ============================================================

def call_userinfo(access_token):
    print_step(5, "UserInfo エンドポイントの呼び出し（OIDC のみ）")
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
# STEP 6: sub 一致確認（OIDC のみ）
# ============================================================

def verify_sub(id_token_payload, userinfo):
    print_step(6, "sub クレームの一致確認（OIDC のみ）")
    sub_id = id_token_payload.get("sub")
    sub_ui = userinfo.get("sub")
    print_param("ID トークンの sub", sub_id)
    print_param("UserInfo の sub",   sub_ui)
    if sub_id != sub_ui:
        print("\n  [ERROR] sub が一致しません！")
        sys.exit(1)
    print_ok("sub 一致確認 OK（同一ユーザー）")


# ============================================================
# STEP 7: リフレッシュトークンによる再取得（オプション）
# ============================================================

def refresh_access_token(refresh_token):
    print_step(7, "リフレッシュトークンでアクセストークンを再取得")
    print(f"  URL: {TOKEN_ENDPOINT}\n")
    body_params = {
        "grant_type":    "refresh_token",
        "client_id":     CLIENT_ID,
        "refresh_token": refresh_token,
    }
    for k, v in body_params.items():
        print_param(f"  {k}", v[:60] + "..." if len(v) > 60 else v)
    resp = requests.post(TOKEN_ENDPOINT, data=body_params)
    if resp.status_code != 200:
        print(f"\n  [ERROR] HTTP {resp.status_code}: {resp.text[:300]}")
        sys.exit(1)
    new_access_token = resp.json().get("access_token", "")
    print(f"\n  ── 新しいアクセストークン ────────────────────────────")
    print(f"  {new_access_token[:80]}...")
    print_ok("アクセストークンの更新完了（ユーザーの再ログインなし）")


# ============================================================
# メイン処理
# ============================================================

def main():
    parser = argparse.ArgumentParser(description="OIDC パスワードフロー クライアント")
    parser.add_argument("--username", "-u", help="ユーザー名")
    parser.add_argument("--password", "-p", help="パスワード")
    parser.add_argument("--skip-refresh", action="store_true",
                        help="リフレッシュトークンによる再取得をスキップする")
    args = parser.parse_args()

    print("\n" + "="*60)
    print(" OIDC パスワードフロー クライアント")
    print(" Case 1 - grant_type=password（OIDC）")
    print("="*60)
    print("\n  ⚠️  このフローは非推奨です（RFC 9700）")
    print("      学習目的の実験としてのみ使用してください。")

    # STEP 1
    username, password = get_credentials(args)

    # STEP 2
    token_resp = request_token(username, password)

    # STEP 3
    show_tokens(token_resp)

    access_token  = token_resp.get("access_token", "")
    id_token      = token_resp.get("id_token", "")
    refresh_token = token_resp.get("refresh_token", "")

    # STEP 4〜6: OIDC のみ
    id_token_payload = verify_id_token(id_token)
    userinfo         = call_userinfo(access_token)
    verify_sub(id_token_payload, userinfo)

    # STEP 7（オプション）
    if not args.skip_refresh and refresh_token:
        print("\n" + "-"*60)
        answer = input("\n  リフレッシュトークンでアクセストークンを再取得しますか？ [y/N]: ").strip().lower()
        if answer == "y":
            refresh_access_token(refresh_token)

    print("\n" + "="*60)
    print(" 実験完了")
    print("="*60 + "\n")


if __name__ == "__main__":
    main()