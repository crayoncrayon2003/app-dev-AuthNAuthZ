#!/usr/bin/env python3
"""
case1_grant_type_password_client.py - OAuth2.0 パスワードフロー クライアント
Case 1 - OAuth2.0
ケース: grant_type=password

【OAuth2.0 と OIDC の違い】
  scope に openid を含めない → id_token が返されない
  STEP 4〜6 はありません（JWT検証・UserInfo・sub一致確認は OIDC のみ）

【シーケンス】
  STEP 1. ユーザー名・パスワードを取得（引数 or 標準入力）
  STEP 2. トークンエンドポイントへ POST（1回で完結）
  STEP 3. トークン受信・表示（access_token · refresh_token のみ）
  STEP 4〜6. OIDC のみ（JWT検証・UserInfo・sub一致確認）
  STEP 7. リフレッシュトークンでアクセストークンを再取得（オプション）

【注意】
  RFC 9700 により非推奨。学習目的の実験としてのみ使用してください。

【実行方法】
  python case1_grant_type_password_client.py
  python case1_grant_type_password_client.py --username testuser --password password

【依存】
  requests
"""

import argparse
import getpass
import json
import sys

import requests

KEYCLOAK_BASE  = "http://localhost:8080"
REALM          = "sample"
CLIENT_ID      = "oauth2-password"
SCOPE          = "profile email"          # openid を含めない → id_token が返されない

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
    print(f"    → scope に openid を含めないため id_token は返されない")
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
    id_token      = token_resp.get("id_token")
    refresh_token = token_resp.get("refresh_token", "")
    print(f"\n  ── アクセストークン (Access Token) ──────────────────")
    print(f"  {access_token[:80]}...")
    print(f"\n  ── ID トークン (ID Token) ───────────────────────────")
    if id_token:
        print(f"  {id_token[:80]}...")
    else:
        print(f"  （なし）")
        print(f"  ※ scope に openid を含めていないため id_token は返されません")
    print(f"\n  ── リフレッシュトークン (Refresh Token) ─────────────")
    print(f"  {refresh_token[:80]}...")
    print(f"\n  ── トークン情報 ──────────────────────────────────────")
    print_param("  expires_in", str(token_resp.get("expires_in", "-")) + " 秒")
    print_param("  token_type", token_resp.get("token_type", "-"))


# ============================================================
# STEP 4〜6: OIDC のみ（JWT検証・UserInfo・sub一致確認）
# OAuth2.0 ではこれらの STEP はありません
# ============================================================


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
    parser = argparse.ArgumentParser(description="OAuth2.0 パスワードフロー クライアント")
    parser.add_argument("--username", "-u", help="ユーザー名")
    parser.add_argument("--password", "-p", help="パスワード")
    parser.add_argument("--skip-refresh", action="store_true",
                        help="リフレッシュトークンによる再取得をスキップする")
    args = parser.parse_args()

    print("\n" + "="*60)
    print(" OAuth2.0 パスワードフロー クライアント")
    print(" Case 1 - grant_type=password（OAuth2.0）")
    print("="*60)
    print("\n  ⚠️  このフローは非推奨です（RFC 9700）")
    print("      学習目的の実験としてのみ使用してください。")

    # STEP 1
    username, password = get_credentials(args)

    # STEP 2
    token_resp = request_token(username, password)

    # STEP 3
    show_tokens(token_resp)

    refresh_token = token_resp.get("refresh_token", "")

    # STEP 4〜6: OIDC のみ

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