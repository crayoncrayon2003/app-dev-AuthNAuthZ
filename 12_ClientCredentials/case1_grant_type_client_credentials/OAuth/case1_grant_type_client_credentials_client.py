#!/usr/bin/env python3
"""
case1_grant_type_client_credentials_client.py - OAuth2.0 クライアントクレデンシャルフロー クライアント
ケース: grant_type=client_credentials

【OAuth2.0 と OIDC の違い】
  scope に openid を含めない
  STEP 4 はありません（JWT検証は OIDC のみ）

【シーケンス】
  STEP 1. クライアントシークレットを取得（引数 or 標準入力）
  STEP 2. トークンエンドポイントへ POST（1回で完結）
  STEP 3. トークン受信・表示（access_token のみ）
  STEP 4. OIDC のみ（アクセストークンの JWT 検証）

【実行方法】
  python case1_grant_type_client_credentials_client.py --secret <client_secret>
  python case1_grant_type_client_credentials_client.py

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
CLIENT_ID      = "oauth2-client-credentials"
SCOPE          = ""                           # openid を含めない

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
# STEP 1: クライアントシークレットの取得
# ============================================================

def get_client_secret(args):
    print_step(1, "クライアントシークレットの入力")
    print(f"  client_id: {CLIENT_ID}")
    secret = args.secret
    if not secret:
        secret = getpass.getpass("  client_secret: ")
    else:
        print(f"  client_secret: {'*' * len(secret)}  （引数から取得）")
    return secret


# ============================================================
# STEP 2: トークンエンドポイントへ POST
# ============================================================

def request_token(client_secret):
    print_step(2, "トークンエンドポイントへ POST")
    print(f"  URL: {TOKEN_ENDPOINT}\n")
    body_params = {
        "grant_type":    "client_credentials",
        "client_id":     CLIENT_ID,
        "client_secret": client_secret,
    }
    print("  送信するパラメータ:")
    for k, v in body_params.items():
        print_param(f"    {k}", "*" * len(v) if k == "client_secret" else v)
    print(f"\n  ポイント: grant_type=client_credentials")
    print(f"    → ユーザー情報（username/password）は不要")
    print(f"    → client_id + client_secret のみで認証")
    print(f"    → id_token・refresh_token は返されない")
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
    refresh_token = token_resp.get("refresh_token")

    print(f"\n  ── アクセストークン (Access Token) ──────────────────")
    print(f"  {access_token[:80]}...")
    print(f"\n  ── リフレッシュトークン ─────────────────────────────")
    if refresh_token:
        print(f"  {refresh_token[:80]}...")
    else:
        print(f"  （なし）")
        print(f"  ※ クライアントクレデンシャルフローでは refresh_token は発行されません")
    print(f"\n  ── トークン情報 ──────────────────────────────────────")
    print_param("  expires_in", str(token_resp.get("expires_in", "-")) + " 秒")
    print_param("  token_type", token_resp.get("token_type", "-"))


# ============================================================
# STEP 4: OIDC のみ（アクセストークンの JWT 検証）
# OAuth2.0 ではこの STEP はありません
# ============================================================


# ============================================================
# メイン処理
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description="OAuth2.0 クライアントクレデンシャルフロー クライアント")
    parser.add_argument("--secret", "-s", help="クライアントシークレット")
    args = parser.parse_args()

    print("\n" + "="*60)
    print(" OAuth2.0 クライアントクレデンシャルフロー クライアント")
    print(" Case 1 - grant_type=client_credentials（OAuth2.0）")
    print("="*60)
    print("\n  用途: 機械間通信（M2M）")
    print("        ユーザーが介在しないバックエンドサービス間の認証")

    # STEP 1
    client_secret = get_client_secret(args)

    # STEP 2
    token_resp = request_token(client_secret)

    # STEP 3
    show_tokens(token_resp)

    # STEP 4: OIDC のみ

    print("\n" + "="*60)
    print(" 実験完了")
    print("="*60 + "\n")


if __name__ == "__main__":
    main()