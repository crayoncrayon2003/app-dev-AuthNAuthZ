#!/usr/bin/env python3
"""
case1_grant_type_client_credentials_setup.py - Keycloak 初期設定スクリプト

ケース: grant_type=client_credentials

【処理内容】
  1. Keycloak 起動確認
  2. 管理者トークンの取得
  3. レルム (sample) の作成
  4. クライアント (oauth2-client-credentials) の作成
  5. クライアントシークレットの取得・表示

【他フローとの違い】
  ユーザーが存在しない M2M フローのためテストユーザーの作成は不要
  publicClient=False（confidential）→ クライアントシークレットが必要
  serviceAccountsEnabled=True → クライアント専用のサービスアカウントを有効化

【実行方法】
  python case1_grant_type_client_credentials_setup.py
"""

import sys
import time

import requests

KEYCLOAK_BASE  = "http://localhost:8080"
ADMIN_USER     = "admin"
ADMIN_PASSWORD = "admin"

REALM_NAME     = "sample"
CLIENT_ID      = "oauth2-client-credentials"


def print_step(num, title):
    print(f"\n{'='*55}\n  STEP {num}: {title}\n{'='*55}")


def print_ok(msg):
    print(f"  [OK] {msg}")


def print_skip(msg):
    print(f"  [SKIP] {msg} (既に存在します)")


def api_get(url, token):
    return requests.get(url, headers={"Authorization": f"Bearer {token}"})


def api_post(url, token, payload):
    return requests.post(url, json=payload, headers={"Authorization": f"Bearer {token}"})


def wait_for_keycloak():
    print_step(0, "Keycloak 起動確認")
    print("  Phase 1: Keycloak プロセス起動待ち...")
    for i in range(30):
        try:
            if requests.get(f"{KEYCLOAK_BASE}/realms/master", timeout=3).status_code == 200:
                print_ok("Keycloak プロセス起動確認")
                break
        except Exception:
            pass
        print(f"  待機中... ({i+1}/30)")
        time.sleep(5)
    else:
        print("  [ERROR] Keycloak が起動しませんでした。")
        sys.exit(1)

    print("  Phase 2: Admin API 起動待ち...")
    for i in range(12):
        try:
            resp = requests.post(
                f"{KEYCLOAK_BASE}/realms/master/protocol/openid-connect/token",
                data={"grant_type": "password", "client_id": "admin-cli",
                      "username": ADMIN_USER, "password": ADMIN_PASSWORD},
                timeout=3,
            )
            if resp.status_code == 200:
                print_ok("Admin API 起動確認")
                return
        except Exception:
            pass
        print(f"  Admin API 待機中... ({i+1}/12)")
        time.sleep(5)
    print("  [ERROR] Admin API が応答しませんでした。")
    sys.exit(1)


def get_admin_token():
    print_step(1, "管理者トークンの取得")
    resp = requests.post(
        f"{KEYCLOAK_BASE}/realms/master/protocol/openid-connect/token",
        data={"grant_type": "password", "client_id": "admin-cli",
              "username": ADMIN_USER, "password": ADMIN_PASSWORD},
    )
    if resp.status_code != 200:
        print(f"  [ERROR] HTTP {resp.status_code}: {resp.text[:300]}")
        sys.exit(1)
    token = resp.json()["access_token"]
    print_ok(f"トークン取得成功 ({token[:40]}...)")
    return token


def create_realm(token):
    print_step(2, f"レルムの作成: {REALM_NAME}")
    if api_get(f"{KEYCLOAK_BASE}/admin/realms/{REALM_NAME}", token).status_code == 200:
        print_skip(REALM_NAME)
        return
    resp = api_post(f"{KEYCLOAK_BASE}/admin/realms", token, {
        "realm":               REALM_NAME,
        "enabled":             True,
        "displayName":         "OAuth2.0 サンプルレルム",
        "sslRequired":         "none",
        "accessTokenLifespan": 300,
    })
    if resp.status_code not in (200, 201):
        print(f"  [ERROR] HTTP {resp.status_code}: {resp.text[:300]}")
        sys.exit(1)
    if api_get(f"{KEYCLOAK_BASE}/admin/realms/{REALM_NAME}", token).status_code != 200:
        print("  [ERROR] レルム作成後の確認に失敗")
        sys.exit(1)
    print_ok(f"レルム '{REALM_NAME}' を作成しました")


def create_client(token):
    print_step(3, f"クライアントの作成: {CLIENT_ID}")
    resp = api_get(
        f"{KEYCLOAK_BASE}/admin/realms/{REALM_NAME}/clients?clientId={CLIENT_ID}", token)
    if resp.status_code == 200 and resp.json():
        print_skip(CLIENT_ID)
        client_uuid = resp.json()[0]["id"]
        return get_client_secret(token, client_uuid)

    resp = api_post(f"{KEYCLOAK_BASE}/admin/realms/{REALM_NAME}/clients", token, {
        "clientId":                  CLIENT_ID,
        "name":                      "OAuth2.0 クライアントクレデンシャルフロー サンプル",
        "enabled":                   True,
        "protocol":                  "openid-connect",
        "publicClient":              False,
        "serviceAccountsEnabled":    True,
        "standardFlowEnabled":       False,
        "implicitFlowEnabled":       False,
        "directAccessGrantsEnabled": False,
    })
    if resp.status_code not in (200, 201):
        print(f"  [ERROR] HTTP {resp.status_code}: {resp.text[:300]}")
        sys.exit(1)
    print_ok(f"クライアント '{CLIENT_ID}' を作成しました")
    print(f"       publicClient       : False (confidential)")
    print(f"       serviceAccounts    : True  (M2M 用サービスアカウント)")
    print(f"       directAccessGrants : False")

    resp = api_get(
        f"{KEYCLOAK_BASE}/admin/realms/{REALM_NAME}/clients?clientId={CLIENT_ID}", token)
    client_uuid = resp.json()[0]["id"]
    return get_client_secret(token, client_uuid)


def get_client_secret(token, client_uuid):
    print_step(4, "クライアントシークレットの取得")
    url = f"{KEYCLOAK_BASE}/admin/realms/{REALM_NAME}/clients/{client_uuid}/client-secret"
    resp = api_get(url, token)
    if resp.status_code != 200:
        print(f"  [ERROR] HTTP {resp.status_code}: {resp.text[:300]}")
        sys.exit(1)
    secret = resp.json().get("value", "")
    print_ok("クライアントシークレット取得成功")
    print(f"       client_secret : {secret}")
    return secret


if __name__ == "__main__":
    wait_for_keycloak()
    token = get_admin_token()
    create_realm(token)
    client_secret = create_client(token)
    print(f"\n{'='*55}\n 設定完了\n{'='*55}")
    print(f"  Keycloak 管理画面 : {KEYCLOAK_BASE}/admin")
    print(f"  レルム            : {REALM_NAME}")
    print(f"  クライアント      : {CLIENT_ID}")
    print(f"  クライアントシークレット: {client_secret}")
    print(f"\n  ※ テストユーザーは不要です（M2M フローのためユーザーは存在しません）")
    print(f"\n  次のステップ:")
    print(f"    python case1_grant_type_client_credentials_client.py --secret {client_secret}\n")