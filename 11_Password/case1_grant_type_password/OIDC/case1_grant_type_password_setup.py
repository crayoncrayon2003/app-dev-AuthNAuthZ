#!/usr/bin/env python3
"""
case1_grant_type_password_setup.py - Keycloak 初期設定スクリプト

ケース: grant_type=password（OIDC パスワードフロー）

【OAuth2.0 と OIDC の違い】
  scope に openid を含める → id_token が返される
  STEP 4〜6 があります（JWT検証・UserInfo・sub一致確認は OIDC のみ）

【処理内容】
  1. Keycloak 起動確認
  2. 管理者トークンの取得
  3. レルム (sample) の作成
  4. クライアント (oidc-password) の作成
  5. テストユーザーの作成

【実行方法】
  python case1_grant_type_password_setup.py
"""

import sys
import time

import requests

KEYCLOAK_BASE  = "http://localhost:8080"
ADMIN_USER     = "admin"
ADMIN_PASSWORD = "admin"

REALM_NAME     = "sample"
CLIENT_ID      = "oidc-password"

TEST_USERNAME  = "testuser"
TEST_PASSWORD  = "password"
TEST_EMAIL     = "testuser@example.com"
TEST_FIRSTNAME = "テスト"
TEST_LASTNAME  = "ユーザー"


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
        "displayName":         "OIDC サンプルレルム",
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
        return
    resp = api_post(f"{KEYCLOAK_BASE}/admin/realms/{REALM_NAME}/clients", token, {
        "clientId":                  CLIENT_ID,
        "name":                      "OIDC パスワードフロー サンプル",
        "enabled":                   True,
        "protocol":                  "openid-connect",
        "publicClient":              True,
        "directAccessGrantsEnabled": True,
        "standardFlowEnabled":       False,
        "implicitFlowEnabled":       False,
        "serviceAccountsEnabled":    False,
    })
    if resp.status_code not in (200, 201):
        print(f"  [ERROR] HTTP {resp.status_code}: {resp.text[:300]}")
        sys.exit(1)
    print_ok(f"クライアント '{CLIENT_ID}' を作成しました")
    print(f"       publicClient          : True  (シークレット不要)")
    print(f"       directAccessGrants    : True  (パスワードフロー)")
    print(f"       standardFlow          : False")
    print(f"       implicitFlow          : False")


def create_user(token):
    print_step(4, f"テストユーザーの作成: {TEST_USERNAME}")
    resp = api_get(
        f"{KEYCLOAK_BASE}/admin/realms/{REALM_NAME}/users?username={TEST_USERNAME}", token)
    if resp.status_code == 200 and resp.json():
        print_skip(TEST_USERNAME)
        return
    resp = api_post(f"{KEYCLOAK_BASE}/admin/realms/{REALM_NAME}/users", token, {
        "username":      TEST_USERNAME,
        "email":         TEST_EMAIL,
        "firstName":     TEST_FIRSTNAME,
        "lastName":      TEST_LASTNAME,
        "enabled":       True,
        "emailVerified": True,
        "credentials":   [{"type": "password", "value": TEST_PASSWORD, "temporary": False}],
    })
    if resp.status_code not in (200, 201):
        print(f"  [ERROR] HTTP {resp.status_code}: {resp.text[:300]}")
        sys.exit(1)
    print_ok(f"ユーザー '{TEST_USERNAME}' を作成しました")
    print(f"       email    : {TEST_EMAIL}")
    print(f"       password : {TEST_PASSWORD}")


if __name__ == "__main__":
    wait_for_keycloak()
    token = get_admin_token()
    create_realm(token)
    create_client(token)
    create_user(token)
    print(f"\n{'='*55}\n 設定完了\n{'='*55}")
    print(f"  Keycloak 管理画面 : {KEYCLOAK_BASE}/admin")
    print(f"  レルム            : {REALM_NAME}")
    print(f"  クライアント      : {CLIENT_ID}")
    print(f"  テストユーザー    : {TEST_USERNAME} / {TEST_PASSWORD}")
    print(f"\n  次のステップ:")
    print(f"    python case1_grant_type_password_client.py\n")