#!/usr/bin/env python3
"""
case2_with_PKCE_setup_idp.py - Keycloak IdP 初期設定スクリプト（OpenLDAP 連携）

役割: IdP（Identity Provider）= OpenLDAP のユーザーを読み込んで認証を行う Keycloak

【処理内容】
  1. Keycloak 起動確認（ポート 8080）
  2. 管理者トークンの取得
  3. レルム (sample) の作成
  4. LDAP ユーザーフェデレーションの設定
     ※ Keycloak が OpenLDAP に接続してユーザーを同期する設定
  5. クライアント (oidc-ldap) の作成
  6. LDAP ユーザーの同期実行

【実行順序】
  1. python case2_with_PKCE_setup_idm_ldap.py
  2. python case2_with_PKCE_setup_idp.py  ← このスクリプト
  3. python case2_with_PKCE_client.py

【実行方法】
  python case2_with_PKCE_setup_idp.py
"""

import sys
import time

import requests

KEYCLOAK_BASE  = "http://localhost:8080"
ADMIN_USER     = "admin"
ADMIN_PASSWORD = "admin"

REALM_NAME     = "sample"
CLIENT_ID      = "oidc-ldap"
REDIRECT_URI   = "http://localhost:8888/callback"

# OpenLDAP の接続情報
LDAP_URL       = "ldap://openldap:389"   # Docker ネットワーク内では コンテナ名で参照
LDAP_BASE_DN   = "dc=example,dc=com"
LDAP_ADMIN_DN  = "cn=admin,dc=example,dc=com"
LDAP_ADMIN_PW  = "admin"
LDAP_USER_DN   = "ou=people,dc=example,dc=com"

def print_step(num, title):
    print(f"\n{'='*55}\n  STEP {num}: {title}\n{'='*55}")

def print_ok(msg):   print(f"  [OK] {msg}")
def print_skip(msg): print(f"  [SKIP] {msg} (既に存在します)")

def api_get(url, token):
    return requests.get(url, headers={"Authorization": f"Bearer {token}"})

def api_post(url, token, payload):
    return requests.post(url, json=payload, headers={"Authorization": f"Bearer {token}"})

def api_put(url, token, payload):
    return requests.put(url, json=payload, headers={"Authorization": f"Bearer {token}"})

def wait_for_keycloak():
    print_step(0, "Keycloak 起動確認（ポート 8080）")
    print("  Phase 1: Keycloak プロセス起動待ち...")
    for i in range(30):
        try:
            if requests.get(f"{KEYCLOAK_BASE}/realms/master", timeout=3).status_code == 200:
                print_ok("Keycloak プロセス起動確認"); break
        except: pass
        print(f"  待機中... ({i+1}/30)"); time.sleep(5)
    else:
        print("  [ERROR] Keycloak が起動しませんでした。"); sys.exit(1)

    print("  Phase 2: Admin API 起動待ち...")
    for i in range(12):
        try:
            resp = requests.post(
                f"{KEYCLOAK_BASE}/realms/master/protocol/openid-connect/token",
                data={"grant_type":"password","client_id":"admin-cli",
                      "username":ADMIN_USER,"password":ADMIN_PASSWORD}, timeout=3)
            if resp.status_code == 200:
                print_ok("Admin API 起動確認"); return
        except: pass
        print(f"  Admin API 待機中... ({i+1}/12)"); time.sleep(5)
    print("  [ERROR] Admin API が応答しませんでした。"); sys.exit(1)

def get_admin_token():
    print_step(1, "管理者トークンの取得")
    resp = requests.post(
        f"{KEYCLOAK_BASE}/realms/master/protocol/openid-connect/token",
        data={"grant_type":"password","client_id":"admin-cli",
              "username":ADMIN_USER,"password":ADMIN_PASSWORD})
    if resp.status_code != 200:
        print(f"  [ERROR] HTTP {resp.status_code}: {resp.text[:300]}"); sys.exit(1)
    token = resp.json()["access_token"]
    print_ok(f"トークン取得成功 ({token[:40]}...)")
    return token

def create_realm(token):
    print_step(2, f"レルムの作成: {REALM_NAME}")
    if api_get(f"{KEYCLOAK_BASE}/admin/realms/{REALM_NAME}", token).status_code == 200:
        print_skip(REALM_NAME); return
    resp = api_post(f"{KEYCLOAK_BASE}/admin/realms", token, {
        "realm":       REALM_NAME,
        "enabled":     True,
        "displayName": "LDAP 連携サンプルレルム",
        "sslRequired": "none",
        "accessTokenLifespan": 300,
    })
    if resp.status_code not in (200, 201):
        print(f"  [ERROR] HTTP {resp.status_code}: {resp.text[:300]}"); sys.exit(1)
    if api_get(f"{KEYCLOAK_BASE}/admin/realms/{REALM_NAME}", token).status_code != 200:
        print("  [ERROR] レルム作成後の確認に失敗"); sys.exit(1)
    print_ok(f"レルム '{REALM_NAME}' を作成しました")

def setup_ldap_federation(token) -> str:
    """
    Keycloak に LDAP ユーザーフェデレーションを設定する。
    これにより Keycloak が OpenLDAP のユーザーを認証に使用できるようになる。

    設定内容:
      - 接続先: OpenLDAP（Docker ネットワーク内のコンテナ名で参照）
      - 同期方式: READ_ONLY（Keycloak は LDAP を読み取るのみ）
      - ユーザー属性マッピング: uid → username, mail → email
    """
    print_step(3, "LDAP ユーザーフェデレーションの設定")

    # 既存確認
    resp = api_get(
        f"{KEYCLOAK_BASE}/admin/realms/{REALM_NAME}/components"
        f"?type=org.keycloak.storage.UserStorageProvider", token)
    if resp.status_code == 200 and resp.json():
        existing = [c for c in resp.json() if c.get("name") == "openldap"]
        if existing:
            print_skip("LDAP フェデレーション (openldap)")
            return existing[0]["id"]

    print(f"  接続先 LDAP URL : {LDAP_URL}")
    print(f"  Base DN         : {LDAP_BASE_DN}")
    print(f"  User DN         : {LDAP_USER_DN}")

    resp = api_post(
        f"{KEYCLOAK_BASE}/admin/realms/{REALM_NAME}/components", token, {
        "name":         "openldap",
        "providerId":   "ldap",
        "providerType": "org.keycloak.storage.UserStorageProvider",
        "config": {
            # 接続設定
            "connectionUrl":          [LDAP_URL],
            "bindDn":                 [LDAP_ADMIN_DN],
            "bindCredential":         [LDAP_ADMIN_PW],
            "usersDn":                [LDAP_USER_DN],

            # LDAP スキーマ設定
            "vendorName":             ["other"],
            "userObjectClasses":      ["inetOrgPerson, organizationalPerson, person"],
            "usernameLDAPAttribute":  ["uid"],      # LDAP の uid を Keycloak の username にマッピング
            "rdnLDAPAttribute":       ["uid"],
            "uuidLDAPAttribute":      ["entryUUID"],
            "searchScope":            ["1"],        # 1=ONE_LEVEL（usersDn 直下のみ）

            # 同期設定
            # READ_ONLY: Keycloak は LDAP を読み取るのみ（書き込みしない）
            "editMode":               ["READ_ONLY"],
            "syncRegistrations":      ["false"],

            # ユーザー同期設定
            "fullSyncPeriod":         ["3600"],     # 1時間ごとに全件同期
            "changedSyncPeriod":      ["300"],      # 5分ごとに差分同期
            "importEnabled":          ["true"],     # Keycloak のローカル DB に同期
        },
    })
    if resp.status_code not in (200, 201):
        print(f"  [ERROR] HTTP {resp.status_code}: {resp.text[:300]}"); sys.exit(1)

    # 201 Created の場合、ID は Location ヘッダから取得する
    # Location: http://localhost:8080/admin/realms/sample/components/{id}
    location = resp.headers.get("Location", "")
    component_id = location.rstrip("/").split("/")[-1] if location else ""

    if not component_id:
        # Location ヘッダがない場合は components API で検索する
        resp2 = api_get(
            f"{KEYCLOAK_BASE}/admin/realms/{REALM_NAME}/components"
            f"?type=org.keycloak.storage.UserStorageProvider", token)
        existing = [c for c in resp2.json() if c.get("name") == "openldap"]
        component_id = existing[0]["id"] if existing else ""

    print_ok("LDAP ユーザーフェデレーションを設定しました")
    print(f"       component_id  : {component_id}")
    print(f"       editMode      : READ_ONLY（LDAP を読み取るのみ）")
    print(f"       importEnabled : True（Keycloak DB に同期）")
    print(f"       usernameLDAP  : uid → username にマッピング")
    return component_id

def create_client(token):
    print_step(4, f"クライアントの作成: {CLIENT_ID}")
    resp = api_get(
        f"{KEYCLOAK_BASE}/admin/realms/{REALM_NAME}/clients?clientId={CLIENT_ID}", token)
    if resp.status_code == 200 and resp.json():
        print_skip(CLIENT_ID); return
    resp = api_post(f"{KEYCLOAK_BASE}/admin/realms/{REALM_NAME}/clients", token, {
        "clientId":                  CLIENT_ID,
        "name":                      "OIDC LDAP 連携 サンプル",
        "enabled":                   True,
        "protocol":                  "openid-connect",
        "publicClient":              True,
        "standardFlowEnabled":       True,
        "implicitFlowEnabled":       False,
        "directAccessGrantsEnabled": False,
        "serviceAccountsEnabled":    False,
        "redirectUris":              [REDIRECT_URI],
        "webOrigins":                ["http://localhost:8888"],
        "attributes": {"pkce.code.challenge.method": "S256"},
    })
    if resp.status_code not in (200, 201):
        print(f"  [ERROR] HTTP {resp.status_code}: {resp.text[:300]}"); sys.exit(1)
    print_ok(f"クライアント '{CLIENT_ID}' を作成しました")
    print(f"       publicClient : True / PKCE : S256")
    print(f"       redirectUri  : {REDIRECT_URI}")

def sync_ldap_users(token, component_id: str):
    """
    LDAP からユーザーを手動で同期する。
    設定後すぐに動作確認できるように全件同期を実行する。
    """
    print_step(5, "LDAP ユーザーの手動同期")
    print("  OpenLDAP → Keycloak へユーザーを同期します...")

    url = (f"{KEYCLOAK_BASE}/admin/realms/{REALM_NAME}"
           f"/user-storage/{component_id}/sync?action=triggerFullSync")
    resp = requests.post(url, headers={"Authorization": f"Bearer {token}"})
    if resp.status_code != 200:
        print(f"  [ERROR] HTTP {resp.status_code}: {resp.text[:300]}"); sys.exit(1)

    result = resp.json()
    print_ok(f"同期完了")
    print(f"       追加: {result.get('added', 0)} 件")
    print(f"       更新: {result.get('updated', 0)} 件")
    print(f"       失敗: {result.get('failed', 0)} 件")

    # 同期後のユーザー確認
    resp = api_get(
        f"{KEYCLOAK_BASE}/admin/realms/{REALM_NAME}/users?username=testuser", token)
    if resp.status_code == 200 and resp.json():
        user = resp.json()[0]
        print(f"\n  同期済みユーザー確認:")
        print(f"       username : {user.get('username')}")
        print(f"       email    : {user.get('email')}")
        print(f"       federationLink: {user.get('federationLink', '（なし）')}")
    else:
        print("  [WARN] testuser が同期されていません。LDAP 設定を確認してください。")

if __name__ == "__main__":
    wait_for_keycloak()
    token = get_admin_token()
    create_realm(token)
    component_id = setup_ldap_federation(token)
    create_client(token)
    sync_ldap_users(token, component_id)
    print(f"\n{'='*55}\n IdP（Keycloak + LDAP 連携）設定完了\n{'='*55}")
    print(f"  Keycloak URL    : {KEYCLOAK_BASE}")
    print(f"  レルム          : {REALM_NAME}")
    print(f"  LDAP 接続先     : {LDAP_URL}")
    print(f"  クライアント    : {CLIENT_ID}")
    print(f"  同期ユーザー    : testuser（OpenLDAP から同期済み）")
    print(f"\n  次のステップ:")
    print(f"    python case2_with_PKCE_client.py\n")