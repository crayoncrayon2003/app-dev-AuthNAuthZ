#!/usr/bin/env python3
"""
case3_without_PKCE_setup_idp.py - Keycloak-IdP 初期設定スクリプト（LDAP連携 + SP向けクライアント）

役割: IdP = OpenLDAP のユーザーで認証し、SP に認証を提供する Keycloak

【処理内容】
  1. Keycloak-IdP 起動確認（ポート 8081）
  2. 管理者トークンの取得
  3. レルム (idp-realm) の作成
  4. LDAP ユーザーフェデレーションの設定（OpenLDAP → Keycloak-IdP 同期）
  5. SP 向けクライアント (sp-client) の作成
  6. LDAP ユーザーの手動同期

【実行順序】
  1. python case3_without_PKCE_setup_idm_ldap.py
  2. python case3_without_PKCE_setup_idp.py  ← このスクリプト
  3. python case3_without_PKCE_setup_sp.py
  4. python case3_without_PKCE_client.py

【実行方法】
  python case3_without_PKCE_setup_idp.py
"""

import sys
import time

import requests

IDP_BASE       = "http://localhost:8081"
ADMIN_USER     = "admin"
ADMIN_PASSWORD = "admin"

IDP_REALM      = "idp-realm"

# SP が IdP に接続するためのクライアント
SP_CLIENT_ID     = "sp-client"
SP_CLIENT_SECRET = "sp-client-secret"
SP_REDIRECT_URI  = "http://localhost:8080/realms/sp-realm/broker/idp-oidc/endpoint"

# OpenLDAP 接続情報（Docker ネットワーク内ではコンテナ名で参照）
LDAP_URL      = "ldap://openldap:389"
LDAP_BASE_DN  = "dc=example,dc=com"
LDAP_ADMIN_DN = "cn=admin,dc=example,dc=com"
LDAP_ADMIN_PW = "admin"
LDAP_USER_DN  = "ou=people,dc=example,dc=com"

def print_step(num, title):
    print(f"\n{'='*55}\n  STEP {num}: {title}\n{'='*55}")

def print_ok(msg):   print(f"  [OK] {msg}")
def print_skip(msg): print(f"  [SKIP] {msg} (既に存在します)")

def api_get(url, token):
    return requests.get(url, headers={"Authorization": f"Bearer {token}"})

def api_post(url, token, payload):
    return requests.post(url, json=payload, headers={"Authorization": f"Bearer {token}"})

def wait_for_keycloak():
    print_step(0, "Keycloak-IdP 起動確認（ポート 8081）")
    print("  Phase 1: プロセス起動待ち...")
    for i in range(30):
        try:
            if requests.get(f"{IDP_BASE}/realms/master", timeout=3).status_code == 200:
                print_ok("Keycloak-IdP プロセス起動確認"); break
        except: pass
        print(f"  待機中... ({i+1}/30)"); time.sleep(5)
    else:
        print("  [ERROR] Keycloak-IdP が起動しませんでした。"); sys.exit(1)

    print("  Phase 2: Admin API 起動待ち...")
    for i in range(12):
        try:
            resp = requests.post(
                f"{IDP_BASE}/realms/master/protocol/openid-connect/token",
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
        f"{IDP_BASE}/realms/master/protocol/openid-connect/token",
        data={"grant_type":"password","client_id":"admin-cli",
              "username":ADMIN_USER,"password":ADMIN_PASSWORD})
    if resp.status_code != 200:
        print(f"  [ERROR] HTTP {resp.status_code}: {resp.text[:300]}"); sys.exit(1)
    token = resp.json()["access_token"]
    print_ok(f"トークン取得成功 ({token[:40]}...)")
    return token

def create_realm(token):
    print_step(2, f"IdP レルムの作成: {IDP_REALM}")
    if api_get(f"{IDP_BASE}/admin/realms/{IDP_REALM}", token).status_code == 200:
        print_skip(IDP_REALM); return
    resp = api_post(f"{IDP_BASE}/admin/realms", token, {
        "realm": IDP_REALM, "enabled": True,
        "displayName": "IdP レルム（OpenLDAP 連携）",
        "sslRequired": "none", "accessTokenLifespan": 300,
    })
    if resp.status_code not in (200, 201):
        print(f"  [ERROR] HTTP {resp.status_code}: {resp.text[:300]}"); sys.exit(1)
    if api_get(f"{IDP_BASE}/admin/realms/{IDP_REALM}", token).status_code != 200:
        print("  [ERROR] レルム作成後の確認に失敗"); sys.exit(1)
    print_ok(f"レルム '{IDP_REALM}' を作成しました")

def setup_ldap_federation(token) -> str:
    """OpenLDAP → Keycloak-IdP のユーザー同期を設定する"""
    print_step(3, "LDAP ユーザーフェデレーションの設定（OpenLDAP → Keycloak-IdP）")

    resp = api_get(
        f"{IDP_BASE}/admin/realms/{IDP_REALM}/components"
        f"?type=org.keycloak.storage.UserStorageProvider", token)
    if resp.status_code == 200 and resp.json():
        existing = [c for c in resp.json() if c.get("name") == "openldap"]
        if existing:
            print_skip("LDAP フェデレーション (openldap)")
            return existing[0]["id"]

    print(f"  LDAP URL : {LDAP_URL}")
    print(f"  User DN  : {LDAP_USER_DN}")

    resp = api_post(f"{IDP_BASE}/admin/realms/{IDP_REALM}/components", token, {
        "name":         "openldap",
        "providerId":   "ldap",
        "providerType": "org.keycloak.storage.UserStorageProvider",
        "config": {
            "connectionUrl":         [LDAP_URL],
            "bindDn":                [LDAP_ADMIN_DN],
            "bindCredential":        [LDAP_ADMIN_PW],
            "usersDn":               [LDAP_USER_DN],
            "vendorName":            ["other"],
            "userObjectClasses":     ["inetOrgPerson, organizationalPerson, person"],
            "usernameLDAPAttribute": ["uid"],
            "rdnLDAPAttribute":      ["uid"],
            "uuidLDAPAttribute":     ["entryUUID"],
            "searchScope":           ["1"],
            "editMode":              ["READ_ONLY"],
            "syncRegistrations":     ["false"],
            "fullSyncPeriod":        ["3600"],
            "changedSyncPeriod":     ["300"],
            "importEnabled":         ["true"],
        },
    })
    if resp.status_code not in (200, 201):
        print(f"  [ERROR] HTTP {resp.status_code}: {resp.text[:300]}"); sys.exit(1)

    location = resp.headers.get("Location", "")
    component_id = location.rstrip("/").split("/")[-1] if location else ""

    if not component_id:
        resp2 = api_get(
            f"{IDP_BASE}/admin/realms/{IDP_REALM}/components"
            f"?type=org.keycloak.storage.UserStorageProvider", token)
        existing = [c for c in resp2.json() if c.get("name") == "openldap"]
        component_id = existing[0]["id"] if existing else ""

    print_ok("LDAP ユーザーフェデレーションを設定しました")
    print(f"       component_id : {component_id}")
    print(f"       editMode : READ_ONLY（OpenLDAP を読み取るのみ）")
    return component_id

def create_sp_client(token):
    """SP が IdP に接続するためのクライアントを作成する"""
    print_step(4, f"SP 向けクライアントの作成: {SP_CLIENT_ID}")
    resp = api_get(
        f"{IDP_BASE}/admin/realms/{IDP_REALM}/clients?clientId={SP_CLIENT_ID}", token)
    if resp.status_code == 200 and resp.json():
        print_skip(SP_CLIENT_ID); return
    resp = api_post(f"{IDP_BASE}/admin/realms/{IDP_REALM}/clients", token, {
        "clientId":                  SP_CLIENT_ID,
        "name":                      "SP クライアント（SP → IdP 接続用）",
        "enabled":                   True,
        "protocol":                  "openid-connect",
        "publicClient":              False,
        "secret":                    SP_CLIENT_SECRET,
        "standardFlowEnabled":       True,
        "implicitFlowEnabled":       False,
        "directAccessGrantsEnabled": False,
        "serviceAccountsEnabled":    False,
        "redirectUris":              [SP_REDIRECT_URI],
        "webOrigins":                ["http://localhost:8080"],
    })
    if resp.status_code not in (200, 201):
        print(f"  [ERROR] HTTP {resp.status_code}: {resp.text[:300]}"); sys.exit(1)
    print_ok(f"クライアント '{SP_CLIENT_ID}' を作成しました")
    print(f"       secret      : {SP_CLIENT_SECRET}")
    print(f"       redirectUri : {SP_REDIRECT_URI}")

def sync_ldap_users(token, component_id: str):
    print_step(5, "LDAP ユーザーの手動同期（OpenLDAP → Keycloak-IdP）")
    url = (f"{IDP_BASE}/admin/realms/{IDP_REALM}"
           f"/user-storage/{component_id}/sync?action=triggerFullSync")
    resp = requests.post(url, headers={"Authorization": f"Bearer {token}"})
    if resp.status_code != 200:
        print(f"  [ERROR] HTTP {resp.status_code}: {resp.text[:300]}"); sys.exit(1)
    result = resp.json()
    print_ok(f"同期完了（追加: {result.get('added',0)} 件 / 更新: {result.get('updated',0)} 件）")

    resp = api_get(
        f"{IDP_BASE}/admin/realms/{IDP_REALM}/users?username=testuser", token)
    if resp.status_code == 200 and resp.json():
        user = resp.json()[0]
        print(f"  同期済みユーザー: {user.get('username')} / {user.get('email')}")
    else:
        print("  [WARN] testuser が同期されていません。LDAP 設定を確認してください。")

if __name__ == "__main__":
    wait_for_keycloak()
    token = get_admin_token()
    create_realm(token)
    component_id = setup_ldap_federation(token)
    create_sp_client(token)
    sync_ldap_users(token, component_id)
    print(f"\n{'='*55}\n IdP（Keycloak + LDAP 連携）設定完了\n{'='*55}")
    print(f"  IdP URL        : {IDP_BASE}")
    print(f"  IdP レルム     : {IDP_REALM}")
    print(f"  LDAP 接続先    : {LDAP_URL}")
    print(f"  SP クライアント: {SP_CLIENT_ID} / {SP_CLIENT_SECRET}")
    print(f"\n  次のステップ:")
    print(f"    python case3_without_PKCE_setup_sp.py\n")