"""
case1_with_PKCE_setup_idm_idp.py - Keycloak IdM + IdP 初期設定スクリプト

役割: IdM（Identity Management）+ IdP（Identity Provider）の一体型 Keycloak

【IdM と IdP の関係】
  IdM: ユーザーアカウントのライフサイクル管理（作成・変更・削除・権限管理）
  IdP: 実際の認証処理（ログイン画面・パスワード検証・トークン発行）

  多くのエンタープライズ製品（Microsoft Entra ID・Okta 等）は IdM と IdP を
  一体化して提供している。本実験では Keycloak がその一体型の役割を担う。

【処理内容】
  1. Keycloak-IdM/IdP 起動確認（ポート 8081）
  2. 管理者トークンの取得
  3. レルム (idp-realm) の作成
  4. SP 向けクライアント (sp-client) の作成
     ※ SP が IdP に接続するためのクライアント
  5. テストユーザーの作成（IdM としてのユーザー管理）
     ※ 実際のユーザー情報は IdM/IdP 側に存在する

【IDフェデレーションの構成】
  人事システム等（ユーザー情報の源泉）
        │ ユーザー管理（本来は IdM が担う）
        ▼
  Keycloak-IdM/IdP（ポート 8081）← IdM + IdP の一体型
        │ OIDC で認証委譲
        ▼
  Keycloak-SP（ポート 8080）  ← クライアントが接続
        │
        ▼
  クライアント（client.py）

【実行順序】
  1. python case1_with_PKCE_setup_idm_idp.py  ← このスクリプト
  2. python case1_with_PKCE_setup_sp.py
  3. python case1_with_PKCE_client.py

【実行方法】
  python case1_with_PKCE_setup_idm_idp.py
"""

import sys
import time
import requests

# IdP は 8081 ポートで起動する
IDP_BASE       = "http://localhost:8081"
ADMIN_USER     = "admin"
ADMIN_PASSWORD = "admin"

# IdP 側のレルム
IDP_REALM      = "idp-realm"

# SP が IdP に接続するためのクライアント設定
# SP は IdP に対してこのクライアント ID・シークレットで認証する
SP_CLIENT_ID     = "sp-client"
SP_CLIENT_SECRET = "sp-client-secret"
# SP の callback URL（SP 側の Keycloak がコールバックを受け取る）
SP_REDIRECT_URI  = "http://localhost:8080/realms/sp-realm/broker/idp-oidc/endpoint"

# IdP 側に作成するテストユーザー
TEST_USERNAME  = "testuser"
TEST_PASSWORD  = "password"
TEST_EMAIL     = "testuser@example.com"
TEST_FIRSTNAME = "テスト"
TEST_LASTNAME  = "ユーザー"

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
    print_step(0, "Keycloak-IdM/IdP 起動確認（ポート 8081）")
    print("  Phase 1: Keycloak-IdM/IdP プロセス起動待ち...")
    for i in range(30):
        try:
            if requests.get(f"{IDP_BASE}/realms/master", timeout=3).status_code == 200:
                print_ok("Keycloak-IdM/IdP プロセス起動確認"); break
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
        "realm":       IDP_REALM,
        "enabled":     True,
        "displayName": "IdP レルム（Identity Provider）",
        "sslRequired": "none",
        "accessTokenLifespan": 300,
    })
    if resp.status_code not in (200, 201):
        print(f"  [ERROR] HTTP {resp.status_code}: {resp.text[:300]}"); sys.exit(1)
    if api_get(f"{IDP_BASE}/admin/realms/{IDP_REALM}", token).status_code != 200:
        print("  [ERROR] レルム作成後の確認に失敗"); sys.exit(1)
    print_ok(f"レルム '{IDP_REALM}' を作成しました")

def create_sp_client(token):
    """
    SP が IdP に接続するためのクライアントを作成する。
    SP の Keycloak は IdP の Keycloak に対してこのクライアントとして認証する。
    """
    print_step(3, f"SP 向けクライアントの作成: {SP_CLIENT_ID}")
    resp = api_get(
        f"{IDP_BASE}/admin/realms/{IDP_REALM}/clients?clientId={SP_CLIENT_ID}", token)
    if resp.status_code == 200 and resp.json():
        print_skip(SP_CLIENT_ID); return

    resp = api_post(f"{IDP_BASE}/admin/realms/{IDP_REALM}/clients", token, {
        "clientId":                  SP_CLIENT_ID,
        "name":                      "SP クライアント（SP → IdP 接続用）",
        "enabled":                   True,
        "protocol":                  "openid-connect",
        # confidential: SP がシークレットを使って IdP に認証する
        "publicClient":              False,
        "secret":                    SP_CLIENT_SECRET,
        "standardFlowEnabled":       True,
        "implicitFlowEnabled":       False,
        "directAccessGrantsEnabled": False,
        "serviceAccountsEnabled":    False,
        # SP の Keycloak がコールバックを受け取る URL
        "redirectUris":              [SP_REDIRECT_URI],
        "webOrigins":                ["http://localhost:8080"],
    })
    if resp.status_code not in (200, 201):
        print(f"  [ERROR] HTTP {resp.status_code}: {resp.text[:300]}"); sys.exit(1)
    print_ok(f"クライアント '{SP_CLIENT_ID}' を作成しました")
    print(f"       publicClient  : False (confidential)")
    print(f"       secret        : {SP_CLIENT_SECRET}")
    print(f"       redirectUri   : {SP_REDIRECT_URI}")

def create_user(token):
    """
    IdM としてのユーザー管理：テストユーザーを作成する。
    実際の運用では人事システムと連携して IdM がユーザーを自動プロビジョニングする。
    ユーザー情報は IdM/IdP 側に存在し、SP 側には存在しない。
    フェデレーション後に SP 側でユーザーが自動作成される。
    """
    print_step(4, f"テストユーザーの作成: {TEST_USERNAME}（IdM/IdP 側）")
    resp = api_get(
        f"{IDP_BASE}/admin/realms/{IDP_REALM}/users?username={TEST_USERNAME}", token)
    if resp.status_code == 200 and resp.json():
        print_skip(TEST_USERNAME); return

    resp = api_post(f"{IDP_BASE}/admin/realms/{IDP_REALM}/users", token, {
        "username":      TEST_USERNAME,
        "email":         TEST_EMAIL,
        "firstName":     TEST_FIRSTNAME,
        "lastName":      TEST_LASTNAME,
        "enabled":       True,
        "emailVerified": True,
        "credentials":   [{"type":"password","value":TEST_PASSWORD,"temporary":False}],
    })
    if resp.status_code not in (200, 201):
        print(f"  [ERROR] HTTP {resp.status_code}: {resp.text[:300]}"); sys.exit(1)
    print_ok(f"ユーザー '{TEST_USERNAME}' を作成しました（IdM/IdP 側）")
    print(f"       email    : {TEST_EMAIL}")
    print(f"       password : {TEST_PASSWORD}")
    print(f"       ※ このユーザーは IdM/IdP 側にのみ存在します")
    print(f"         フェデレーション後に SP 側でも自動作成されます")

if __name__ == "__main__":
    wait_for_keycloak()
    token = get_admin_token()
    create_realm(token)
    create_sp_client(token)
    create_user(token)
    print(f"\n{'='*55}\n IdM/IdP 設定完了\n{'='*55}")
    print(f"  IdM/IdP URL    : {IDP_BASE}")
    print(f"  IdP レルム     : {IDP_REALM}")
    print(f"  SP クライアント: {SP_CLIENT_ID} / {SP_CLIENT_SECRET}")
    print(f"  テストユーザー : {TEST_USERNAME} / {TEST_PASSWORD}（IdM/IdP 側）")
    print(f"\n  次のステップ:")
    print(f"    python case1_with_PKCE_setup_sp.py\n")