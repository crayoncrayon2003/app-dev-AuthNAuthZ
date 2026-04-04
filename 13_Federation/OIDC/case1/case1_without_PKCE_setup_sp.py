"""
case1_without_PKCE_setup_sp.py - Keycloak SP 初期設定スクリプト

役割: SP（Service Provider）= クライアントが接続する Keycloak。認証を IdP に委譲する

【処理内容】
  1. Keycloak-SP 起動確認（ポート 8080）
  2. 管理者トークンの取得
  3. レルム (sp-realm) の作成
  4. IdP プロバイダーの登録
     ※ SP が「この IdP に認証を委譲する」という設定
     ※ discoveryEndpoint にはコンテナ間通信用 URL を指定する
  5. クライアント (oidc-federation) の作成

【コンテナ間通信について】
  ホストOS（Python）からの接続  : http://localhost:8081
  コンテナ内（Keycloak-SP）からの接続: http://keycloak-idp:8080
  discoveryEndpoint にはコンテナ内から到達できる URL を設定する必要がある

【実行順序】
  1. python case1_without_PKCE_setup_idm_idp.py
  2. python case1_without_PKCE_setup_sp.py        ← このスクリプト
  3. python case1_without_PKCE_client.py

【実行方法】
  python case1_without_PKCE_setup_sp.py
"""

import sys
import time

import requests

SP_BASE            = "http://localhost:8080"
IDP_BASE_HOST      = "http://localhost:8081"       # ホストOSからIdPへ接続するURL
IDP_BASE_CONTAINER = "http://keycloak-idp:8080"    # コンテナ内からIdPへ接続するURL

ADMIN_USER     = "admin"
ADMIN_PASSWORD = "admin"

SP_REALM         = "sp-realm"
IDP_REALM        = "idp-realm"
SP_CLIENT_ID     = "sp-client"
SP_CLIENT_SECRET = "sp-client-secret"
IDP_ALIAS        = "idp-oidc"
CLIENT_ID        = "oidc-federation"
REDIRECT_URI     = "http://localhost:8888/callback"


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
    print_step(0, "Keycloak-SP 起動確認（ポート 8080）")
    print("  Phase 1: Keycloak-SP プロセス起動待ち...")
    for i in range(30):
        try:
            if requests.get(f"{SP_BASE}/realms/master", timeout=3).status_code == 200:
                print_ok("Keycloak-SP プロセス起動確認")
                break
        except Exception:
            pass
        print(f"  待機中... ({i+1}/30)")
        time.sleep(5)
    else:
        print("  [ERROR] Keycloak-SP が起動しませんでした。")
        sys.exit(1)

    print("  Phase 2: Admin API 起動待ち...")
    for i in range(12):
        try:
            resp = requests.post(
                f"{SP_BASE}/realms/master/protocol/openid-connect/token",
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
        f"{SP_BASE}/realms/master/protocol/openid-connect/token",
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
    print_step(2, f"SP レルムの作成: {SP_REALM}")
    if api_get(f"{SP_BASE}/admin/realms/{SP_REALM}", token).status_code == 200:
        print_skip(SP_REALM)
        return
    resp = api_post(f"{SP_BASE}/admin/realms", token, {
        "realm":               SP_REALM,
        "enabled":             True,
        "displayName":         "SP レルム（Service Provider）",
        "sslRequired":         "none",
        "accessTokenLifespan": 300,
    })
    if resp.status_code not in (200, 201):
        print(f"  [ERROR] HTTP {resp.status_code}: {resp.text[:300]}")
        sys.exit(1)
    if api_get(f"{SP_BASE}/admin/realms/{SP_REALM}", token).status_code != 200:
        print("  [ERROR] レルム作成後の確認に失敗")
        sys.exit(1)
    print_ok(f"レルム '{SP_REALM}' を作成しました")


def register_idp_provider(token):
    """
    SP に IdP プロバイダーを登録する。
    discoveryEndpoint による自動取得が機能しない場合があるため、
    各エンドポイント URL を明示的に設定する。
    """
    print_step(3, f"IdP プロバイダーの登録: {IDP_ALIAS}")

    resp = api_get(
        f"{SP_BASE}/admin/realms/{SP_REALM}/identity-provider/instances/{IDP_ALIAS}", token)
    if resp.status_code == 200:
        print_skip(IDP_ALIAS)
        return

    # ホストOSからDiscovery URLの到達確認
    idp_discovery_url_host = (
        f"{IDP_BASE_HOST}/realms/{IDP_REALM}/.well-known/openid-configuration"
    )
    print(f"  IdP Discovery URL（到達確認用）: {idp_discovery_url_host}")
    resp = requests.get(idp_discovery_url_host, timeout=5)
    if resp.status_code != 200:
        print("  [ERROR] IdP Discovery URL に到達できません。setup_idm_idp.py を先に実行してください。")
        sys.exit(1)
    print_ok("IdP Discovery URL 到達確認")

    # Discovery URL からエンドポイント情報を取得する
    discovery = resp.json()

    # authorizationUrl はブラウザがアクセスするURL → localhost:8081 のまま使う
    authorization_url = discovery["authorization_endpoint"]

    # tokenUrl・jwksUrl・userInfoUrl は SP コンテナ内からアクセスするURL
    # localhost:8081 → keycloak-idp:8080 に置換してコンテナ間通信に対応する
    def to_container_url(url):
        return url.replace("localhost:8081", "keycloak-idp:8080")

    token_url    = to_container_url(discovery["token_endpoint"])
    jwks_url     = to_container_url(discovery["jwks_uri"])
    userinfo_url = to_container_url(discovery["userinfo_endpoint"])
    logout_url   = to_container_url(discovery.get("end_session_endpoint", ""))
    # issuer はトークンの iss クレームと照合するため localhost:8081 のまま使う
    issuer       = discovery["issuer"]

    print(f"  authorizationUrl : {authorization_url}")
    print(f"  tokenUrl         : {token_url}")
    print(f"  jwksUrl          : {jwks_url}")

    resp = api_post(
        f"{SP_BASE}/admin/realms/{SP_REALM}/identity-provider/instances", token, {
            "providerId":                "oidc",
            "alias":                     IDP_ALIAS,
            "displayName":               "Keycloak IdP（OIDC フェデレーション）",
            "enabled":                   True,
            "firstBrokerLoginFlowAlias": "first broker login",
            "config": {
                "authorizationUrl": authorization_url,
                "tokenUrl":         token_url,
                "jwksUrl":          jwks_url,
                "userInfoUrl":      userinfo_url,
                "logoutUrl":        logout_url,
                "issuer":           issuer,
                "clientId":         SP_CLIENT_ID,
                "clientSecret":     SP_CLIENT_SECRET,
                "syncMode":         "IMPORT",
                "validateSignature": "true",
                "useJwksUrl":       "true",
            },
        }
    )
    if resp.status_code not in (200, 201):
        print(f"  [ERROR] HTTP {resp.status_code}: {resp.text[:300]}")
        sys.exit(1)
    print_ok(f"IdP プロバイダー '{IDP_ALIAS}' を登録しました")
    print(f"       authorizationUrl : {authorization_url}")
    print(f"       clientId         : {SP_CLIENT_ID}")


def create_client(token):
    print_step(4, f"クライアントの作成: {CLIENT_ID}")
    resp = api_get(
        f"{SP_BASE}/admin/realms/{SP_REALM}/clients?clientId={CLIENT_ID}", token)
    if resp.status_code == 200 and resp.json():
        print_skip(CLIENT_ID)
        return
    resp = api_post(f"{SP_BASE}/admin/realms/{SP_REALM}/clients", token, {
        "clientId":                  CLIENT_ID,
        "name":                      "OIDC フェデレーション サンプル",
        "enabled":                   True,
        "protocol":                  "openid-connect",
        "publicClient":              True,
        "standardFlowEnabled":       True,
        "implicitFlowEnabled":       False,
        "directAccessGrantsEnabled": False,
        "serviceAccountsEnabled":    False,
        "redirectUris":              [REDIRECT_URI],
        "webOrigins":                ["http://localhost:8888"],
    })
    if resp.status_code not in (200, 201):
        print(f"  [ERROR] HTTP {resp.status_code}: {resp.text[:300]}")
        sys.exit(1)
    print_ok(f"クライアント '{CLIENT_ID}' を作成しました")
    print(f"       publicClient : True  (シークレット不要)")
    print(f"       standardFlow : True  (認可コードフロー)")
    print(f"       redirectUri  : {REDIRECT_URI}")


if __name__ == "__main__":
    wait_for_keycloak()
    token = get_admin_token()
    create_realm(token)
    register_idp_provider(token)
    create_client(token)
    print(f"\n{'='*55}\n SP 設定完了\n{'='*55}")
    print(f"  SP URL         : {SP_BASE}")
    print(f"  SP レルム      : {SP_REALM}")
    print(f"  IdP エイリアス : {IDP_ALIAS}")
    print(f"  クライアント   : {CLIENT_ID}")
    print(f"\n  フェデレーション構成:")
    print(f"    クライアント → SP（{SP_BASE}）→ IdP（{IDP_BASE_HOST}）")
    print(f"\n  次のステップ:")
    print(f"    python case1_without_PKCE_client.py\n")