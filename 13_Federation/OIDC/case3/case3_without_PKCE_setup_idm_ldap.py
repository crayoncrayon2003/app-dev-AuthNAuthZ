#!/usr/bin/env python3
"""
case3_without_PKCE_setup_idm_ldap.py - OpenLDAP 初期設定スクリプト（IdM）

役割: IdM（Identity Management）= OpenLDAP でユーザー情報を管理する

【Case3 の全体構成】
  OpenLDAP（IdM / ポート 389）  ← ユーザー情報を管理
        │ LDAP フェデレーション（ユーザー同期）
        ▼
  Keycloak-IdP（ポート 8081）   ← OpenLDAP のユーザーで認証処理
        │ OIDC フェデレーション（認証委譲）
        ▼
  Keycloak-SP（ポート 8080）    ← クライアントが接続する service
        │ OIDC（認可コードフロー）
        ▼
  クライアント（client.py）

【処理内容】
  1. OpenLDAP 起動確認（ポート 389）
  2. OU（組織単位）の作成: ou=people
  3. テストユーザーの作成: uid=testuser

【実行順序】
  1. python case3_without_PKCE_setup_idm_ldap.py  ← このスクリプト
  2. python case3_without_PKCE_setup_idp.py
  3. python case3_without_PKCE_setup_sp.py
  4. python case3_without_PKCE_client.py

【実行方法】
  python case3_without_PKCE_setup_idm_ldap.py
"""

import subprocess
import sys
import time

LDAP_HOST     = "localhost"
LDAP_PORT     = 389
LDAP_BASE_DN  = "dc=example,dc=com"
LDAP_ADMIN_DN = f"cn=admin,{LDAP_BASE_DN}"
LDAP_ADMIN_PW = "admin"
OU_PEOPLE     = f"ou=people,{LDAP_BASE_DN}"

TEST_USERNAME  = "testuser"
TEST_PASSWORD  = "password"
TEST_EMAIL     = "testuser@example.com"
TEST_FIRSTNAME = "テスト"
TEST_LASTNAME  = "ユーザー"
TEST_DN        = f"uid={TEST_USERNAME},{OU_PEOPLE}"

def print_step(num, title):
    print(f"\n{'='*55}\n  STEP {num}: {title}\n{'='*55}")

def print_ok(msg):   print(f"  [OK] {msg}")
def print_skip(msg): print(f"  [SKIP] {msg} (既に存在します)")

def ldap_add(ldif: str):
    result = subprocess.run([
        "ldapadd", "-x",
        "-H", f"ldap://{LDAP_HOST}:{LDAP_PORT}",
        "-D", LDAP_ADMIN_DN,
        "-w", LDAP_ADMIN_PW,
    ], input=ldif, capture_output=True, text=True)
    if result.returncode == 0:
        return True
    if "Already exists" in result.stderr:
        return None
    print(f"  [ERROR] ldapadd 失敗: {result.stderr[:300]}")
    sys.exit(1)

def wait_for_ldap():
    print_step(0, "OpenLDAP 起動確認（ポート 389）")
    print("  ldapsearch で接続確認中...")
    for i in range(24):
        result = subprocess.run([
            "ldapsearch", "-x",
            "-H", f"ldap://{LDAP_HOST}:{LDAP_PORT}",
            "-D", LDAP_ADMIN_DN,
            "-w", LDAP_ADMIN_PW,
            "-b", LDAP_BASE_DN, "(objectClass=*)",
        ], capture_output=True, text=True)
        if result.returncode == 0:
            print_ok("OpenLDAP 起動確認"); return
        print(f"  待機中... ({i+1}/24)"); time.sleep(5)
    print("  [ERROR] OpenLDAP が起動しませんでした。")
    print("          docker compose -f docker-compose.yml up -d を確認してください。")
    sys.exit(1)

def create_ou_people():
    print_step(1, f"OU の作成: ou=people")
    result = subprocess.run([
        "ldapsearch", "-x",
        "-H", f"ldap://{LDAP_HOST}:{LDAP_PORT}",
        "-D", LDAP_ADMIN_DN, "-w", LDAP_ADMIN_PW,
        "-b", OU_PEOPLE, "(objectClass=organizationalUnit)",
    ], capture_output=True, text=True)
    if result.returncode == 0 and "dn:" in result.stdout:
        print_skip(OU_PEOPLE); return
    ret = ldap_add(f"dn: {OU_PEOPLE}\nobjectClass: organizationalUnit\nou: people\n")
    if ret is None:
        print_skip(OU_PEOPLE)
    else:
        print_ok(f"OU '{OU_PEOPLE}' を作成しました")

def create_user():
    print_step(2, f"テストユーザーの作成: {TEST_USERNAME}")
    result = subprocess.run([
        "ldapsearch", "-x",
        "-H", f"ldap://{LDAP_HOST}:{LDAP_PORT}",
        "-D", LDAP_ADMIN_DN, "-w", LDAP_ADMIN_PW,
        "-b", OU_PEOPLE, f"(uid={TEST_USERNAME})",
    ], capture_output=True, text=True)
    if result.returncode == 0 and "dn:" in result.stdout:
        print_skip(TEST_DN); return
    ldif = f"""\
dn: {TEST_DN}
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
uid: {TEST_USERNAME}
cn: {TEST_FIRSTNAME} {TEST_LASTNAME}
sn: {TEST_LASTNAME}
givenName: {TEST_FIRSTNAME}
mail: {TEST_EMAIL}
userPassword: {TEST_PASSWORD}
"""
    ret = ldap_add(ldif)
    if ret is None:
        print_skip(TEST_DN)
    else:
        print_ok(f"ユーザー '{TEST_USERNAME}' を作成しました（IdM 側）")
        print(f"       DN      : {TEST_DN}")
        print(f"       email   : {TEST_EMAIL}")
        print(f"       password: {TEST_PASSWORD}")
        print(f"       ※ OpenLDAP（IdM）にのみ存在します")
        print(f"         Keycloak-IdP への同期は setup_idp.py で実行します")

if __name__ == "__main__":
    wait_for_ldap()
    create_ou_people()
    create_user()
    print(f"\n{'='*55}\n IdM（OpenLDAP）設定完了\n{'='*55}")
    print(f"  LDAP URL       : ldap://{LDAP_HOST}:{LDAP_PORT}")
    print(f"  Base DN        : {LDAP_BASE_DN}")
    print(f"  OU             : {OU_PEOPLE}")
    print(f"  テストユーザー : {TEST_USERNAME} / {TEST_PASSWORD}（OpenLDAP 側）")
    print(f"\n  次のステップ:")
    print(f"    python case3_without_PKCE_setup_idp.py\n")