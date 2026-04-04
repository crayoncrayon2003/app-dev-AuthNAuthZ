#!/usr/bin/env python3
"""
case2_without_PKCE_setup_idm_ldap.py - OpenLDAP 初期設定スクリプト（IdM）

役割: IdM（Identity Management）= OpenLDAP でユーザー情報を管理する

【IdM としての OpenLDAP の役割】
  OpenLDAP はユーザーアカウントのライフサイクルを管理するディレクトリサービス。
  企業では Active Directory（AD）が同じ役割を担うことが多い。
  Keycloak（IdP）は OpenLDAP に接続してユーザー情報を取得・同期する。

【ディレクトリ構造】
  dc=example,dc=com              ← ルート
  └── ou=people,dc=example,dc=com ← ユーザーを格納する OU（組織単位）
      └── uid=testuser,...         ← テストユーザー

【処理内容】
  1. OpenLDAP 起動確認（ポート 389）
  2. OU（組織単位）の作成: ou=people
  3. テストユーザーの作成: uid=testuser

【実行前提】
  docker compose up -d を実行していること

【実行順序】
  1. python case2_without_PKCE_setup_idm_ldap.py  ← このスクリプト
  2. python case2_without_PKCE_setup_idp.py
  3. python case2_without_PKCE_client.py

【実行方法】
  python case2_without_PKCE_setup_idm_ldap.py

【依存】
  requests（ldap3 は使わず ldapsearch/ldapadd コマンドを subprocess で呼ぶ）
  ※ ldap3 ライブラリを避けることで requirements.txt を増やさない
"""

import subprocess
import sys
import time

import requests

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

def ldap_search(base_dn, filter_str) -> bool:
    """ldapsearch コマンドで DN の存在確認を行う"""
    result = subprocess.run([
        "ldapsearch", "-x",
        "-H", f"ldap://{LDAP_HOST}:{LDAP_PORT}",
        "-D", LDAP_ADMIN_DN,
        "-w", LDAP_ADMIN_PW,
        "-b", base_dn,
        filter_str,
    ], capture_output=True, text=True)
    return "numEntries: 1" in result.stdout or "numEntries: 2" in result.stdout

def ldap_add(ldif: str) -> bool:
    """ldapadd コマンドでエントリを追加する"""
    result = subprocess.run([
        "ldapadd", "-x",
        "-H", f"ldap://{LDAP_HOST}:{LDAP_PORT}",
        "-D", LDAP_ADMIN_DN,
        "-w", LDAP_ADMIN_PW,
    ], input=ldif, capture_output=True, text=True)
    if result.returncode == 0:
        return True
    if "Already exists" in result.stderr:
        return None  # 既存
    print(f"  [ERROR] ldapadd 失敗: {result.stderr[:300]}")
    sys.exit(1)

def wait_for_ldap():
    """OpenLDAP の起動を待機する"""
    print_step(0, "OpenLDAP 起動確認（ポート 389）")
    print("  ldapsearch で接続確認中...")
    for i in range(24):
        result = subprocess.run([
            "ldapsearch", "-x",
            "-H", f"ldap://{LDAP_HOST}:{LDAP_PORT}",
            "-D", LDAP_ADMIN_DN,
            "-w", LDAP_ADMIN_PW,
            "-b", LDAP_BASE_DN,
            "(objectClass=*)",
        ], capture_output=True, text=True)
        if result.returncode == 0:
            print_ok("OpenLDAP 起動確認")
            return
        print(f"  待機中... ({i+1}/24)")
        time.sleep(5)
    print("  [ERROR] OpenLDAP が起動しませんでした。")
    print("          docker compose up -d を確認してください。")
    sys.exit(1)

def create_ou_people():
    """ユーザーを格納する OU（組織単位）を作成する"""
    print_step(1, f"OU の作成: ou=people")

    # 既存確認
    result = subprocess.run([
        "ldapsearch", "-x",
        "-H", f"ldap://{LDAP_HOST}:{LDAP_PORT}",
        "-D", LDAP_ADMIN_DN,
        "-w", LDAP_ADMIN_PW,
        "-b", OU_PEOPLE,
        "(objectClass=organizationalUnit)",
    ], capture_output=True, text=True)
    if result.returncode == 0 and "dn:" in result.stdout:
        print_skip(OU_PEOPLE)
        return

    ldif = f"""\
dn: {OU_PEOPLE}
objectClass: organizationalUnit
ou: people
description: ユーザーアカウントを格納する OU
"""
    ret = ldap_add(ldif)
    if ret is None:
        print_skip(OU_PEOPLE)
    else:
        print_ok(f"OU '{OU_PEOPLE}' を作成しました")

def create_user():
    """テストユーザーを OpenLDAP に追加する"""
    print_step(2, f"テストユーザーの作成: {TEST_USERNAME}")

    # 既存確認
    result = subprocess.run([
        "ldapsearch", "-x",
        "-H", f"ldap://{LDAP_HOST}:{LDAP_PORT}",
        "-D", LDAP_ADMIN_DN,
        "-w", LDAP_ADMIN_PW,
        "-b", OU_PEOPLE,
        f"(uid={TEST_USERNAME})",
    ], capture_output=True, text=True)
    if result.returncode == 0 and "dn:" in result.stdout:
        print_skip(TEST_DN)
        return

    # inetOrgPerson スキーマでユーザーを作成する
    # inetOrgPerson は LDAP の標準的なユーザースキーマ
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
        print_ok(f"ユーザー '{TEST_USERNAME}' を作成しました")
        print(f"       DN       : {TEST_DN}")
        print(f"       email    : {TEST_EMAIL}")
        print(f"       password : {TEST_PASSWORD}")
        print(f"       ※ このユーザーは OpenLDAP（IdM）側にのみ存在します")
        print(f"         Keycloak へのログイン後、Keycloak 側にも自動同期されます")

if __name__ == "__main__":
    wait_for_ldap()
    create_ou_people()
    create_user()
    print(f"\n{'='*55}\n IdM（OpenLDAP）設定完了\n{'='*55}")
    print(f"  LDAP URL       : ldap://{LDAP_HOST}:{LDAP_PORT}")
    print(f"  Base DN        : {LDAP_BASE_DN}")
    print(f"  Admin DN       : {LDAP_ADMIN_DN}")
    print(f"  OU             : {OU_PEOPLE}")
    print(f"  テストユーザー : {TEST_USERNAME} / {TEST_PASSWORD}（OpenLDAP側）")
    print(f"\n  次のステップ:")
    print(f"    python case2_without_PKCE_setup_idp.py\n")