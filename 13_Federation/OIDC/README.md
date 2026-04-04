# 14 - IDフェデレーション（OIDC）

## 概要

OIDC を使った **IDフェデレーション（Identity Federation）** を3つの構成で実験します。
ケースを段階的に積み上げることで、IdM・IdP・SP それぞれの役割と連携を理解できます。

---

## IdM・IdP・SP の役割

| 用語 | 正式名称 | 役割 | 本実験での実装 |
|---|---|---|---|
| **IdM** | Identity Management | ユーザーアカウントのライフサイクル管理 | Keycloak（Case1）/ OpenLDAP（Case2・3） |
| **IdP** | Identity Provider | 実際の認証処理（ログイン・トークン発行） | Keycloak |
| **SP** | Service Provider | サービスを提供する側。IdP の認証結果を信頼して使う | Keycloak |

---

## 3ケースの比較

| | Case1 | Case2 | Case3 |
|---|---|---|---|
| **構成** | Keycloak-IdP ↔ Keycloak-SP | OpenLDAP + Keycloak | OpenLDAP + Keycloak-IdP + Keycloak-SP |
| **IdM** | Keycloak-IdP（一体型） | OpenLDAP（分離） | OpenLDAP（分離） |
| **IdP** | Keycloak-IdP | Keycloak | Keycloak-IdP |
| **SP** | Keycloak-SP | なし | Keycloak-SP |
| **コンテナ数** | 2台 | 2台 | 3台 |
| **学べること** | フェデレーション基礎 | IdM/IdP の分離 | IdM+IdP+SP の完成形 |

---

## フォルダ構成

```
14_Federation/
├── README.md
├── requirements.txt            # 全ケース共通（requests, PyJWT[crypto]）
│
├── case1/                      # Case1: Keycloak-IdP + Keycloak-SP
│   ├── docker-compose.yml
│   ├── setup_idm_idp.py        # Keycloak-IdP（IdM+IdP一体型）の設定
│   ├── setup_sp.py             # Keycloak-SP の設定
│   └── client.py               # 動作確認クライアント
│
├── case2/                      # Case2: OpenLDAP + Keycloak
│   ├── docker-compose.yml
│   ├── setup_idm_ldap.py       # OpenLDAP（IdM）の設定
│   ├── setup_idp.py            # Keycloak（IdP）の設定
│   └── client.py               # 動作確認クライアント
│
└── case3/                      # Case3: OpenLDAP + Keycloak-IdP + Keycloak-SP
    ├── docker-compose.yml
    ├── setup_idm_ldap.py       # OpenLDAP（IdM）の設定
    ├── setup_idp.py            # Keycloak-IdP の設定
    ├── setup_sp.py             # Keycloak-SP の設定
    └── client.py               # 動作確認クライアント
```

---

## 仮想環境のセットアップ（全ケース共通）

```bash
cd 14_Federation
python -m venv .env
source .env/bin/activate
pip install -r requirements.txt
```

---

## Case1: Keycloak-IdP + Keycloak-SP（フェデレーション基礎）

### 構成図

```
クライアント
      │ OIDC（認可コードフロー）
      ▼
Keycloak-SP（ポート 8080 / sp-realm）    ← SP
      │ OIDC フェデレーション（認証委譲）
      ▼
Keycloak-IdP（ポート 8081 / idp-realm）  ← IdM + IdP（一体型）
      │
      ▼
testuser（IdP 側のユーザー）
```

**ポイント:**
- Keycloak-IdP が IdM（ユーザー管理）と IdP（認証処理）を兼ねる
- クライアントは SP（8080）に接続し、SP が IdP（8081）に認証を委譲する
- id_token の `iss` は SP のレルム URL（IdP ではなく SP が発行）

### 実行手順

```bash
cd case1
docker compose up -d
python setup_idm_idp.py   # Keycloak-IdP にユーザー・クライアントを設定
python setup_sp.py        # Keycloak-SP に IdP フェデレーションを設定
python client.py
```

ログイン画面: **Keycloak-IdP（8081）**
- ユーザー名: `testuser` / パスワード: `password`

### 後片付け

```bash
docker compose down
```

---

## Case2: OpenLDAP（IdM）+ Keycloak（IdP）

### 構成図

```
クライアント
      │ OIDC（認可コードフロー）
      ▼
Keycloak（ポート 8080 / sample）  ← IdP
      │ LDAP フェデレーション（ユーザー同期）
      ▼
OpenLDAP（ポート 389）            ← IdM
      │
      ▼
testuser（OpenLDAP のユーザー）
```

**ポイント:**
- OpenLDAP が IdM として独立し、Keycloak とユーザー情報を同期する
- クライアントから見ると OpenLDAP の存在は透過的
- 企業の Active Directory 連携と同じ構造

### 実行手順

```bash
cd case2
sudo apt install -y ldap-utils
docker compose up -d
python setup_idm_ldap.py  # OpenLDAP にユーザーを登録
python setup_idp.py       # Keycloak に LDAP 連携を設定
python client.py
```

ログイン画面: **Keycloak（8080）**
- ユーザー名: `testuser` / パスワード: `password`（OpenLDAP に登録したパスワード）

> ※ `ldapsearch` / `ldapadd` コマンドが必要です
> ```bash
> sudo apt install ldap-utils
> ```

### 後片付け

```bash
docker compose down
```

---

## Case3: OpenLDAP（IdM）+ Keycloak-IdP + Keycloak-SP（完成形）

### 構成図

```
クライアント
      │ OIDC（認可コードフロー）
      ▼
Keycloak-SP（ポート 8080 / sp-realm）    ← SP
      │ OIDC フェデレーション（認証委譲）
      ▼
Keycloak-IdP（ポート 8081 / idp-realm）  ← IdP
      │ LDAP フェデレーション（ユーザー同期）
      ▼
OpenLDAP（ポート 389）                   ← IdM
      │
      ▼
testuser（OpenLDAP のユーザー）
```

**ポイント:**
- IdM・IdP・SP の3者が完全に分離した完成形
- クライアントは SP（8080）にのみ接続する
- ユーザー情報の流れ: OpenLDAP → Keycloak-IdP → Keycloak-SP → クライアント
- id_token の `iss` は SP のレルム URL

### 実行手順

```bash
cd case3
docker compose up -d
python setup_idm_ldap.py  # OpenLDAP にユーザーを登録
python setup_idp.py       # Keycloak-IdP に LDAP 連携・SP向けクライアントを設定
python setup_sp.py        # Keycloak-SP に IdP フェデレーションを設定
python client.py
```

ログイン画面: **Keycloak-IdP（8081）**
- ユーザー名: `testuser` / パスワード: `password`（OpenLDAP に登録したパスワード）

> ※ `ldapsearch` / `ldapadd` コマンドが必要です
> ```bash
> sudo apt install ldap-utils
> ```

### 後片付け

```bash
docker compose down
```
