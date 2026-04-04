# パスワードフロー - Case 1 - OIDC

## 概要

OIDC の **パスワードフロー（grant_type=password）** を Keycloak で実験します。
ユーザー名とパスワードをトークンエンドポイントに直接 POST する 1 回のリクエストで完結します。

OAuth2.0版との違いは以下の通りです。

| 項目 | OAuth2.0 | OIDC（このフォルダ） |
|---|---|---|
| scope | `profile email` | `openid profile email` |
| id_token | 返されない | 返される |
| JWT検証 | なし | あり（STEP 4〜6） |
| UserInfo | なし | あり |

## ファイル構成

```
OIDC/
├── docker-compose.yml                    # Keycloak コンテナ定義
├── requirements.txt                      # 依存パッケージ
├── case1_grant_type_password_setup.py    # Keycloak 初期設定
├── case1_grant_type_password_client.py   # パスワードフロー クライアント
└── README.md                             # 本ファイル
```

## 実行手順

### 1. Keycloak を起動する

```bash
docker compose up -d
```

### 2. 仮想環境を作成する

```bash
python -m venv .env
source .env/bin/activate
pip install -r requirements.txt
```

### 3. Keycloak を設定する

```bash
python case1_grant_type_password_setup.py
```

以下が作成されます:

| 項目 | 値 |
|---|---|
| レルム | sample |
| クライアントID | oidc-password |
| テストユーザー | testuser / password |

### 4. 実験を実行する

**対話形式（ユーザー名・パスワードをターミナルで入力）:**

```bash
python case1_grant_type_password_client.py
```

**引数で指定する形式:**

```bash
python case1_grant_type_password_client.py --username testuser --password password
```

## 後片付け

```bash
deactivate
docker compose down
rm -rf .env
```