# クライアントクレデンシャルフロー - Case 1 - OAuth2.0

## 概要

OAuth2.0 の **クライアントクレデンシャルフロー（grant_type=client_credentials）** を
Keycloak で実験します。

クライアント ID とクライアントシークレットのみでトークンを取得します。
ユーザーが存在しないマシン間通信（M2M）に使用します。

OIDCとの違いは以下の通りです。

| 項目 | OAuth2.0（このフォルダ） | OIDC |
|---|---|---|
| scope | なし | `openid` |
| id_token | 返されない | 返されない（仕様外） |
| JWT検証 | なし（STEP 4 なし） | あり（アクセストークン検証） |

## ファイル構成

```
OAuth/
├── docker-compose.yml                                    # Keycloak コンテナ定義
├── requirements.txt                                      # 依存パッケージ
├── case1_grant_type_client_credentials_setup.py          # Keycloak 初期設定
├── case1_grant_type_client_credentials_client.py         # クライアント
└── README.md                                             # 本ファイル
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
python case1_grant_type_client_credentials_setup.py
```

実行後にクライアントシークレットが表示されます:

```
  次のステップ:
    python case1_grant_type_client_credentials_client.py --secret xxxxxxxx-xxxx-...
```

以下が作成されます:

| 項目 | 値 |
|---|---|
| レルム | sample |
| クライアントID | oauth2-client-credentials |
| クライアント種別 | confidential（シークレットあり） |
| テストユーザー | なし（不要） |

### 4. 実験を実行する

**引数でシークレットを渡す形式（推奨）:**

```bash
python case1_grant_type_client_credentials_client.py --secret <setup.py で表示されたシークレット>
```

**対話形式:**

```bash
python case1_grant_type_client_credentials_client.py
```

## 後片付け

```bash
deactivate
docker compose down
rm -rf .env
```