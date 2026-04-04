# インプリシットフロー - Case 3 - OIDC

## 概要

OIDC の **インプリシットフロー（response_type=id_token token）** を Keycloak で実験します。
id_token と access_token の両方がフラグメントで返されます。

Case 2（id_token）との違いは以下の通りです。

| 項目 | Case 2 OIDC | Case 3 OIDC（このフォルダ） |
|---|---|---|
| response_type | `id_token` | `id_token token` |
| 返されるトークン | id_token のみ | id_token + access_token |
| at_hash 検証 | なし | あり（OIDC 仕様必須） |
| UserInfo | 不可 | 可能 |
| sub一致確認 | 省略 | あり |

## ファイル構成

```
OIDC/
├── docker-compose.yml                              # Keycloak コンテナ定義
├── requirements.txt                                # 依存パッケージ
├── case3_response_type_id_token_token_setup.py     # Keycloak 初期設定
├── case3_response_type_id_token_token_client.py    # インプリシットフロー クライアント
└── README.md                                       # 本ファイル
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
python case3_response_type_id_token_token_setup.py
```

以下が作成されます:

| 項目 | 値 |
|---|---|
| レルム | sample |
| クライアントID | oidc-implicit-id-token-token |
| テストユーザー | testuser / password |
| リダイレクトURI | http://localhost:8888/callback |

### 4. 実験を実行する

```bash
python case3_response_type_id_token_token_client.py
```

表示された URL をブラウザに貼り付けてください。

- ユーザー名: `testuser`
- パスワード: `password`

## 後片付け

```bash
deactivate
docker compose down
rm -rf .env
```