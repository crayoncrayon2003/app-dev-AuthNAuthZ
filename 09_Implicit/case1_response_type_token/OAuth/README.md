# インプリシットフロー - Case 1 - OAuth2.0

## 概要

OAuth2.0 の **インプリシットフロー（Implicit Flow）** を Keycloak で実験します。
認可コードフローと異なり、access_token がフラグメント（URL の # 以降）で直接返されます。

認可コードフローとの違いは以下の通りです。

| 項目 | 認可コードフロー | インプリシットフロー（このフォルダ） |
|---|---|---|
| response_type | `code` | `token` |
| トークン取得方法 | code → トークンエンドポイントで交換 | フラグメントで直接返される |
| PKCE | あり | なし |
| refresh_token | あり | なし |

## ファイル構成

```
OAuth/
├── docker-compose.yml                    # Keycloak コンテナ定義
├── requirements.txt                      # 依存パッケージ
├── case1_response_type_token_setup.py    # Keycloak 初期設定
├── case1_response_type_token_client.py   # インプリシットフロー クライアント
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
python case1_response_type_token_setup.py
```

以下が作成されます:

| 項目 | 値 |
|---|---|
| レルム | sample |
| クライアントID | oauth2-implicit-token |
| テストユーザー | testuser / password |
| リダイレクトURI | http://localhost:8888/callback |

### 4. 実験を実行する

```bash
python case1_response_type_token_client.py
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