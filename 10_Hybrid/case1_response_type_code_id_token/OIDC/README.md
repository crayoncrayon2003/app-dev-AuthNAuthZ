# 08 - ハイブリッドフロー - Case 1 - OIDC

## 概要

OIDC の **ハイブリッドフロー（response_type=code id_token）** を Keycloak で実験します。
認可レスポンスのフラグメントに code と id_token が返され、
さらにトークンエンドポイントで access_token・id_token・refresh_token を取得します。

認可コードフローとの違いは以下の通りです。

| 項目 | 認可コードフロー | ハイブリッドフロー（このフォルダ） |
|---|---|---|
| response_type | `code` | `code id_token` |
| フラグメント | なし | code + id_token |
| c_hash 検証 | なし | あり（OIDC 仕様必須） |
| トークンエンドポイント | あり | あり |

## ファイル構成

```
OIDC/
├── docker-compose.yml                              # Keycloak コンテナ定義
├── requirements.txt                                # 依存パッケージ
├── case1_response_type_code_id_token_setup.py      # Keycloak 初期設定
├── case1_response_type_code_id_token_client.py     # ハイブリッドフロー クライアント
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
python case1_response_type_code_id_token_setup.py
```

以下が作成されます:

| 項目 | 値 |
|---|---|
| レルム | sample |
| クライアントID | oidc-hybrid-code-id-token |
| テストユーザー | testuser / password |
| リダイレクトURI | http://localhost:8888/callback |

### 4. 実験を実行する

```bash
python case1_response_type_code_id_token_client.py
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