# 08 - ハイブリッドフロー - Case 2 - OIDC

## 概要

OIDC の **ハイブリッドフロー（response_type=code token）** を Keycloak で実験します。
認可レスポンスのフラグメントに code と access_token が返されます。

Case 1（code id_token）との違いは以下の通りです。

| 項目 | Case 1 OIDC | Case 2 OIDC（このフォルダ） |
|---|---|---|
| response_type | `code id_token` | `code token` |
| フラグメント | code + id_token | code + access_token |
| c_hash 検証 | あり（必須） | なし（id_token がないため） |
| id_token の取得元 | フラグメント + トークンエンドポイント | トークンエンドポイントのみ |

## ファイル構成

```
OIDC/
├── docker-compose.yml                        # Keycloak コンテナ定義
├── requirements.txt                          # 依存パッケージ
├── case2_response_type_code_token_setup.py   # Keycloak 初期設定
├── case2_response_type_code_token_client.py  # ハイブリッドフロー クライアント
└── README.md                                 # 本ファイル
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
python case2_response_type_code_token_setup.py
```

以下が作成されます:

| 項目 | 値 |
|---|---|
| レルム | sample |
| クライアントID | oidc-hybrid-code-token |
| テストユーザー | testuser / password |
| リダイレクトURI | http://localhost:8888/callback |

### 4. 実験を実行する

```bash
python case2_response_type_code_token_client.py
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