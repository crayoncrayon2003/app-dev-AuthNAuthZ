# ハイブリッドフロー - Case 3 - OIDC

## 概要

OIDC の **ハイブリッドフロー（response_type=code id_token token）** を Keycloak で実験します。
認可レスポンスのフラグメントに code・id_token・access_token の全部が返されます。

他のケースとの違いは以下の通りです。

| 項目 | Case 1 | Case 2 | Case 3（このフォルダ） |
|---|---|---|---|
| response_type | `code id_token` | `code token` | `code id_token token` |
| フラグメント | code + id_token | code + access_token | code + id_token + access_token |
| c_hash 検証 | あり | なし | あり |
| at_hash 検証 | なし | なし | あり |

## ファイル構成

```
OIDC/
├── docker-compose.yml                                    # Keycloak コンテナ定義
├── requirements.txt                                      # 依存パッケージ
├── case3_response_type_code_id_token_token_setup.py      # Keycloak 初期設定
├── case3_response_type_code_id_token_token_client.py     # ハイブリッドフロー クライアント
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
python case3_response_type_code_id_token_token_setup.py
```

以下が作成されます:

| 項目 | 値 |
|---|---|
| レルム | sample |
| クライアントID | oidc-hybrid-code-id-token-token |
| テストユーザー | testuser / password |
| リダイレクトURI | http://localhost:8888/callback |

### 4. 実験を実行する

```bash
python case3_response_type_code_id_token_token_client.py
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