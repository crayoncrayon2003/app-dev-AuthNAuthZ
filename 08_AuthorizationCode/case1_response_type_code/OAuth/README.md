# 認可コードフロー - Case 1 - OAuth2.0

## 概要

OAuth2.0 の **認可コードフロー（Authorization Code Flow）** を Keycloak で実験します。
PKCE（RFC 7636）を組み合わせ、パブリッククライアントでも安全に利用できる構成です。

OIDCとの違いは以下の通りです。

| 項目 | OAuth2.0（このフォルダ） | OIDC |
|---|---|---|
| scope | `profile email` | `openid profile email` |
| nonce | なし | あり（リプレイ攻撃対策） |
| id_token | 返されない | 返される |
| JWT検証 | なし | あり（署名・iss・aud・exp・nonce） |
| UserInfo | なし | あり |
| sub一致確認 | なし | あり |

---

## ファイル構成

```
OAuth/
├── docker-compose.yml                    # Keycloak コンテナ定義
├── requirements.txt                      # 依存パッケージ
├── case1_response_type_code_setup.py     # Keycloak 初期設定
├── case1_response_type_code_client.py    # 認可コードフロー クライアント
└── README.md                             # 本ファイル
```

---

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
python case1_response_type_code_setup.py
```

以下が作成されます:

| 項目 | 値 |
|---|---|
| レルム | sample |
| クライアントID | oauth2-auth-code |
| テストユーザー | testuser / password |
| リダイレクトURI | http://localhost:8888/callback |

### 4. 実験を実行する

```bash
python case1_response_type_code_client.py
```

表示された URL をブラウザに貼り付けてください。

- ユーザー名: `testuser`
- パスワード: `password`

---

## 後片付け

```bash
deactivate
docker compose down
rm -rf .env
```