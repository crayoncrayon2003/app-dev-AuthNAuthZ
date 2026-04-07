# アプリケーション開発入門 - Dockerコンテナで学ぶ認証認可の仕組み編

本リポジトリは、書籍「アプリケーション開発入門 -Dockerコンテナで学ぶ認証認可の仕組み編-」のサンプルコードです。

## 📖 書籍情報

| | |
|---|---|
| **書名** | アプリケーション開発入門 -Dockerコンテナで学ぶ認証認可の仕組み編- |
| **著者** | 松原潤弥 |
| **販売** | Amazon Kindle |

🛒 **[Amazonで購入する](https://www.amazon.co.jp/dp/B0GHP54LH8)**

## 📝 書籍概要

本書は、アプリケーション開発に必要な認証・認可の知識を、**Dockerコンテナを使った実験**を通じて学ぶ入門書です。

理論だけでなく、実際にOAuth 2.0やOpenID Connectのフローを動かして、認証・認可の仕組みを体験できる構成になっています。

### 対象読者

- アプリケーション開発の経験がない方
- 認証・認可に関する知識がない方、または学習したが挫折してしまった方
- 将来、自作したアプリケーションをクラウドや組み込み機器で動作させたいと考えている方

### 学習内容

| 章 | 内容 |
|---|---|
| 4章 | JWT(JSON Web Token)の仕組みと実装 |
| 5章 | ベーシック認証の仕組みと実装 |
| 6章 | Keycloakのセットアップ |
| 8章 | オーソリゼーションコードフロー(OAuth 2.0 / OIDC) |
| 9章 | インプリシットフロー(OAuth 2.0 / OIDC) |
| 10章 | ハイブリッドフロー(OIDC) |
| 11章 | パスワードフロー(OAuth 2.0 / OIDC) |
| 12章 | クライアントクレデンシャルズフロー(OAuth 2.0) |
| 13章 | IDフェデレーション(OIDC) |

## 🛠 動作環境

| ツール | バージョン |
|---|---|
| OS | Windows 11 Home |
| WSL2 | Ubuntu 24.04.4 LTS |
| Docker | 29.3.0 |
| Docker Compose | 5.1.0 |

## 📂 リポジトリ構成

```
.
├── 04_JWT/                         # 4章:JWTの生成・エンコード・デコード・検証
├── 05_BasicAuthentication/         # 5章:ベーシック認証のクライアント・サーバー実装
├── 06_Keycloak/                    # 6章:Keycloakのセットアップ
├── 08_AuthorizationCode/           # 8章:オーソリゼーションコードフロー(OAuth / OIDC)
├── 09_Implicit/                    # 9章:インプリシットフロー(OAuth / OIDC)
├── 10_Hybrid/                      # 10章:ハイブリッドフロー(OIDC)
├── 11_Password/                    # 11章:パスワードフロー(OAuth / OIDC)
├── 12_ClientCredentials/           # 12章:クライアントクレデンシャルズフロー(OAuth)
└── 13_Federation/                  # 13章:IDフェデレーション(OIDC)
```

### 各章のフロー対応表

| 章 | フロー | OAuth | OIDC |
|---|---|---|---|
| 8章 | 認可コード (`response_type=code`) | ✅ | ✅ |
| 9章 | インプリシット Case1 (`response_type=token`) | ✅ | - |
| 9章 | インプリシット Case2 (`response_type=id_token`) | - | ✅ |
| 9章 | インプリシット Case3 (`response_type=id_token token`) | - | ✅ |
| 10章 | ハイブリッド Case1 (`response_type=code id_token`) | - | ✅ |
| 10章 | ハイブリッド Case2 (`response_type=code token`) | - | ✅ |
| 10章 | ハイブリッド Case3 (`response_type=code id_token token`) | - | ✅ |
| 11章 | パスワード (`grant_type=password`) | ✅ | ✅ |
| 12章 | クライアントクレデンシャルズ (`grant_type=client_credentials`) | ✅ | - |
| 13章 | IDフェデレーション Case1・Case2・Case3 | - | ✅ |

## 🚀 使い方

### コンテナの起動

各章・各フローのフォルダに移動して、以下のコマンドを実行します。

```bash
docker compose up -d
```

### コンテナの停止

```bash
docker compose down
```

### サンプルコードの実行

各フォルダに `setup.py`（Keycloakの初期設定）と `client.py`（フローの実行）が用意されています。

```bash
# 依存パッケージのインストール
pip install -r requirements.txt

# Keycloakの初期設定
python xxxxx_setup.py

# フローの実行
python xxxxx_client.py
```

詳細な手順は各フォルダ内の `README.md` を参照してください。

## 🔗 関連書籍

本書の実験環境(WSL2、Docker、VS Code)の構築方法は、以下の書籍で説明しています。

🛒 **[アプリケーション開発入門 - 開発環境構築編](https://www.amazon.co.jp/dp/B0GQY5ZY41)**

本書の前提となるネットワークの知識は、以下の書籍で学べます。

🛒 **[アプリケーション開発入門 - Dockerコンテナで学ぶネットワークの仕組み編](https://www.amazon.co.jp/dp/B0GSSYJYXK)**

## 📄 ライセンス

本リポジトリのサンプルコードは、書籍の補助教材として提供しています。

## 📘 留意点
本リポジトリのシーケンス図およびサンプルコードは、各フローの基本的な流れを示しています。

このため各フローのクライアントによる次の２つの情報のチェックは、本編を参照してください。

* 各トークンエンドポイントから取得できる情報
  * トークンエンドポイント
  * トークンイントロスペクションエンドポイントのレスポンス内容
* トークンに含まれるクレームの検証方法
  * IDトークンの検証手順
  * フロー別の検証要否
  * UserInfo照合の方法