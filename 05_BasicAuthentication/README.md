# 1. 仮想環境を作成する

次のコマンドで、仮想環境を作ります。

```bash
$ python -m venv .env
```

# 2. 仮想環境を有効化する

次のコマンドで、仮想環境を有効化します。

必要なモジュールをインストールします。

```bash
$ source .env/bin/activate
$ (env) pip install -r requirements.txt
```

# 3. 実験
## STEP1：ターミナル1を開いてサーバーを起動します

次のコマンドで、サーバを起動します。

```bash
python server.py
```


## STEP2：ターミナル2を開いてクライアント1を起動します

次のコマンドで、クライアントを起動します。

このクライアントは、ベーシック認証が不要な /public に アクセスします。

```bash
python client1.py

```

## STEP2：ターミナル2を開いてクライアント2を起動します

次のコマンドで、クライアントを起動します。

このクライアントは、ベーシック認証が不要な /private に アクセスします。

```bash
python client2.py

```

# 4. 仮想環境を非活性化します
```bash
(env) $ deactivate
```

# 5. 仮想環境を削除する
```bash
$ sudo rm -r env
```