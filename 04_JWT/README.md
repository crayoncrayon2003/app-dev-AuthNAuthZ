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
## STEP1：サーバーによる秘密鍵と公開鍵の生成

次のコマンドで、秘密鍵と公開鍵のセットを生成します。

private_key.pem / public_key.pem が生成されます。

```bash
python step1_generate_keys.py
```


## STEP2：サーバーによるJWTの生成

次のコマンドで、JWTを生成します。

token.txt の中にJWTを保存します。

```bash
python step2_encode.py --payload "message=サンプルのクレームです"

```

## STEP3：クライアントによるJWTの復号

次のコマンドで、JWTを復号します。

ペイロードの中身が表示されます。

```bash
python step3_decode.py --token token.txt
```

## STEP4：クライアントによるJWTの検証

次のコマンドで、JWTを検証します。

 署名検証結果とペイロードが表示されます。

```bash
python step4_verify.py --token token.txt --public-key public_key.pem
```

# 4. 仮想環境を非活性化します
```bash
(env) $ deactivate
```

# 5. 仮想環境を削除する
```bash
$ sudo rm -r env
```