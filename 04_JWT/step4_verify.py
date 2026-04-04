#!/usr/bin/env python3
"""
step4_verify.py - JWT の署名検証（公開鍵で検証）

【入力】
  --token       JWT ファイルのパス（デフォルト: token.txt）
  --public-key  公開鍵ファイルのパス（デフォルト: public_key.pem）

【処理・出力】
  STEP 6. 公開鍵で Signature を復号化してハッシュ値を取得する
  STEP 7. Header と Payload をピリオド（.）で連結する
  STEP 8. STEP 7 の文字列を alg のアルゴリズムでハッシュ化する
  STEP 9. STEP 6 と STEP 8 のハッシュ値を比較して改ざん検知する

【実行例】
  python step4_verify.py
  python step4_verify.py --token token.txt --public-key public_key.pem
"""

import argparse
import base64
import hashlib
import json
import sys

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

DEFAULT_TOKEN_FILE      = "token.txt"
DEFAULT_PUBLIC_KEY_FILE = "public_key.pem"


def print_step(num, title):
    print(f"\n{'='*60}\n STEP {num}: {title}\n{'='*60}")


def print_ok(msg):
    print(f"  [OK] {msg}")


def base64url_decode(s):
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def load_token(path):
    try:
        with open(path, "r") as f:
            return f.read().strip()
    except FileNotFoundError:
        print(f"  [ERROR] {path} が見つかりません。")
        print("          先に step2_encode.py を実行してください。")
        sys.exit(1)


def load_public_key(path):
    try:
        with open(path, "rb") as f:
            return serialization.load_pem_public_key(f.read())
    except FileNotFoundError:
        print(f"  [ERROR] {path} が見つかりません。")
        print("          先に step1_generate_keys.py を実行してください。")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="JWT の署名検証（公開鍵で検証）")
    parser.add_argument(
        "--token", "-t",
        default=DEFAULT_TOKEN_FILE,
        help=f"JWT ファイルのパス（デフォルト: {DEFAULT_TOKEN_FILE}）",
    )
    parser.add_argument(
        "--public-key", "-k",
        default=DEFAULT_PUBLIC_KEY_FILE,
        help=f"公開鍵ファイルのパス（デフォルト: {DEFAULT_PUBLIC_KEY_FILE}）",
    )
    args = parser.parse_args()

    # ファイルの読み込み
    token = load_token(args.token)
    public_key = load_public_key(args.public_key)
    parts = token.split(".")
    if len(parts) != 3:
        print("  [ERROR] JWT の形式が正しくありません")
        sys.exit(1)

    header_b64  = parts[0]
    payload_b64 = parts[1]
    signature_b64 = parts[2]

    header = json.loads(base64url_decode(header_b64))

    # STEP 6: 公開鍵で Signature を復号化 → ハッシュ値を取得
    print_step(6, "公開鍵で Signature を復号化します（= ハッシュ値を取得）")
    print(f"  Signature（復号化前）: {signature_b64}")
    signature_bytes = base64url_decode(signature_b64)
    try:
        # RSA-PKCS1v15 で復号化してハッシュ値（DER形式）を取得
        decrypted = public_key.recover_data_from_signature(
            signature_bytes,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        hash_from_signature = decrypted.hex()
    except Exception:
        # recover_data_from_signature が使えない環境向けのフォールバック
        # 公開鍵で検証し、ハッシュ値はSTEP 8で計算したものを参照として表示
        hash_from_signature = None

    if hash_from_signature:
        print(f"  復号化結果（ハッシュ値）: {hash_from_signature}")
    else:
        print("  ※ 使用している cryptography ライブラリのバージョンにより")
        print("     復号化したハッシュ値の直接取得ができないため、")
        print("     STEP 8 で計算したハッシュ値と STEP 9 で比較します")

    # STEP 7: Header と Payload をピリオドで連結
    print_step(7, "Header と Payload をピリオド（.）で連結します")
    signing_input = f"{header_b64}.{payload_b64}"
    print(f"  {signing_input}")

    # STEP 8: alg のアルゴリズムでハッシュ化
    print_step(8, f"STEP 7 の文字列を {header.get('alg', 'RS256')}（SHA-256）でハッシュ化します")
    hash_computed = hashlib.sha256(signing_input.encode()).hexdigest()
    print(f"  ハッシュ値: {hash_computed}")

    # STEP 9: ハッシュ値を比較して改ざん検知
    print_step(9, "STEP 6 と STEP 8 のハッシュ値を比較します")
    if hash_from_signature:
        print(f"  STEP 6（Signature 復号化）: {hash_from_signature}")
        print(f"  STEP 8（再計算）          : {hash_computed}")
        match = (hash_from_signature == hash_computed)
    else:
        # PyJWT で署名検証して結果を表示
        import jwt
        try:
            jwt.decode(
                token,
                public_key,
                algorithms=["RS256"],
                options={"verify_exp": False},
            )
            match = True
        except jwt.InvalidSignatureError:
            match = False
        print(f"  STEP 8（再計算したハッシュ値）: {hash_computed}")
        print(f"  Signature の検証            : PyJWT ライブラリで実施")

    print()
    if match:
        print_ok("ハッシュ値が一致しました → JWT は改ざんされていません")
    else:
        print("  [ERROR] ハッシュ値が一致しません → JWT は改ざんされています")
        sys.exit(1)

    print()
    print("  ポイント:")
    print("    秘密鍵で署名されたことを公開鍵だけで確認できます")
    print("    JWT の内容が 1 文字でも変わるとハッシュ値が変わり検証が失敗します")
    print()
    print("  実験完了")
    print()


if __name__ == "__main__":
    main()