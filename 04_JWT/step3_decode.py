#!/usr/bin/env python3
"""
step3_decode.py - JWT のデコード

【入力】
  --token  JWT ファイルのパス（デフォルト: token.txt）

【処理・出力】
  STEP 1. 公開鍵ファイルの確認
  STEP 2. JWT ファイルの確認
  STEP 3. JWT をピリオド（.）で分割する
  STEP 4. Header を Base64URL デコードして alg を取得する
  STEP 5. Payload を Base64URL デコードしてクレームを取得する

【実行例】
  python step3_decode.py
  python step3_decode.py --token token.txt

【次のステップ】
  python step4_verify.py --token token.txt --public-key public_key.pem
"""

import argparse
import base64
import json
import sys

DEFAULT_TOKEN_FILE      = "token.txt"
DEFAULT_PUBLIC_KEY_FILE = "public_key.pem"


def print_step(num, title):
    print(f"\n{'='*60}\n STEP {num}: {title}\n{'='*60}")


def print_ok(msg):
    print(f"  [OK] {msg}")


def pretty_json(obj):
    return json.dumps(obj, ensure_ascii=False, indent=2)


def base64url_decode(s):
    # Base64URL は = パディングなしのため補完が必要
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


def main():
    parser = argparse.ArgumentParser(description="JWT のデコード")
    parser.add_argument(
        "--token", "-t",
        default=DEFAULT_TOKEN_FILE,
        help=f"JWT ファイルのパス（デフォルト: {DEFAULT_TOKEN_FILE}）",
    )
    args = parser.parse_args()

    # STEP 1: 公開鍵ファイルの確認
    print_step(1, "公開鍵ファイルを確認します")
    try:
        with open(DEFAULT_PUBLIC_KEY_FILE, "r") as f:
            public_key_content = f.read()
        print_ok(f"{DEFAULT_PUBLIC_KEY_FILE} を確認しました")
        print(f"\n{public_key_content}")
    except FileNotFoundError:
        print(f"  [ERROR] {DEFAULT_PUBLIC_KEY_FILE} が見つかりません。")
        print("          先に step1_generate_keys.py を実行してください。")
        sys.exit(1)

    # STEP 2: JWT ファイルの確認
    print_step(2, "JWT ファイルを確認します")
    token = load_token(args.token)
    print_ok(f"{args.token} を確認しました")
    print(f"\n  {token}")

    # STEP 3: JWT をピリオドで分割
    print_step(3, "JWT をピリオド（.）で分割します")
    parts = token.split(".")
    if len(parts) != 3:
        print("  [ERROR] JWT の形式が正しくありません（3パートに分割できません）")
        sys.exit(1)
    print(f"  Base64URL エンコード済みの Header   : {parts[0]}")
    print(f"  Base64URL エンコード済みの Payload  : {parts[1]}")
    print(f"  Signature（秘密鍵で暗号化されたハッシュ値）: {parts[2]}")

    # STEP 4: Header を Base64URL デコード → alg を取得
    print_step(4, "Header を Base64URL デコードして alg を取得します")
    header = json.loads(base64url_decode(parts[0]))
    print(f"  デコード結果: {pretty_json(header)}")
    print(f"\n  alg: {header.get('alg', '（なし）')}")

    # STEP 5: Payload を Base64URL デコード → クレームを取得
    print_step(5, "Payload を Base64URL デコードしてクレームを取得します")
    payload = json.loads(base64url_decode(parts[1]))
    print(f"  デコード結果（クレーム）:")
    print(pretty_json(payload))

    print()
    print_ok("JWT デコード完了")
    print()
    print("  ポイント:")
    print("    JWT の中身は暗号化されていません（Base64URL でエンコードされているだけ）")
    print("    機密情報（パスワード等）を JWT に含めてはいけません")
    print()
    print("  次のステップ:")
    print(f"    python step4_verify.py --token {args.token} --public-key {DEFAULT_PUBLIC_KEY_FILE}")
    print()


if __name__ == "__main__":
    main()