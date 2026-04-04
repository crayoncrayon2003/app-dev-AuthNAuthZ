#!/usr/bin/env python3
"""
step2_encode.py - JWT のエンコード（秘密鍵で署名）

【入力】
  --private-key  秘密鍵ファイルのパス（デフォルト: private_key.pem）
  --payload      JWT に埋め込む key=value（スペース区切りで複数指定可能）

【処理】
  秘密鍵（RS256）でペイロードに署名して JWT を生成する

【出力】
  --output       JWT の保存先ファイルパス（デフォルト: token.txt）
  ターミナルに JWT の生成手順を表示する

【実行例】
  python step2_encode.py --payload "name=山田太郎 role=admin"
  python step2_encode.py --payload "name=山田太郎 role=admin" --private-key private_key.pem --output token.txt

【次のステップ】
  python step3_decode.py --token token.txt
"""

import argparse
import json
import sys

import jwt

DEFAULT_PRIVATE_KEY = "private_key.pem"
DEFAULT_TOKEN_FILE  = "token.txt"


def print_step(num, title):
    print(f"\n{'='*60}\n STEP {num}: {title}\n{'='*60}")


def print_ok(msg):
    print(f"  [OK] {msg}")


def load_private_key(path):
    try:
        with open(path, "rb") as f:
            return f.read()
    except FileNotFoundError:
        print(f"  [ERROR] {path} が見つかりません。")
        print("          先に step1_generate_keys.py を実行してください。")
        sys.exit(1)


def parse_payload(payload_str):
    """
    "name=山田太郎 role=admin" → {"name": "山田太郎", "role": "admin"}
    """
    payload = {}
    for item in payload_str.split():
        if "=" not in item:
            print(f"  [ERROR] 形式が正しくありません: {item}")
            print("          key=value の形式で指定してください")
            sys.exit(1)
        key, value = item.split("=", 1)
        payload[key] = value
    return payload


def main():
    parser = argparse.ArgumentParser(description="JWT のエンコード（秘密鍵で署名）")
    parser.add_argument(
        "--private-key", "-k",
        default=DEFAULT_PRIVATE_KEY,
        help=f"秘密鍵ファイルのパス（デフォルト: {DEFAULT_PRIVATE_KEY}）",
    )
    parser.add_argument(
        "--payload", "-p",
        required=True,
        help='JWT に埋め込む key=value（スペース区切り）例: "name=山田太郎 role=admin"',
    )
    parser.add_argument(
        "--output", "-o",
        default=DEFAULT_TOKEN_FILE,
        help=f"JWT の保存先ファイルパス（デフォルト: {DEFAULT_TOKEN_FILE}）",
    )
    args = parser.parse_args()

    # 秘密鍵の読み込み
    private_key = load_private_key(args.private_key)
    print_ok(f"{args.private_key} を読み込みました")

    # ペイロードの解析
    payload = parse_payload(args.payload)

    # JWT を生成（内部処理）
    token = jwt.encode(payload, private_key, algorithm="RS256")
    parts = token.split(".")

    # STEP 2: Header の作成
    print_step(2, "Header を作成します")
    header = {"alg": "RS256", "typ": "JWT"}
    print(f"  {json.dumps(header, ensure_ascii=False)}")

    # STEP 3: Payload の作成
    print_step(3, "Payload を作成します")
    print(f"  {json.dumps(payload, ensure_ascii=False)}")

    # STEP 4: Header を Base64URL エンコード
    print_step(4, "Header を Base64URL エンコードします")
    print(f"  {parts[0]}")

    # STEP 5: Payload を Base64URL エンコード
    print_step(5, "Payload を Base64URL エンコードします")
    print(f"  {parts[1]}")

    # STEP 6: Header と Payload をピリオドで連結
    print_step(6, "STEP 4 と STEP 5 をピリオド（.）で連結します")
    print(f"  {parts[0]}.{parts[1]}")

    # STEP 7: ハッシュ値を求める
    print_step(7, "STEP 6 の文字列を RS256（SHA-256）でハッシュ化します")
    print("  ※ ハッシュ値は次の STEP 8 で秘密鍵による暗号化に使用します")
    print("  ※ 使用している PyJWT ライブラリはハッシュ化から署名まで一括処理するため、")
    print("     中間値であるハッシュ値だけを取り出して表示することができません")

    # STEP 8: 秘密鍵で暗号化 → Signature
    print_step(8, "秘密鍵で STEP 7 のハッシュ値を暗号化します（= Signature）")
    print(f"  {parts[2]}")

    # STEP 9: Header・Payload・Signature をピリオドで連結 → JWT
    print_step(9, "STEP 4・5・8 をピリオド（.）で連結します（= JWT）")
    print(f"  {token}")

    # STEP 10: JWT の発行
    print_step(10, "JWT をファイルに保存します（クライアントへの発行）")
    with open(args.output, "w") as f:
        f.write(token)
    print_ok(f"JWT を保存しました → {args.output}")

    print()
    print("  次のステップ:")
    print(f"    python step3_decode.py --token {args.output}")
    print()


if __name__ == "__main__":
    main()