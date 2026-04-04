#!/usr/bin/env python3
"""
step1_generate_keys.py - RSA 鍵ペアの生成

【処理内容】
  RSA 2048bit の秘密鍵と公開鍵を生成し、ファイルに保存する

【出力ファイル】
  private_key.pem  ← 署名に使用（絶対に外部に漏らしてはいけません）
  public_key.pem   ← 署名検証に使用（誰に配布しても構いません）

【実行方法】
  python step1_generate_keys.py

【次のステップ】
  python step2_encode.py
"""

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

PRIVATE_KEY_FILE = "private_key.pem"
PUBLIC_KEY_FILE  = "public_key.pem"


def print_step(title):
    print(f"\n{'='*60}\n {title}\n{'='*60}")


def print_ok(msg):
    print(f"  [OK] {msg}")


def main():
    print("\n" + "="*60)
    print(" STEP 1: RSA 鍵ペアの生成")
    print("="*60)

    print_step("RSA 2048bit 鍵ペアを生成します")

    # 秘密鍵の生成
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    # 秘密鍵をファイルに保存
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(PRIVATE_KEY_FILE, "wb") as f:
        f.write(private_pem)

    # 公開鍵をファイルに保存
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(PUBLIC_KEY_FILE, "wb") as f:
        f.write(public_pem)

    print(f"\n  ── 秘密鍵（Private Key）─────────────────────────────")
    print(private_pem.decode())
    print(f"  ── 公開鍵（Public Key）──────────────────────────────")
    print(public_pem.decode())

    print_ok(f"秘密鍵を保存しました → {PRIVATE_KEY_FILE}")
    print_ok(f"公開鍵を保存しました → {PUBLIC_KEY_FILE}")
    print()
    print("  ポイント:")
    print("    秘密鍵 → JWT の署名に使用します（自分だけが持つ）")
    print("    公開鍵 → JWT の署名検証に使用します（相手に渡せる）")
    print()
    print("  次のステップ:")
    print("    python step2_encode.py")
    print()


if __name__ == "__main__":
    main()