#!/usr/bin/env python3
from binascii import unhexlify

def decrypt_hex(hex_str):
    ct = unhexlify(hex_str)
    inv = 179
    pt = bytes((inv * ((c - 18) % 256)) % 256 for c in ct)
    return pt

if __name__ == "__main__":
    encrypted_text = "6e0a9372ec49a3f6930ed8723f9df6f6720ed8d89dc4937222ec7214d89d1e0e352ce0aa6ec82bf622227bb70e7fb7352249b7d893c493d8539dec8fb7935d490e7f9d22ec89b7a322ec8fd80e7f8921"
    print(decrypt_hex(encrypted_text).decode())
