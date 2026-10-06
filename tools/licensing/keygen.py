#!/usr/bin/env python3
"""
Aryorithm License System: Ed25519 Master Key Generator
Generates:
  1. master_private.key -> Used ONLY by Aryorithm to sign commercial licenses.
  2. master_public.key  -> Embedded into C++ LicenseManager.cpp for local verification.
"""

import os
import base64
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

KEY_DIR = os.path.dirname(os.path.abspath(__file__))

def main():
    # Generate Ed25519 private key
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    # Raw 32-byte keys
    raw_private = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    raw_public = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    priv_path = os.path.join(KEY_DIR, "master_private.key")
    pub_path = os.path.join(KEY_DIR, "master_public.key")

    with open(priv_path, "wb") as f:
        f.write(raw_private)
    with open(pub_path, "wb") as f:
        f.write(raw_public)

    print("==================================================================")
    print("  ARYORITHM ED25519 MASTER LICENSING KEYS GENERATED")
    print("==================================================================")
    print(f"[+] Private Key saved to: {priv_path} (KEEP STRICTLY CONFIDENTIAL!)")
    print(f"[+] Public Key saved to : {pub_path}")
    print("------------------------------------------------------------------")
    print(f"Public Key (Base64) : {base64.b64encode(raw_public).decode('utf-8')}")
    print("C++ Array (for LicenseManager.cpp):")
    hex_bytes = ", ".join([f"0x{b:02x}" for b in raw_public])
    print(f"static const uint8_t ARYORITHM_MASTER_PUBKEY[32] = {{{hex_bytes}}};")
    print("==================================================================")

if __name__ == "__main__":
    main()