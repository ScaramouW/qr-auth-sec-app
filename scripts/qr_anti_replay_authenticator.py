#!/usr/bin/env python3
"""
Dynamic QR Code Anti-Replay Token Generator
Author: Fahd BELHIBA
Description: Generates time-bounded HMAC-SHA256 tokens for dynamic QR Code authentication,
preventing replay attacks in attendance and access control systems.
"""

import time
import hmac
import hashlib
import argparse

def generate_dynamic_qr_token(secret_key: str, validity_window: int = 30) -> str:
    """Generates a dynamic token based on secret key and current timestamp window."""
    current_time_block = int(time.time()) // validity_window
    message = str(current_time_block).encode('utf-8')
    key = secret_key.encode('utf-8')
    
    signature = hmac.new(key, message, hashlib.sha256).hexdigest()[:16]
    return f"QR-AUTH:{current_time_block}:{signature}"

def verify_qr_token(token: str, secret_key: str, validity_window: int = 30) -> bool:
    """Validates if a QR code token is valid within the allowed time window."""
    parts = token.split(':')
    if len(parts) != 3 or parts[0] != "QR-AUTH":
        return False

    token_time_block = int(parts[1])
    current_time_block = int(time.time()) // validity_window

    # Allow current window and 1 preceding window (clock skew / latency)
    if abs(current_time_block - token_time_block) > 1:
        print("[!] Token Expired or Replayed!")
        return False

    expected_signature = hmac.new(secret_key.encode('utf-8'), str(token_time_block).encode('utf-8'), hashlib.sha256).hexdigest()[:16]
    return hmac.compare_digest(parts[2], expected_signature)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Dynamic QR Code Anti-Replay Authenticator")
    parser.add_argument("-s", "--secret", default="DEFSEC_SECRET_2026", help="Shared secret key")
    args = parser.parse_args()

    token = generate_dynamic_qr_token(args.secret)
    print(f"[*] Generated Dynamic QR Token: {token}")
    is_valid = verify_qr_token(token, args.secret)
    print(f"[✓] Token Verification Result: {'VALID' if is_valid else 'INVALID'}")
