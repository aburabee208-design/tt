#!/usr/bin/env python3
"""
config_cipher.py -- Custom ConfigCipher for Remote Config Pastebin Obfuscation

Encrypts/decrypts remote config pastebin lines using a private multi-stage cipher.
Each line is encrypted independently with a random 4-byte nonce.

Commands:
  python config_cipher.py encrypt "device_id,KEY,pool=1,shootit=0"
  python config_cipher.py decrypt "W7pLm2Hv..."
  python config_cipher.py encrypt-file config.txt
  python config_cipher.py test

Cipher stages (encrypt):
  1. Prepend 4-byte random nonce
  2. XOR with position-dependent keystream
  3. Swap adjacent byte pairs
  4. Additive rotation per byte
  5. Encode with custom base64 (shuffled alphabet)
"""

import os
import sys
import argparse

# ======================================================================
# SECRET CONSTANTS -- must match C++ and C# exactly
# ======================================================================
SECRET_KEY = [0xE7, 0x2C, 0x8B, 0x54, 0xF1, 0x39, 0xA6, 0x7D,
              0x1E, 0xC8, 0x63, 0xB0, 0x4A, 0xDF, 0x95, 0x02]

# Shuffled base64 alphabet (NOT standard A-Za-z0-9+/)
CUSTOM_ALPHABET = "W7pLm2HvTqK9BxRwYjZf4Ds5NrXkUe1CaFn6PhSb0GilMcEd3tAuOg8IyJozVQ+/"
CUSTOM_PAD = '='

# Build reverse lookup table
_DECODE_TABLE = {}
for _i, _c in enumerate(CUSTOM_ALPHABET):
    _DECODE_TABLE[_c] = _i


# ======================================================================
# CUSTOM BASE64 ENCODE / DECODE (with shuffled alphabet)
# ======================================================================
def custom_b64_encode(data):
    """Encode bytes to custom base64 string."""
    result = []
    i = 0
    while i < len(data):
        # Grab 3 bytes (pad with 0 if needed)
        b0 = data[i]
        b1 = data[i + 1] if i + 1 < len(data) else 0
        b2 = data[i + 2] if i + 2 < len(data) else 0

        # Split into 4 6-bit groups
        result.append(CUSTOM_ALPHABET[(b0 >> 2) & 0x3F])
        result.append(CUSTOM_ALPHABET[((b0 & 0x03) << 4) | ((b1 >> 4) & 0x0F)])

        if i + 1 < len(data):
            result.append(CUSTOM_ALPHABET[((b1 & 0x0F) << 2) | ((b2 >> 6) & 0x03)])
        else:
            result.append(CUSTOM_PAD)

        if i + 2 < len(data):
            result.append(CUSTOM_ALPHABET[b2 & 0x3F])
        else:
            result.append(CUSTOM_PAD)

        i += 3

    return ''.join(result)


def custom_b64_decode(encoded):
    """Decode custom base64 string to bytes."""
    result = []
    i = 0
    while i < len(encoded):
        # Get 4 chars
        c0 = _DECODE_TABLE.get(encoded[i], 0) if i < len(encoded) and encoded[i] != CUSTOM_PAD else 0
        c1 = _DECODE_TABLE.get(encoded[i+1], 0) if i+1 < len(encoded) and encoded[i+1] != CUSTOM_PAD else 0
        c2 = _DECODE_TABLE.get(encoded[i+2], 0) if i+2 < len(encoded) and encoded[i+2] != CUSTOM_PAD else 0
        c3 = _DECODE_TABLE.get(encoded[i+3], 0) if i+3 < len(encoded) and encoded[i+3] != CUSTOM_PAD else 0

        result.append((c0 << 2) | (c1 >> 4))
        if i + 2 < len(encoded) and encoded[i+2] != CUSTOM_PAD:
            result.append(((c1 & 0x0F) << 4) | (c2 >> 2))
        if i + 3 < len(encoded) and encoded[i+3] != CUSTOM_PAD:
            result.append(((c2 & 0x03) << 6) | c3)

        i += 4

    return bytes(result)


# ======================================================================
# CIPHER: ENCRYPT / DECRYPT
# ======================================================================
NONCE_LEN = 4

def encrypt(plaintext):
    """Encrypt a plaintext string → custom base64 ciphertext."""
    plain_bytes = plaintext.encode('utf-8')

    # Step 1: Prepend random nonce
    nonce = os.urandom(NONCE_LEN)
    data = bytearray(nonce + plain_bytes)

    # Step 2: XOR with position-dependent keystream
    for i in range(len(data)):
        ks = SECRET_KEY[i % len(SECRET_KEY)] ^ ((i * 0x9E + 0x47) & 0xFF)
        data[i] ^= ks

    # Step 3: Swap adjacent byte pairs
    for i in range(0, len(data) - 1, 2):
        data[i], data[i + 1] = data[i + 1], data[i]

    # Step 4: Additive rotation
    for i in range(len(data)):
        data[i] = (data[i] + (i * 0x37 + 0x5C)) & 0xFF

    # Step 5: Custom base64 encode
    return custom_b64_encode(bytes(data))


def decrypt(ciphertext):
    """Decrypt a custom base64 ciphertext → plaintext string."""
    # Step 5 reverse: Custom base64 decode
    data = bytearray(custom_b64_decode(ciphertext))

    # Step 4 reverse: Reverse additive rotation
    for i in range(len(data)):
        data[i] = (data[i] - (i * 0x37 + 0x5C)) & 0xFF

    # Step 3 reverse: Swap adjacent byte pairs back
    for i in range(0, len(data) - 1, 2):
        data[i], data[i + 1] = data[i + 1], data[i]

    # Step 2 reverse: XOR with position-dependent keystream
    for i in range(len(data)):
        ks = SECRET_KEY[i % len(SECRET_KEY)] ^ ((i * 0x9E + 0x47) & 0xFF)
        data[i] ^= ks

    # Step 1 reverse: Strip nonce
    if len(data) <= NONCE_LEN:
        raise ValueError("Ciphertext too short (no data after nonce)")

    return bytes(data[NONCE_LEN:]).decode('utf-8')


# ======================================================================
# COMMANDS
# ======================================================================
def cmd_encrypt(args):
    """Encrypt a single plaintext string."""
    result = encrypt(args.plaintext)
    print(result)


def cmd_decrypt(args):
    """Decrypt a single ciphertext string."""
    try:
        result = decrypt(args.ciphertext)
        print(result)
    except Exception as e:
        print(f"Decryption failed: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_encrypt_file(args):
    """Encrypt each line of a file."""
    with open(args.filename, 'r', encoding='utf-8') as f:
        lines = f.read().splitlines()

    print(f"Encrypting {len(lines)} lines from {args.filename}:\n")
    encrypted_lines = []
    for i, line in enumerate(lines):
        line = line.strip()
        if not line:
            continue
        enc = encrypt(line)
        encrypted_lines.append(enc)
        print(f"  [{i+1}] {line}")
        print(f"   →  {enc}")
        # Verify round-trip
        dec = decrypt(enc)
        assert dec == line, f"Round-trip FAILED for line {i+1}!"
        print(f"   ✓  round-trip OK")
        print()

    print("=" * 60)
    print("  PASTE INTO PASTEBIN (one line per entry)")
    print("=" * 60)
    print()
    for enc_line in encrypted_lines:
        print(enc_line)

    print()
    print(f"  Total: {len(encrypted_lines)} encrypted lines")
    print(f"  ALL ROUND-TRIP CHECKS PASSED")


def cmd_test(args):
    """Run self-test: round-trip + nonce uniqueness + standard base64 defense."""
    import base64

    print("=" * 60)
    print("  ConfigCipher Self-Test")
    print("=" * 60)
    passed = 0
    failed = 0

    # Test 1: Basic round-trip
    test_lines = [
        "a19cf916f8c89170,0F72-0FBQ-GPBJ-BZIJ,pool=1,shootit=0",
        "*,PUBLIC-KEY-HERE,pool=1,shootit=1",
        "abcdef123456,XXXX-YYYY-ZZZZ-WWWW,pool=0,shootit=1,disabled",
        "short",
        "a,b",
    ]
    print("\n[1] Round-trip tests:")
    for line in test_lines:
        enc = encrypt(line)
        dec = decrypt(enc)
        ok = dec == line
        status = "OK" if ok else "FAIL"
        print(f"  {status}: \"{line[:50]}...\"" if len(line) > 50 else f"  {status}: \"{line}\"")
        if ok:
            passed += 1
        else:
            failed += 1
            print(f"    Expected: {line}")
            print(f"    Got:      {dec}")

    # Test 2: Nonce uniqueness
    print("\n[2] Nonce uniqueness:")
    enc1 = encrypt("same-plaintext")
    enc2 = encrypt("same-plaintext")
    if enc1 != enc2:
        print(f"  OK: Two encryptions of same text produce different output")
        print(f"    enc1: {enc1}")
        print(f"    enc2: {enc2}")
        passed += 1
    else:
        print(f"  FAIL: Identical ciphertexts!")
        failed += 1

    # Test 3: Standard base64 defense
    print("\n[3] Standard base64 defense:")
    enc = encrypt("a19cf916,KEY,pool=1,shootit=0")
    try:
        std_decoded = base64.b64decode(enc + '==')  # pad for standard
        # Check if the decoded contains any recognizable substring
        try:
            std_text = std_decoded.decode('utf-8', errors='strict')
            has_pattern = 'pool' in std_text or 'KEY' in std_text or 'shootit' in std_text
        except:
            has_pattern = False
        if not has_pattern:
            print(f"  OK: Standard base64 decode produces garbage")
            passed += 1
        else:
            print(f"  FAIL: Standard base64 decode reveals content!")
            failed += 1
    except:
        print(f"  OK: Standard base64 decode fails entirely")
        passed += 1

    # Test 4: Custom alphabet check
    print("\n[4] Alphabet uniqueness check:")
    if len(set(CUSTOM_ALPHABET)) == 64:
        print(f"  OK: 64 unique characters in custom alphabet")
        passed += 1
    else:
        print(f"  FAIL: Alphabet has duplicate or missing characters!")
        failed += 1

    # Summary
    print(f"\n{'=' * 60}")
    if failed == 0:
        print(f"  ALL {passed} TESTS PASSED")
    else:
        print(f"  {passed} passed, {failed} FAILED")
    print(f"{'=' * 60}")

    if failed > 0:
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="ConfigCipher — Remote Config Pastebin Obfuscator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  %(prog)s encrypt "device_id,KEY,pool=1,shootit=0"
  %(prog)s decrypt "W7pLm2Hv..."
  %(prog)s encrypt-file config.txt
  %(prog)s test""")

    sub = parser.add_subparsers(dest="command")

    ep = sub.add_parser("encrypt", help="Encrypt a single plaintext line")
    ep.add_argument("plaintext", help="Plaintext string to encrypt")

    dp = sub.add_parser("decrypt", help="Decrypt a single ciphertext line")
    dp.add_argument("ciphertext", help="Ciphertext string to decrypt")

    fp = sub.add_parser("encrypt-file", help="Encrypt each line of a file")
    fp.add_argument("filename", help="Path to file with plaintext lines")

    sub.add_parser("test", help="Run self-test suite")

    args = parser.parse_args()

    if args.command == "encrypt":
        cmd_encrypt(args)
    elif args.command == "decrypt":
        cmd_decrypt(args)
    elif args.command == "encrypt-file":
        cmd_encrypt_file(args)
    elif args.command == "test":
        cmd_test(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
