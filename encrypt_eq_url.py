#!/usr/bin/env python3
"""Encrypt a Pastebin URL for E_RURL_EQ (v2 cipher: XOR + ADD + ROTATE).

Must match decryptStr() in native-lib.cpp exactly.
"""

import sys

K1 = [0xA3, 0x5F, 0x1D, 0x7E, 0xC4, 0x92, 0x3A, 0xB8, 0x06, 0xE1, 0x4D]
K2 = [0x6B, 0xD7, 0x14, 0x8C, 0xF3, 0x29, 0xA5]


def pos_byte(i):
    return (i * i * 7 + i * 0x1B + 0x3D) & 0xFF


def encrypt(s):
    enc = []
    for i, c in enumerate(s):
        x = ord(c)
        x ^= K1[i % 11]
        x = (x + pos_byte(i)) & 0xFF
        x = ((x << 3) | (x >> 5)) & 0xFF
        x ^= K2[i % 7]
        enc.append(x)
    return enc


def decrypt(enc):
    out = []
    for i, b in enumerate(enc):
        x = b
        x ^= K2[i % 7]
        x = ((x >> 3) | (x << 5)) & 0xFF
        x = (x - pos_byte(i)) & 0xFF
        x ^= K1[i % 11]
        out.append(chr(x))
    return ''.join(out)


def fmt(name, enc):
    return "static const uint8_t %s[] = {%s};" % (name, ",".join("0x%02X" % b for b in enc))


if len(sys.argv) < 2:
    print("Usage: python encrypt_eq_url.py <raw_pastebin_url>")
    print("Example: python encrypt_eq_url.py https://pastebin.com/raw/XXXXXXXX")
    sys.exit(1)

url = sys.argv[1]
enc = encrypt(url)

# Verify round-trip
dec = decrypt(enc)
assert dec == url, f"FAIL: decrypted {dec!r} != {url!r}"

print(f'// "{url}" (len={len(url)})')
print(fmt("E_RURL_EQ", enc))
print()
print("Copy the line above and replace the placeholder in native-lib.cpp")
