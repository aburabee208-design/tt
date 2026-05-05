#!/usr/bin/env python3
"""enc_strings.py — encrypts JNI helper strings (v2: XOR + ADD + ROTATE)."""

K1 = [0xA3, 0x5F, 0x1D, 0x7E, 0xC4, 0x92, 0x3A, 0xB8, 0x06, 0xE1, 0x4D]
K2 = [0x6B, 0xD7, 0x14, 0x8C, 0xF3, 0x29, 0xA5]


def pos_byte(i):
    return (i * i * 7 + i * 0x1B + 0x3D) & 0xFF


def encrypt(s):
    out = []
    for i, c in enumerate(s):
        x = ord(c)
        x ^= K1[i % 11]
        x = (x + pos_byte(i)) & 0xFF
        x = ((x << 3) | (x >> 5)) & 0xFF
        x ^= K2[i % 7]
        out.append(x)
    return out


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


strings = {
    "ENC_JNI_URL_CLS":       "java/net/URL",
    "ENC_JNI_IS_CLS":        "java/io/InputStream",
    "ENC_JNI_INIT":          "<init>",
    "ENC_JNI_INIT_SIG":      "(Ljava/lang/String;)V",
    "ENC_JNI_OPENSTREAM":    "openStream",
    "ENC_JNI_OPENSTREAM_SIG": "()Ljava/io/InputStream;",
    "ENC_JNI_READ":          "read",
    "ENC_JNI_READ_SIG":      "([B)I",
    "ENC_JNI_CLOSE":         "close",
    "ENC_JNI_CLOSE_SIG":     "()V",
}

for name, s in strings.items():
    enc = encrypt(s)
    dec = decrypt(enc)
    assert dec == s, f"FAIL: {name} round-trip {dec!r} != {s!r}"
    print(f'// "{s}" (len={len(s)})')
    print(fmt(name, enc))
    print()
