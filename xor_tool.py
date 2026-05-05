#!/usr/bin/env python3
"""
Multi-Layer String Encryption Tool (v2 — XOR + ADD + ROTATE)
Produces encrypted byte arrays for native-lib.cpp.

NEW algorithm (must match decryptStr() in C++ exactly):

  Encrypt (this script, build-time)            Decrypt (C++, runtime)
  ─────────────────────────────────             ─────────────────────────
  x ^= K1[i % 11]                               x ^= K2[i % 7]
  x  = (x + pos_byte(i)) & 0xFF                 x  = rotr3(x)
  x  = ((x << 3) | (x >> 5)) & 0xFF             x  = (x - pos_byte(i)) & 0xFF
  x ^= K2[i % 7]                                x ^= K1[i % 11]

Where pos_byte(i) = (i*i*7 + i*0x1B + 0x3D) & 0xFF.

XOR alone is symmetric and trivial to break with AI-assisted analysis.
Adding ADD/SUB and bit rotations produces an asymmetric pipeline that
forces an attacker to actually trace the function rather than recognize
a textbook XOR cipher.
"""

import sys

KEY1 = bytes([0xA3, 0x5F, 0x1D, 0x7E, 0xC4, 0x92, 0x3A, 0xB8, 0x06, 0xE1, 0x4D])  # 11 bytes
KEY2 = bytes([0x6B, 0xD7, 0x14, 0x8C, 0xF3, 0x29, 0xA5])                            # 7 bytes


def pos_byte(i: int) -> int:
    return (i * i * 7 + i * 0x1B + 0x3D) & 0xFF


def encrypt(plaintext: str) -> bytes:
    raw = plaintext.encode('utf-8')
    out = bytearray(len(raw))
    for i, b in enumerate(raw):
        x = b
        x ^= KEY1[i % len(KEY1)]                  # Layer 1
        x = (x + pos_byte(i)) & 0xFF              # Layer 2 — ADD non-linear
        x = ((x << 3) | (x >> 5)) & 0xFF          # Layer 3 — rotate left 3
        x ^= KEY2[i % len(KEY2)]                  # Layer 4
        out[i] = x
    return bytes(out)


def decrypt(data: bytes) -> str:
    """Reverse of encrypt — used for verification."""
    out = bytearray(len(data))
    for i, b in enumerate(data):
        x = b
        x ^= KEY2[i % len(KEY2)]                  # reverse Layer 4
        x = ((x >> 3) | (x << 5)) & 0xFF          # reverse Layer 3 — rotate right 3
        x = (x - pos_byte(i)) & 0xFF              # reverse Layer 2 — SUB
        x ^= KEY1[i % len(KEY1)]                  # reverse Layer 1
        out[i] = x
    return out.decode('utf-8')


def to_cpp_array(name: str, data: bytes) -> str:
    hex_vals = ', '.join(f'0x{b:02X}' for b in data)
    return f'static const uint8_t {name}[] = {{{hex_vals}}}; // len={len(data)}'


# All strings to encrypt — plaintext lookup
STRINGS = {
    # Critical secrets
    "ENC_SALT":       "JwkrCh3t0_2026",
    "ENC_BASE36":     "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "ENC_PREFS":      ".sys_cfg",
    "ENC_KEY_LT":     "lt",
    "ENC_KEY_LK":     "lk",
    "ENC_ANDROID_ID": "android_id",

    # UI text
    "ENC_TITLE":      "JAWAKER CHETO",
    "ENC_TITLE2":     "Jawaker CHETO",
    "ENC_WAIT":       "Wait %d seconds",
    "ENC_EMPTY":      "Please enter a key",
    "ENC_EXPIRED":    "Key expired",
    "ENC_CLOCK":      "Clock tampering detected",
    "ENC_INVALID":    "Invalid key",
    "ENC_WELCOME":    "Welcome back!",
    "ENC_EXPIRED2":   "Your key has expired",
    "ENC_POWER":      "Power: ---",
    "ENC_SPIN":       "Spin: ---",
    "ENC_DIR":        "Dir: ---",
    "ENC_OPACITY":    "Opacity: 75%",
    "ENC_DEVICE":     "Device: ",
    "ENC_XXXX":       "XXXX",
    "ENC_LOGIN":      "LOGIN",
    "ENC_DASH":       "\u2014",
    "ENC_PLUS":       "+",

    # Anti-Frida detection strings
    "ENC_S_FRIDA":           "frida",
    "ENC_S_GADGET":          "gadget",
    "ENC_S_LINJECTOR":       "linjector",
    "ENC_S_GMAIN":           "gmain",
    "ENC_S_GDBUS":           "gdbus",
    "ENC_S_GUMJS":           "gum-js",

    # GameStore key name
    "ENC_S_ADD_BREAK_POWER": "add_break_power",
}

if __name__ == "__main__":
    print("=" * 70)
    print("MULTI-LAYER ENCRYPTION (v2 — XOR + ADD + ROTATE)")
    print("=" * 70)
    print()
    print("// === ENCRYPTED STRING DATA (paste into native-lib.cpp) ===")
    print()

    for name, plaintext in STRINGS.items():
        print(to_cpp_array(name, encrypt(plaintext)))

    # Verification
    print()
    print("=" * 70)
    print("VERIFICATION (round-trip):")
    print("=" * 70)
    all_ok = True
    for name, plaintext in STRINGS.items():
        enc = encrypt(plaintext)
        decoded = decrypt(enc)
        ok = decoded == plaintext
        if not ok:
            all_ok = False
        status = "OK" if ok else "FAIL"
        print(f'  {name}: "{decoded}" [{status}]')

    print(f'\nAll checks: {"PASSED" if all_ok else "FAILED"}')
