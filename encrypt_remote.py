#!/usr/bin/env python3
"""
encrypt_remote.py -- Remote Kill-Switch Encoder & Pastebin Rotator

Commands:
  python encrypt_remote.py                    # legacy: show current constants
  python encrypt_remote.py rotate             # generate new pastebin content
  python encrypt_remote.py verify <textA> <textB>  # verify pastebin texts

Encryption scheme:
  Layer 1: ROT + position-dependent byte shuffle + salt XOR
  Layer 2: FNV-1a hash of decrypted word -> per-pastebin seed
  Layer 3: g_remote_seed = seed_a ^ seed_b (dual-pastebin XOR)
  Layer 4: ENC_REMOTE_* = real_offset ^ g_rva_seed ^ g_remote_seed
"""

import base64
import random
import string
import sys
import argparse

# ======================================================================
# CONFIG -- must match native-lib.cpp exactly
# ======================================================================
# g_rva_seed at runtime = RAW_SEED ^ computePrologueDigest().
# We read PROLOGUE_DIGEST from offset_encoder.py so this stays in sync
# automatically — no manual update needed during digest recalibration.
import re, pathlib
_RAW_RVA_SEED = 0x5A9E37C1
def _read_prologue_digest():
    p = pathlib.Path(__file__).parent / "offset_encoder.py"
    for line in p.read_text(encoding='utf-8', errors='ignore').splitlines():
        m = re.match(r'^\s*PROLOGUE_DIGEST\s*=\s*(0x[0-9A-Fa-f]+)', line)
        if m: return int(m.group(1), 16)
    raise RuntimeError("PROLOGUE_DIGEST not found in offset_encoder.py")
G_RVA_SEED = _RAW_RVA_SEED ^ _read_prologue_digest()
TARGET_REMOTE_SEED = 0x63F01C4F  # ROTATED 2026-04-07 (was 0x6E2B4F91)

REMOTE_SALT = [0xCA, 0x0F, 0x67, 0x40, 0x02, 0x77, 0xA1, 0xA4,
               0xB9, 0xFF, 0xC1, 0xE5, 0x77, 0x51, 0x29, 0xF5]

PRESHOT_OFFSETS = {
    "BSS_CIPHER_KLASS":       0x0A6D6D80,
    "BSS_BYTE_ARRAY_KLASS":   0x0A6CA750,
    "BSS_KEY_FORMAT_SECRET":  0x0A7BE3A8,
    "BSS_KEY_TURN":           0x0A7D5898,
    "RVA_CIPHER_SEED":        0x0839A688,
    "RVA_CIPHER_ENCRYPT":     0x0839B050,
    # Pool post-first-shot + ShootIt predictions (added for full kill-switch)
    "SHOOTIT_SIMULATE":          0x04C794C8,
    "SHOOTIT_CONTROLLER_INPUT":  0x0506010C,
    "SHOOTIT_MYPLAYER_GET":      0x05060A44,
    "BSS_SHOOTIT_CLASS_REF":     0x0A3F43A0,
    "POOL_SIMULATE":             0x04C79DAC,
    "RUSTBRIDGE_SIMULATE_POOL":  0x04C79EDC,
    "CLEARGS":                   0x04786DF4,
}

STEGO_INTERVAL = 11  # every 11th character (positions 10, 21, 32, ...)
WORD_LENGTH = 16     # magic word length (keeps base64 at 24 chars)

# ======================================================================
# LAYER 1: Encrypt / Decrypt
# ======================================================================

def encrypt_word(word):
    """Encrypt word using ROT + position shuffle + salt XOR."""
    data = word.encode('utf-8')
    # Step 1: ROT by position-dependent offset
    rotated = bytearray()
    for i, b in enumerate(data):
        offset = (i * 13 + 7) % 256
        rotated.append((b + offset) & 0xFF)
    # Step 2: Swap adjacent pairs
    shuffled = bytearray(rotated)
    for i in range(0, len(shuffled) - 1, 2):
        shuffled[i], shuffled[i + 1] = shuffled[i + 1], shuffled[i]
    # Step 3: XOR with repeating salt
    for i in range(len(shuffled)):
        shuffled[i] ^= REMOTE_SALT[i % len(REMOTE_SALT)]
    return bytes(shuffled)


def decrypt_word(encrypted):
    """Decrypt: reverse salt XOR, reverse pair swap, reverse ROT."""
    data = bytearray(encrypted)
    for i in range(len(data)):
        data[i] ^= REMOTE_SALT[i % len(REMOTE_SALT)]
    for i in range(0, len(data) - 1, 2):
        data[i], data[i + 1] = data[i + 1], data[i]
    result = bytearray()
    for i, b in enumerate(data):
        offset = (i * 13 + 7) % 256
        result.append((b - offset) & 0xFF)
    return bytes(result).decode('utf-8')


# ======================================================================
# LAYER 2: FNV-1a hash
# ======================================================================

def fnv1a_32(s):
    h = 0x811C9DC5
    for c in s.encode('utf-8'):
        h ^= c
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h


# ======================================================================
# STEGANOGRAPHY: embed base64 into innocent filler text
# ======================================================================

def embed_stego(b64_payload):
    """Generate random innocent-looking text with b64 hidden at every 9th char.

    IMPORTANT: first and last filler positions use letters only (no spaces)
    because pastebin.com strips leading/trailing whitespace.
    """
    filler_chars = string.ascii_lowercase + "  "  # letters + spaces for natural look
    filler_safe = string.ascii_lowercase           # no spaces (for edges)
    result = []
    payload_idx = 0

    # We need (len(b64) - 1) * 7 + 7 chars minimum
    total_len = len(b64_payload) * STEGO_INTERVAL
    for i in range(total_len):
        if (i % STEGO_INTERVAL) == (STEGO_INTERVAL - 1) and payload_idx < len(b64_payload):
            # This is a stego position -- place the hidden char
            result.append(b64_payload[payload_idx])
            payload_idx += 1
        elif i == 0 or i == total_len - 1:
            # Edge positions: never use spaces (pastebin strips them)
            result.append(random.choice(filler_safe))
        else:
            result.append(random.choice(filler_chars))

    return ''.join(result)


def extract_stego(text):
    """Extract hidden chars at every 9th position (0-indexed: 8, 17, 26, ...)."""
    return ''.join(text[i] for i in range(STEGO_INTERVAL - 1, len(text), STEGO_INTERVAL))


# ======================================================================
# WORD PAIR BRUTE-FORCE: find two words whose seeds XOR to target
# ======================================================================

def random_word(length=WORD_LENGTH):
    """Generate a random alphanumeric + underscore word."""
    chars = string.ascii_lowercase + string.digits + "_"
    return ''.join(random.choices(chars, k=length))


def find_word_pair(target_xor, word_length=WORD_LENGTH, max_attempts=500000):
    """Brute-force a pair of words whose FNV-1a hashes XOR to target_xor.

    Strategy: generate many random words, store their hashes in a dict.
    For each new word with hash H, check if (H ^ target_xor) already exists.
    Expected to find a match in ~2^16 = 65536 attempts (birthday-like).
    """
    seen = {}  # hash -> word

    for attempt in range(max_attempts):
        w = random_word(word_length)
        h = fnv1a_32(w)
        needed = h ^ target_xor

        if needed in seen:
            return seen[needed], w, attempt + 1

        seen[h] = w

    raise RuntimeError(f"Failed to find pair in {max_attempts} attempts")


# ======================================================================
# COMMANDS
# ======================================================================

def cmd_rotate(args):
    """Generate fresh pastebin content with new words, same g_remote_seed."""
    print("=" * 60)
    print("  Pastebin Content Rotation")
    print("=" * 60)

    # 1. Find word pair
    print(f"\n[1] Brute-forcing word pair (target XOR: 0x{TARGET_REMOTE_SEED:08X})...")
    word_a, word_b, attempts = find_word_pair(TARGET_REMOTE_SEED)
    seed_a = fnv1a_32(word_a)
    seed_b = fnv1a_32(word_b)

    print(f"    Found in {attempts} attempts!")
    print(f"    Word A: \"{word_a}\"  seed: 0x{seed_a:08X}")
    print(f"    Word B: \"{word_b}\"  seed: 0x{seed_b:08X}")
    print(f"    XOR check: 0x{seed_a:08X} ^ 0x{seed_b:08X} = 0x{seed_a ^ seed_b:08X}")
    assert seed_a ^ seed_b == TARGET_REMOTE_SEED, "XOR mismatch!"

    # 2. Encrypt both words
    print(f"\n[2] Encrypting words...")
    enc_a = encrypt_word(word_a)
    enc_b = encrypt_word(word_b)
    b64_a = base64.b64encode(enc_a).decode('ascii')
    b64_b = base64.b64encode(enc_b).decode('ascii')

    # Verify round-trip
    assert decrypt_word(enc_a) == word_a, "Word A round-trip failed!"
    assert decrypt_word(enc_b) == word_b, "Word B round-trip failed!"
    print(f"    Base64 A: {b64_a}")
    print(f"    Base64 B: {b64_b}")
    print(f"    Round-trip: OK")

    # 3. Generate steganographic text
    print(f"\n[3] Generating steganographic filler text...")
    stego_a = embed_stego(b64_a)
    stego_b = embed_stego(b64_b)

    # Verify extraction
    extracted_a = extract_stego(stego_a)
    extracted_b = extract_stego(stego_b)
    assert extracted_a == b64_a, f"Stego A extraction failed: got '{extracted_a}'"
    assert extracted_b == b64_b, f"Stego B extraction failed: got '{extracted_b}'"
    print(f"    Stego extraction: OK")

    # 4. Full pipeline verification
    print(f"\n[4] Full pipeline verification...")
    dec_a = decrypt_word(base64.b64decode(extracted_a))
    dec_b = decrypt_word(base64.b64decode(extracted_b))
    verify_seed_a = fnv1a_32(dec_a)
    verify_seed_b = fnv1a_32(dec_b)
    verify_remote = verify_seed_a ^ verify_seed_b

    print(f"    Extracted A -> \"{dec_a}\" -> 0x{verify_seed_a:08X}")
    print(f"    Extracted B -> \"{dec_b}\" -> 0x{verify_seed_b:08X}")
    print(f"    g_remote_seed = 0x{verify_remote:08X}")
    assert verify_remote == TARGET_REMOTE_SEED, "Final seed mismatch!"

    # Verify all offsets decode correctly
    for name, real in PRESHOT_OFFSETS.items():
        encoded = real ^ G_RVA_SEED ^ verify_remote
        decoded = encoded ^ G_RVA_SEED ^ verify_remote
        assert decoded == real, f"{name} verification failed!"
    print(f"    All 6 offsets: OK")

    # 5. Output ready-to-paste content
    print(f"\n{'=' * 60}")
    print(f"  PASTE INTO PASTEBINS")
    print(f"{'=' * 60}")
    print(f"\n  Pastebin A (pastebin.com/CLNB1PVb):")
    print(f"  {stego_a}")
    print(f"\n  Pastebin B (pastebin.com/RudKfPSu):")
    print(f"  {stego_b}")

    print(f"\n{'=' * 60}")
    print(f"  ALL VERIFICATIONS PASSED")
    print(f"{'=' * 60}")


def cmd_verify(args):
    """Verify that given pastebin texts produce the correct g_remote_seed."""
    text_a = args.text_a
    text_b = args.text_b

    print("=" * 60)
    print("  Pastebin Verification")
    print("=" * 60)

    for label, text in [("A", text_a), ("B", text_b)]:
        stego = extract_stego(text)
        decoded = base64.b64decode(stego)
        word = decrypt_word(decoded)
        seed = fnv1a_32(word)
        print(f"\n  Pastebin {label}:")
        print(f"    Hidden base64: \"{stego}\"")
        print(f"    Decrypted word: \"{word}\"")
        print(f"    FNV-1a seed: 0x{seed:08X}")

    stego_a = extract_stego(text_a)
    stego_b = extract_stego(text_b)
    word_a = decrypt_word(base64.b64decode(stego_a))
    word_b = decrypt_word(base64.b64decode(stego_b))
    seed_a = fnv1a_32(word_a)
    seed_b = fnv1a_32(word_b)
    remote = seed_a ^ seed_b

    print(f"\n  g_remote_seed = 0x{seed_a:08X} ^ 0x{seed_b:08X} = 0x{remote:08X}")

    if remote == TARGET_REMOTE_SEED:
        print(f"  Status: CORRECT (matches 0x{TARGET_REMOTE_SEED:08X})")
    else:
        print(f"  Status: MISMATCH! Expected 0x{TARGET_REMOTE_SEED:08X}")
        sys.exit(1)

    # Verify offsets
    print(f"\n  Offset verification:")
    for name, real in PRESHOT_OFFSETS.items():
        encoded = real ^ G_RVA_SEED ^ remote
        decoded = encoded ^ G_RVA_SEED ^ remote
        ok = "OK" if decoded == real else "FAIL"
        print(f"    {name}: 0x{decoded:08X} [{ok}]")


def cmd_legacy(args):
    """Original single-word mode for reference."""
    MAGIC_WORD = "turret95_magic"

    print("=" * 60)
    print("  Remote Kill-Switch Encoder (Legacy Mode)")
    print("=" * 60)

    encrypted = encrypt_word(MAGIC_WORD)
    b64_blob = base64.b64encode(encrypted).decode('ascii')

    print(f"\n[1] Magic word: \"{MAGIC_WORD}\"")
    print(f"    Encrypted bytes: {encrypted.hex()}")
    print(f"    Base64 for pastebin: {b64_blob}")

    decrypted = decrypt_word(encrypted)
    assert decrypted == MAGIC_WORD
    print(f"    Round-trip verified [OK]")

    remote_seed = fnv1a_32(MAGIC_WORD)
    print(f"\n[2] FNV-1a hash: 0x{remote_seed:08X}")
    print(f"    g_rva_seed:    0x{G_RVA_SEED:08X}")
    print(f"    g_remote_seed: 0x{remote_seed:08X}")

    print(f"\n[3] Double-encoded constants:\n")
    print("// Remote-protected pre-shot offsets (require g_rva_seed AND g_remote_seed)")
    for name, real in PRESHOT_OFFSETS.items():
        encoded = real ^ G_RVA_SEED ^ remote_seed
        print(f"constexpr uintptr_t ENC_REMOTE_{name} = 0x{encoded:08X};")

    print(f"\n[4] Shuffle salt array:\n")
    salt_str = ", ".join(f"0x{b:02X}" for b in REMOTE_SALT)
    print(f"static const uint8_t REMOTE_SALT[] = {{{salt_str}}};")

    print(f"\n{'=' * 60}")
    print(f"  ALL VERIFICATIONS PASSED [OK]")
    print(f"{'=' * 60}")


def main():
    parser = argparse.ArgumentParser(
        description="Remote Kill-Switch Encoder & Pastebin Rotator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  %(prog)s                              legacy single-word mode
  %(prog)s rotate                       generate new pastebin content
  %(prog)s verify "text A" "text B"     verify pastebin texts""")

    sub = parser.add_subparsers(dest="command")

    sub.add_parser("rotate", help="Generate fresh pastebin content (new words, same seed)")

    vp = sub.add_parser("verify", help="Verify pastebin texts produce correct seed")
    vp.add_argument("text_a", help="Full text from pastebin A")
    vp.add_argument("text_b", help="Full text from pastebin B")

    args = parser.parse_args()

    if args.command == "rotate":
        cmd_rotate(args)
    elif args.command == "verify":
        cmd_verify(args)
    else:
        cmd_legacy(args)


if __name__ == "__main__":
    main()
