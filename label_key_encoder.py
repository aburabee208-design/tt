#!/usr/bin/env python3
"""
Label Key Encoder — Build-time encoder for the ON/OFF crash-on-tamper system.

Pipeline:
  1. V1 = PROLOGUE_DIGEST  (read live from offset_encoder.py — same value the C++
                            computePrologueDigest() will produce at runtime)
  2. V2 = FNV-1a fold of all entries in the C++ ALLOWED_LIBS whitelist
                           (parsed live from native-lib.cpp — same value the C++
                            computeLibsFingerprint() will produce at runtime,
                            assuming the device has exactly the expected .so set)
  3. P1, P2, P3 = three 32-bit coefficients stored on a Pastebin URL
                  (randomized every rotation; copy the printed line into Pastebin)
  4. K = customMix(V1, V2, P1, P2, P3)     — 8-round ARX permutation, distinct
                                              from mixHash() so a reverser has
                                              two different chains to analyse
  5. ENC_LABEL_OFFSET_ON  = 0 ^ K          — "ON"  starts at offset 0 in g_labels_table
     ENC_LABEL_OFFSET_OFF = 3 ^ K          — "OFF" starts at offset 3 in g_labels_table

If anything is tampered (binary patched -> wrong V1; extra .so injected -> wrong V2;
pastebin gone -> P1/P2/P3 missing), runtime K does not match build-time K, the offset
XOR produces a wild 32-bit value, g_labels_table + wild_offset is unmapped memory,
and NewStringUTF SIGSEGVs inside libart.so.

Commands:
  python label_key_encoder.py --compute                           Compute K and patch source
  python label_key_encoder.py --rotate                            Generate fresh P1/P2/P3, then --compute
  python label_key_encoder.py --verify                            Verify source offsets decode correctly
  python label_key_encoder.py --print-pastebin                    Print just the Pastebin line
  python label_key_encoder.py --test                              Self-test the equation
"""

import os
import re
import secrets
import sys

# ================================================================
# PATHS
# ================================================================
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
NATIVE_LIB_CPP    = os.path.join(SCRIPT_DIR, "app", "src", "main", "cpp", "native-lib.cpp")
OFFSET_ENCODER_PY = os.path.join(SCRIPT_DIR, "offset_encoder.py")

# ================================================================
# COEFFICIENTS — rotate via --rotate when desired.
# These are written into the script body so subsequent --compute / --verify
# runs use the same values until the next rotation.
# ================================================================
COEFF_P1 = 0x7B19E4A2
COEFF_P2 = 0xCD4083F1
COEFF_P3 = 0x2856FA0D

# ================================================================
# LABEL TABLE LAYOUT — must match g_labels_table[] in native-lib.cpp
# ================================================================
LABELS_TABLE        = b"ON\x00OFF\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"  # 16 bytes
LABEL_OFFSET_ON     = 0
LABEL_OFFSET_OFF    = 3

# ================================================================
# Bit math helpers
# ================================================================
M32 = 0xFFFFFFFF
M64 = 0xFFFFFFFFFFFFFFFF


def extend_key(K):
    """
    Mirror of C++ extendLabelKey() — extends 32-bit K into a 64-bit ext_K.
    The encoded label offsets are (real_offset ^ extend_key(K_build)) so the
    decryption at runtime XORs with extend_key(K_runtime). When K=0 (fresh
    install + dead pastebin + no cache), ext_K=0 and the decoded offset is
    a fully random 64-bit value -> SIGSEGV when dereferenced via JNI.
    """
    K &= M32
    high = K
    high ^= (high >> 16)
    high  = (high * 0x85EBCA6B) & M32
    high ^= (high >> 13)
    high  = (high * 0xC2B2AE35) & M32
    high ^= (high >> 16)
    return ((high << 32) | K) & M64


def rotl(x, n):
    n &= 31
    return ((x << n) | (x >> (32 - n))) & M32


def rotr(x, n):
    n &= 31
    return ((x >> n) | (x << (32 - n))) & M32


# ================================================================
# THE EQUATION — must match computeLabelKey() in native-lib.cpp
# ================================================================
def compute_label_key(V1, V2, P1, P2, P3):
    """
    8-round ARX permutation over a 4-word state.
    Distinct shape from mixHash() so reversers must analyse a second chain.
    """
    s0 = (V1 ^ 0x6A09E667) & M32
    s1 = (V2 ^ 0xBB67AE85) & M32
    s2 = (P1 ^ 0x3C6EF372) & M32
    s3 = (P2 ^ 0xA54FF53A) & M32

    for r in range(8):
        rc = (P3 + r * 0x9E3779B1) & M32

        # Mixing block A
        s0 = (s0 + s1 + rc) & M32
        s3 = rotl(s3 ^ s0, 16)
        s2 = (s2 + s3) & M32
        s1 = rotl(s1 ^ s2, 12)

        # Mixing block B (different rotation amounts)
        s0 = (s0 + s1) & M32
        s3 = rotl(s3 ^ s0, 8)
        s2 = (s2 + s3) & M32
        s1 = rotl(s1 ^ s2, 7)

        # Diagonal swap — alternates per round so each round disassembles differently
        if r & 1:
            s0, s2 = s2, s0
        else:
            s1, s3 = s3, s1

    # Final compression — murmur-style finalizer for extra avalanche
    K = (s0 ^ s1 ^ s2 ^ s3) & M32
    K = (K ^ (K >> 16)) & M32
    K = (K * 0x85EBCA6B) & M32
    K = (K ^ (K >> 13)) & M32
    K = (K * 0xC2B2AE35) & M32
    K = (K ^ (K >> 16)) & M32
    return K


# ================================================================
# Read PROLOGUE_DIGEST from offset_encoder.py (= V1)
# ================================================================
def read_prologue_digest():
    with open(OFFSET_ENCODER_PY, "r", encoding="utf-8") as f:
        for line in f:
            m = re.match(r'^\s*PROLOGUE_DIGEST\s*=\s*(0x[0-9A-Fa-f]+)', line)
            if m:
                return int(m.group(1), 16)
    print("ERROR: PROLOGUE_DIGEST not found in offset_encoder.py")
    sys.exit(1)


# ================================================================
# Parse ALLOWED_LIBS list out of native-lib.cpp and FNV-1a-fold them (= V2)
#
# This MUST match the runtime computation done by computeLibsFingerprint()
# in native-lib.cpp. Both walk the same list, hash each name with FNV-1a
# (32-bit, FNV_offset 0x811C9DC5, FNV_prime 0x01000193 — identical to
# isAllowedLib's hash), then XOR-fold all hashes into one 32-bit accumulator.
# Order independence: XOR is commutative, so readdir() ordering doesn't matter.
# ================================================================
def fnv1a_32(name: str) -> int:
    h = 0x811C9DC5
    for c in name.encode('ascii'):
        h ^= c
        h = (h * 0x01000193) & M32
    return h


def parse_allowed_libs():
    """Return the list of .so filenames whose FNV-1a-of-basename is whitelisted."""
    with open(NATIVE_LIB_CPP, "r", encoding="utf-8") as f:
        source = f.read()

    # Find the ALLOWED_LIBS array. We accept any of the common shapes:
    #   static constexpr uint32_t ALLOWED_LIBS[] = { fnv1a("libfoo.so"), ... };
    # Just grep all fnv1a("...") patterns in the relevant region.
    m = re.search(
        r'ALLOWED_LIBS\s*\[\s*\]\s*=\s*\{(.*?)\}\s*;',
        source, re.DOTALL
    )
    if not m:
        print("ERROR: ALLOWED_LIBS array not found in native-lib.cpp")
        sys.exit(1)

    body = m.group(1)
    names = re.findall(r'fnv1a\(\s*"([^"]+)"\s*\)', body)
    if not names:
        print("ERROR: no fnv1a(\"...\") entries inside ALLOWED_LIBS")
        sys.exit(1)
    return names


def compute_libs_fingerprint(lib_names):
    """XOR-fold the FNV-1a of each name. Order-independent (matches C++ readdir)."""
    fold = 0
    for name in lib_names:
        fold ^= fnv1a_32(name)
    return fold


# ================================================================
# Patch encoded offsets into native-lib.cpp between markers
# ================================================================
START_MARKER = "// LABEL_KEY_ENCODER_MARKER_START"
END_MARKER   = "// LABEL_KEY_ENCODER_MARKER_END"


def patch_source(K):
    ext_K = extend_key(K)
    enc_on  = (LABEL_OFFSET_ON  ^ ext_K) & M64
    enc_off = (LABEL_OFFSET_OFF ^ ext_K) & M64

    with open(NATIVE_LIB_CPP, "r", encoding="utf-8") as f:
        source = f.read()

    start = source.find(START_MARKER)
    end   = source.find(END_MARKER)
    if start < 0 or end < 0:
        print(f"ERROR: markers not found in native-lib.cpp")
        print(f"  Add this block once, then re-run:")
        print(f"    {START_MARKER}")
        print(f"    static constexpr uint64_t ENC_LABEL_OFFSET_ON  = 0x0000000000000000ull;")
        print(f"    static constexpr uint64_t ENC_LABEL_OFFSET_OFF = 0x0000000000000000ull;")
        print(f"    {END_MARKER}")
        sys.exit(1)

    block = (
        f"{START_MARKER}\r\n"
        f"static constexpr uint64_t ENC_LABEL_OFFSET_ON  = 0x{enc_on:016X}ull;\r\n"
        f"static constexpr uint64_t ENC_LABEL_OFFSET_OFF = 0x{enc_off:016X}ull;\r\n"
        f"{END_MARKER}"
    )

    new_source = source[:start] + block + source[end + len(END_MARKER):]
    with open(NATIVE_LIB_CPP, "w", encoding="utf-8") as f:
        f.write(new_source)

    print(f"  ext_K (64-bit)               = 0x{ext_K:016X}")
    print(f"  Patched ENC_LABEL_OFFSET_ON  = 0x{enc_on:016X}")
    print(f"  Patched ENC_LABEL_OFFSET_OFF = 0x{enc_off:016X}")


def patch_self_coefficients(P1, P2, P3):
    """Update COEFF_P1/P2/P3 in this script file (so --verify uses the same values)."""
    script_path = os.path.abspath(__file__)
    with open(script_path, "r", encoding="utf-8") as f:
        content = f.read()

    for name, val in [("COEFF_P1", P1), ("COEFF_P2", P2), ("COEFF_P3", P3)]:
        new_line = f"{name} = 0x{val:08X}"
        content = re.sub(
            rf'^{name}\s*=\s*0x[0-9A-Fa-f]+\s*$',
            new_line,
            content,
            count=1,
            flags=re.MULTILINE,
        )

    with open(script_path, "w", encoding="utf-8") as f:
        f.write(content)


# ================================================================
# Commands
# ================================================================
def gather_inputs():
    V1 = read_prologue_digest()
    lib_names = parse_allowed_libs()
    V2 = compute_libs_fingerprint(lib_names)
    return V1, V2, lib_names


def cmd_compute():
    print("=== Label Key Encoder: --compute ===")
    V1, V2, lib_names = gather_inputs()
    print(f"  V1 (PROLOGUE_DIGEST):    0x{V1:08X}")
    print(f"  V2 (libs fingerprint):   0x{V2:08X}  [{len(lib_names)} libs]")
    for n in lib_names:
        print(f"      fnv1a(\"{n}\") = 0x{fnv1a_32(n):08X}")
    print(f"  P1: 0x{COEFF_P1:08X}")
    print(f"  P2: 0x{COEFF_P2:08X}")
    print(f"  P3: 0x{COEFF_P3:08X}")

    K = compute_label_key(V1, V2, COEFF_P1, COEFF_P2, COEFF_P3)
    print(f"  K  (label key):          0x{K:08X}")
    print()

    patch_source(K)
    print()
    print(f"  Pastebin content (paste into the URL pointed to by E_RURL_LABELS):")
    print(f"    {COEFF_P1:08X},{COEFF_P2:08X},{COEFF_P3:08X}")


def cmd_rotate():
    print("=== Label Key Encoder: --rotate ===")
    P1 = secrets.randbits(32)
    P2 = secrets.randbits(32)
    P3 = secrets.randbits(32)
    print(f"  New P1: 0x{P1:08X}")
    print(f"  New P2: 0x{P2:08X}")
    print(f"  New P3: 0x{P3:08X}")

    patch_self_coefficients(P1, P2, P3)

    # Reload to make --compute use the new values in this same run
    global COEFF_P1, COEFF_P2, COEFF_P3
    COEFF_P1, COEFF_P2, COEFF_P3 = P1, P2, P3

    print()
    cmd_compute()


def cmd_verify():
    print("=== Label Key Encoder: --verify ===")
    V1, V2, _ = gather_inputs()
    K = compute_label_key(V1, V2, COEFF_P1, COEFF_P2, COEFF_P3)
    ext_K = extend_key(K)
    print(f"  Recomputed K     = 0x{K:08X}")
    print(f"  Recomputed ext_K = 0x{ext_K:016X}")

    with open(NATIVE_LIB_CPP, "r", encoding="utf-8") as f:
        source = f.read()
    start = source.find(START_MARKER)
    end   = source.find(END_MARKER)
    if start < 0 or end < 0:
        print("  ERROR: markers not found")
        return False
    region = source[start:end]
    on_match  = re.search(r'ENC_LABEL_OFFSET_ON\s*=\s*0x([0-9A-Fa-f]+)',  region)
    off_match = re.search(r'ENC_LABEL_OFFSET_OFF\s*=\s*0x([0-9A-Fa-f]+)', region)
    if not (on_match and off_match):
        print("  ERROR: encoded offsets not found in marker region")
        return False

    enc_on  = int(on_match.group(1),  16)
    enc_off = int(off_match.group(1), 16)
    dec_on  = enc_on  ^ ext_K
    dec_off = enc_off ^ ext_K

    ok_on  = dec_on  == LABEL_OFFSET_ON
    ok_off = dec_off == LABEL_OFFSET_OFF

    print(f"  ENC_LABEL_OFFSET_ON   = 0x{enc_on:016X}  ^ ext_K = 0x{dec_on:016X}  expected 0x{LABEL_OFFSET_ON:016X}  [{'OK' if ok_on else 'FAIL'}]")
    print(f"  ENC_LABEL_OFFSET_OFF  = 0x{enc_off:016X}  ^ ext_K = 0x{dec_off:016X}  expected 0x{LABEL_OFFSET_OFF:016X}  [{'OK' if ok_off else 'FAIL'}]")

    if ok_on and ok_off:
        print("  VERIFIED")
        return True
    else:
        print("  FAILED — re-run --compute")
        return False


def cmd_print_pastebin():
    print(f"{COEFF_P1:08X},{COEFF_P2:08X},{COEFF_P3:08X}")


def cmd_test():
    """Self-test: avalanche, determinism, sensitivity to each input."""
    print("=== Label Key Encoder: --test ===")
    fails = 0

    # Determinism
    a = compute_label_key(0x12345678, 0x87654321, COEFF_P1, COEFF_P2, COEFF_P3)
    b = compute_label_key(0x12345678, 0x87654321, COEFF_P1, COEFF_P2, COEFF_P3)
    print(f"  [1] Deterministic: 0x{a:08X} == 0x{b:08X} -> {'OK' if a == b else 'FAIL'}")
    if a != b:
        fails += 1

    # Avalanche on each input
    base = compute_label_key(0x12345678, 0x87654321, 0xAAAAAAAA, 0xBBBBBBBB, 0xCCCCCCCC)
    for label, args in [
        ("V1 +1bit", (0x12345679, 0x87654321, 0xAAAAAAAA, 0xBBBBBBBB, 0xCCCCCCCC)),
        ("V2 +1bit", (0x12345678, 0x87654320, 0xAAAAAAAA, 0xBBBBBBBB, 0xCCCCCCCC)),
        ("P1 +1bit", (0x12345678, 0x87654321, 0xAAAAAAAB, 0xBBBBBBBB, 0xCCCCCCCC)),
        ("P2 +1bit", (0x12345678, 0x87654321, 0xAAAAAAAA, 0xBBBBBBBA, 0xCCCCCCCC)),
        ("P3 +1bit", (0x12345678, 0x87654321, 0xAAAAAAAA, 0xBBBBBBBB, 0xCCCCCCCD)),
    ]:
        flipped = compute_label_key(*args)
        bits = bin(base ^ flipped).count("1")
        ok = bits >= 12  # any decent mixer flips ~16 bits per single input bit
        print(f"  [2] Avalanche {label}: {bits}/32 bits flipped -> {'OK' if ok else 'WEAK'}")
        if not ok:
            fails += 1

    # XOR round-trip on offsets
    K = compute_label_key(0xDEADBEEF, 0xCAFEBABE, COEFF_P1, COEFF_P2, COEFF_P3)
    rt_on  = (LABEL_OFFSET_ON  ^ K) ^ K
    rt_off = (LABEL_OFFSET_OFF ^ K) ^ K
    ok_rt = rt_on == LABEL_OFFSET_ON and rt_off == LABEL_OFFSET_OFF
    print(f"  [3] Offset round-trip: {'OK' if ok_rt else 'FAIL'}")
    if not ok_rt:
        fails += 1

    print(f"\n  {'ALL TESTS PASSED' if fails == 0 else f'{fails} TEST(S) FAILED'}")
    return fails == 0


# ================================================================
# CLI
# ================================================================
def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(0)

    cmd = sys.argv[1]
    if cmd == "--compute":
        cmd_compute()
    elif cmd == "--rotate":
        cmd_rotate()
    elif cmd == "--verify":
        ok = cmd_verify()
        sys.exit(0 if ok else 1)
    elif cmd == "--print-pastebin":
        cmd_print_pastebin()
    elif cmd == "--test":
        ok = cmd_test()
        sys.exit(0 if ok else 1)
    else:
        print(f"Unknown command: {cmd}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
