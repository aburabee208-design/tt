#!/usr/bin/env python3
"""
Offset Encoder — Build-time XOR encryption for RVA offsets.

XORs each real offset with a 32-bit BUILD_XOR key so the binary
never contains the real addresses in plaintext.

At runtime, getRVA(encoded) = encoded ^ g_rva_seed
where g_rva_seed is assembled from obfuscated parts after key validation.

Usage:
    python offset_encoder.py                              # Print C++ constants
    python offset_encoder.py --verify                     # Verify round-trip XOR
    python offset_encoder.py --compute-digest <so> <map>  # Recompute PROLOGUE_DIGEST
                                                          # from actual binary prologues,
                                                          # auto-update this script file,
                                                          # and print the delta for
                                                          # patch_enc_constants.py
"""

import os
import re
import struct
import sys
import zlib

# ================================================================
# BUILD-TIME XOR KEY  (32-bit, must match the C++ reconstruction)
# Split into 4 obfuscated parts in the C++ code.
# ================================================================
BUILD_XOR = 0x5A9E37C1

# ================================================================
# PROLOGUE DIGEST  (CRC32 of the 8 detection-function prologues)
# Auto-updated by: python offset_encoder.py --compute-digest <so> <map>
# At runtime, g_rva_seed = assembleRvaSeed() ^ computePrologueDigest()
# So the encoded constants must compensate for the digest.
# WARNING: This value changes when ADVANCED_CONTROLS is toggled!
#          Always re-run --compute-digest after changing build flags.
# ================================================================
PROLOGUE_DIGEST = 0x7B6AC4EB

# Effective XOR = base seed XOR'd with prologue digest
EFFECTIVE_XOR = BUILD_XOR ^ PROLOGUE_DIGEST

# ================================================================
# Real RVA offsets (from il2cpp, arm64-v8a, Jawaker v28.2.78)
# ================================================================
OFFSETS = {
    # Hook RVAs
    "ENC_RVA_POWER_BAR_DRAGGED":       0x50E4D34,
    "ENC_RVA_ROTATE_CUE":              0x50E4414,
    "ENC_RVA_APPLY_SPIN":              0x50E52A4,
    "ENC_RVA_BIH_LATEUPDATE":         0x50D9EB8,
    "ENC_RVA_DROP_BALL_FROM_HAND":     0x50E3A80,
    "ENC_RVA_POOL_SIMULATE":           0x4C79DAC,
    "ENC_RVA_RUSTBRIDGE_SIMULATE_POOL":0x4C79EDC,
    "ENC_RVA_SET_LAST_LOCAL_SHOT_INFO":0x50E7C28,
    # GameStore / JToken
    "ENC_RVA_GAMESTORE_READ":          0x4770238,
    "ENC_RVA_JTOKEN_VALUE_STRING":     0x5F7EF98,
    # BSS metadata
    "ENC_BSS_KEY_ENCRYPTED_PROPS":     0xA7BEEC0,
    "ENC_BSS_KEY_SIGNATURE":           0xA7D2AC0,
    "ENC_BSS_MI_JTOKEN_STRING":        0xA738CD0,
    # Camera
    "ENC_RVA_GET_MAIN_CAMERA":         0x99CB6C4,
    "ENC_RVA_WORLD_TO_SCREEN_POINT":   0x99CAC18,
    "ENC_RVA_GET_PIXEL_HEIGHT":        0x99C9400,
    # Cipher (pre-shot ghost simulation)
    "ENC_RVA_FORMAT_SECRET":           0x5E777D8,
    "ENC_RVA_CIPHER_SEED":             0x839A688,
    "ENC_RVA_CIPHER_ENCRYPT":          0x839B050,
    # Take Shot: PoolGameController.Shoot
    "ENC_RVA_POOL_SHOOT":              0x50E4A38,
}


def encode(real: int) -> int:
    return real ^ EFFECTIVE_XOR


def main():
    verify = "--verify" in sys.argv

    # --- SEED_PARTS reconstruct to BUILD_XOR (prologue digest added at runtime) ---
    # --- ENC_* constants use EFFECTIVE_XOR (BUILD_XOR ^ PROLOGUE_DIGEST) ---
    sb0 = (BUILD_XOR >> 24) & 0xFF
    sb1 = (BUILD_XOR >> 16) & 0xFF
    sb2 = (BUILD_XOR >>  8) & 0xFF
    sb3 = (BUILD_XOR >>  0) & 0xFF

    print("=" * 70)
    print("OFFSET ENCODER — XOR'd RVA Constants")
    print("=" * 70)
    print()
    print(f"// BUILD_XOR         = 0x{BUILD_XOR:08X}  (SEED_PARTS reconstruct to this)")
    print(f"// PROLOGUE_DIGEST   = 0x{PROLOGUE_DIGEST:08X}  (added at runtime by computePrologueDigest)")
    print(f"// EFFECTIVE_XOR     = 0x{EFFECTIVE_XOR:08X}  (BUILD_XOR ^ PROLOGUE_DIGEST — used for ENC_* constants)")
    print()

    # --- Obfuscated seed parts (each byte XOR'd with a positional constant) ---
    # In C++ these are scattered across different variables.
    # To reconstruct: byte[i] ^ PART_MASK[i]
    PART_MASKS = [0x3D, 0xA7, 0x52, 0x8E]
    obf_parts = [b ^ m for b, m in zip([sb0, sb1, sb2, sb3], PART_MASKS)]

    print("// === OBFUSCATED SEED PARTS (paste into native-lib.cpp) ===")
    print(f"// Reconstruction: for each i, real_byte[i] = part[i] ^ mask[i]")
    print(f"static const uint8_t SEED_PARTS[] = {{0x{obf_parts[0]:02X}, 0x{obf_parts[1]:02X}, 0x{obf_parts[2]:02X}, 0x{obf_parts[3]:02X}}};")
    print(f"static const uint8_t SEED_MASKS[] = {{0x{PART_MASKS[0]:02X}, 0x{PART_MASKS[1]:02X}, 0x{PART_MASKS[2]:02X}, 0x{PART_MASKS[3]:02X}}};")
    print()

    print("// === ENCODED RVA OFFSETS (paste into native-lib.cpp) ===")
    print()
    for name, real in OFFSETS.items():
        enc = encode(real)
        print(f"constexpr uintptr_t {name} = 0x{enc:08X};  // real: 0x{real:X}")

    print()

    if verify:
        print("=" * 70)
        print("VERIFICATION (round-trip decode):")
        print("=" * 70)
        all_ok = True
        for name, real in OFFSETS.items():
            enc = encode(real)
            decoded = enc ^ EFFECTIVE_XOR
            ok = decoded == real
            if not ok:
                all_ok = False
            print(f"  {name}: 0x{enc:08X} ^ 0x{EFFECTIVE_XOR:08X} = 0x{decoded:08X} [{('OK' if ok else 'FAIL')}]")

        # Verify seed reconstruction → must equal BUILD_XOR
        # (prologue digest is added at runtime by computePrologueDigest)
        reconstructed = 0
        for i in range(4):
            reconstructed |= ((obf_parts[i] ^ PART_MASKS[i]) << (24 - i * 8))
        seed_ok = reconstructed == BUILD_XOR
        print(f"\n  Seed reconstruction: 0x{reconstructed:08X} == 0x{BUILD_XOR:08X} [{'OK' if seed_ok else 'FAIL'}]")
        print(f"  + prologue digest:   0x{reconstructed:08X} ^ 0x{PROLOGUE_DIGEST:08X} = 0x{reconstructed ^ PROLOGUE_DIGEST:08X} == EFFECTIVE_XOR [{'OK' if (reconstructed ^ PROLOGUE_DIGEST) == EFFECTIVE_XOR else 'FAIL'}]")
        if not seed_ok:
            all_ok = False

        print(f"\n  All checks: {'PASSED' if all_ok else 'FAILED'}")


# ================================================================
# Prologue digest computation from the actual binary
# ================================================================

# Must match the function list in inject_prologues.py and native-lib.cpp
DIGEST_PROTECTED_FUNCTIONS = [
    "checkProcMaps",
    "checkProcFD",
    "checkThreadNames",
    "checkFridaPort",
    "checkRootIndicators",
    "checkLoadedLibraries",
    "checkMemoryCRC",
    "checkInlineHooks",
]
PROLOGUE_SIZE = 16  # 4 ARM64 instructions


def parse_elf_load_segments(data: bytes) -> list:
    """Parse ELF64 LOAD segments to map virtual addresses to file offsets."""
    if data[:4] != b'\x7fELF' or data[4] != 2:
        raise ValueError("Not an ELF64 file")
    e_phoff = struct.unpack_from('<Q', data, 32)[0]
    e_phentsize = struct.unpack_from('<H', data, 54)[0]
    e_phnum = struct.unpack_from('<H', data, 56)[0]
    segments = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type = struct.unpack_from('<I', data, off)[0]
        if p_type != 1:  # PT_LOAD
            continue
        segments.append({
            'vaddr':  struct.unpack_from('<Q', data, off + 16)[0],
            'offset': struct.unpack_from('<Q', data, off + 8)[0],
            'filesz': struct.unpack_from('<Q', data, off + 32)[0],
        })
    return segments


def vaddr_to_file_offset(vaddr: int, segments: list) -> int:
    for seg in segments:
        if seg['vaddr'] <= vaddr < seg['vaddr'] + seg['filesz']:
            return vaddr - seg['vaddr'] + seg['offset']
    raise ValueError(f"vaddr 0x{vaddr:X} not in any LOAD segment")


def parse_map_for_functions(map_path: str, func_names: list) -> dict:
    """Parse a linker map file and return {name: vaddr} for requested functions.
    
    Map format examples:
      52d64  52d64  34c  1  checkProcMaps()
      0x000000000052d64  ...  checkProcMaps
    """
    result = {}
    with open(map_path, 'r', errors='replace') as f:
        for line in f:
            for name in func_names:
                if name in result:
                    continue
                # Match function name (with or without parentheses)
                if re.search(rf'\b{re.escape(name)}\b', line):
                    # Only match .text section (actual code), not .gcc_except_table
                    if '.gcc_except_table' in line or '.eh_frame' in line:
                        continue
                    # Try 0x-prefixed addresses first
                    m = re.search(r'0x([0-9a-fA-F]+)', line)
                    if m:
                        result[name] = int(m.group(1), 16)
                    else:
                        # Column format: first hex number on the line is the vaddr
                        m = re.match(r'\s*([0-9a-fA-F]+)', line)
                        if m:
                            result[name] = int(m.group(1), 16)
    return result


def compute_digest_from_binary(so_path: str, map_path: str) -> int:
    """Read raw prologues from the .so binary and compute CRC32 digest."""
    with open(so_path, 'rb') as f:
        data = f.read()

    segments = parse_elf_load_segments(data)
    func_addrs = parse_map_for_functions(map_path, DIGEST_PROTECTED_FUNCTIONS)

    missing = [n for n in DIGEST_PROTECTED_FUNCTIONS if n not in func_addrs]
    if missing:
        raise ValueError(f"Functions not found in map: {missing}")

    # Concatenate prologues in the same order as computePrologueDigest() in C++
    all_prologues = b""
    for name in DIGEST_PROTECTED_FUNCTIONS:
        vaddr = func_addrs[name]
        file_off = vaddr_to_file_offset(vaddr, segments)
        prologue = data[file_off:file_off + PROLOGUE_SIZE]
        all_prologues += prologue

    return zlib.crc32(all_prologues) & 0xFFFFFFFF


def handle_compute_digest(args: list):
    """--compute-digest <so> <map>: compute CRC32, auto-update this file, print delta."""
    if len(args) < 2:
        print("Usage: offset_encoder.py --compute-digest <path/to/libsystem.so> <path/to/system.map>")
        sys.exit(1)

    so_path, map_path = args[0], args[1]
    new_digest = compute_digest_from_binary(so_path, map_path)
    old_digest = PROLOGUE_DIGEST
    delta = (new_digest ^ old_digest) & 0xFFFFFFFF

    print(f"  OLD PROLOGUE_DIGEST = 0x{old_digest:08X}")
    print(f"  NEW PROLOGUE_DIGEST = 0x{new_digest:08X}")
    print(f"  DELTA               = 0x{delta:08X}")
    print()

    if delta == 0:
        print("  [OK] Digest unchanged — no recalibration needed.")
        return

    # Auto-update PROLOGUE_DIGEST in this script file
    script_path = os.path.abspath(__file__)
    with open(script_path, 'r', encoding='utf-8') as f:
        content = f.read()

    old_line = f"PROLOGUE_DIGEST = 0x{old_digest:08X}"
    new_line = f"PROLOGUE_DIGEST = 0x{new_digest:08X}"
    if old_line not in content:
        print(f"  [WARN] Could not find '{old_line}' in {script_path} — manual update needed.")
    else:
        content = content.replace(old_line, new_line)
        with open(script_path, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"  [OK] Auto-updated {os.path.basename(script_path)}: {old_line} -> {new_line}")

    print()
    print(f"  ┌─────────────────────────────────────────────────────────────────┐")
    print(f"  │  RECALIBRATION REQUIRED — run these commands:                   │")
    print(f"  │                                                                 │")
    print(f"  │  1. python patch_enc_constants.py 0x{delta:08X} native-lib.cpp  │")
    print(f"  │  2. Update K1 in decryptStr() (use compute_digest.py)           │")
    print(f"  │  3. Rebuild + re-inject prologues + re-inject hash              │")
    print(f"  └─────────────────────────────────────────────────────────────────┘")


if __name__ == "__main__":
    if "--compute-digest" in sys.argv:
        idx = sys.argv.index("--compute-digest")
        handle_compute_digest(sys.argv[idx + 1:])
    else:
        main()
