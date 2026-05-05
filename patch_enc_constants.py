#!/usr/bin/env python3
"""
Patch all ENC_ constants in native-lib.cpp by XOR'ing their hex values
with the prologue digest. This compensates for the prologue digest
being folded into g_rva_seed at runtime.

Usage: python patch_enc_constants.py <digest_hex> <cpp_file>
"""
import re
import sys

def main():
    if len(sys.argv) < 3:
        print("Usage: python patch_enc_constants.py <digest_hex> <cpp_file>")
        sys.exit(1)
    
    digest = int(sys.argv[1], 16)
    cpp_path = sys.argv[2]
    
    with open(cpp_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    # Pattern: constexpr uintptr_t ENC_xxx = 0xHEXVALUE;
    pattern = re.compile(
        r'^(\s*constexpr\s+uintptr_t\s+ENC_\w+\s*=\s*)0x([0-9A-Fa-f]+)(\s*;.*)$'
    )
    
    count = 0
    for i, line in enumerate(lines):
        m = pattern.match(line)
        if m:
            prefix = m.group(1)
            old_val = int(m.group(2), 16)
            suffix = m.group(3)
            new_val = old_val ^ digest
            old_hex = f"0x{old_val:08X}"
            new_hex = f"0x{new_val:08X}"
            lines[i] = f"{prefix}{new_hex}{suffix}\n"
            print(f"  L{i+1}: {old_hex} -> {new_hex}")
            count += 1
    
    with open(cpp_path, 'w', encoding='utf-8') as f:
        f.writelines(lines)
    
    print(f"\n  [OK] Patched {count} ENC_ constants with digest 0x{digest:08X}")

if __name__ == '__main__':
    main()
