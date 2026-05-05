#!/usr/bin/env python3
"""
Compute obfuscated K1 AND K2 values for the arm64 path of decryptStr().

Both keys are pre-XOR'd with prologue digest bytes (little-endian) at build
time, and restored at runtime by computePrologueDigest(). If a Frida hook
changes any of the 8 protected detection functions, the digest is wrong,
the keys stay obfuscated, and all decrypted strings turn into garbage.

Usage: python compute_k1.py <digest_hex>
  e.g. python compute_k1.py 0x6D0DAE79

K1 obfuscation: K1[i] ^ digest_bytes[i % 4]
K2 obfuscation: K2[i] ^ digest_bytes[(i + 2) % 4]   (rotated index for variety)
K2 is also split into 3 scattered fragments: 2 + 3 + 2 bytes.
"""
import struct
import sys

if len(sys.argv) < 2:
    print("Usage: python compute_k1.py <digest_hex>")
    print("  e.g. python compute_k1.py 0x6D0DAE79")
    sys.exit(1)

digest = int(sys.argv[1], 16)
db = struct.pack('<I', digest)  # little-endian bytes

K1_orig = [0xA3, 0x5F, 0x1D, 0x7E, 0xC4, 0x92, 0x3A, 0xB8, 0x06, 0xE1, 0x4D]
K2_orig = [0x6B, 0xD7, 0x14, 0x8C, 0xF3, 0x29, 0xA5]

K1_obf = [(k ^ db[i % 4]) & 0xFF for i, k in enumerate(K1_orig)]
K2_obf = [(k ^ db[(i + 2) % 4]) & 0xFF for i, k in enumerate(K2_orig)]

print(f"Digest: 0x{digest:08X}")
print(f"LE bytes: {{{', '.join(f'0x{b:02X}' for b in db)}}}")
print()
print("Paste into the #if defined(__aarch64__) block of decryptStr():")
print()
print("  // K1 — pre-XOR'd with digest bytes (LE: " +
      ",".join(f"0x{b:02X}" for b in db) + ")")
print(f"  static uint8_t K1[] = {{{','.join(f'0x{b:02X}' for b in K1_obf)}}};")
print()
print("  // K2 split into 3 fragments, also pre-XOR'd with digest bytes")
print("  // (rotated indexing so K2's pattern looks different from K1's)")
print(f"  static uint8_t K2_p1[] = {{0x{K2_obf[0]:02X}, 0x{K2_obf[1]:02X}}};")
print(f"  static uint8_t K2_p2[] = {{0x{K2_obf[2]:02X}, 0x{K2_obf[3]:02X}, 0x{K2_obf[4]:02X}}};")
print(f"  static uint8_t K2_p3[] = {{0x{K2_obf[5]:02X}, 0x{K2_obf[6]:02X}}};")
print()

# Verify round-trip for both
print("Verification:")
for label, orig, obf, mod in [("K1", K1_orig, K1_obf, lambda i: i % 4),
                              ("K2", K2_orig, K2_obf, lambda i: (i + 2) % 4)]:
    print(f"  {label}:")
    all_ok = True
    for i, (o, n) in enumerate(zip(orig, obf)):
        restored = n ^ db[mod(i)]
        ok = restored == o
        if not ok:
            all_ok = False
        status = 'OK' if ok else 'FAIL'
        print(f"    [{i}]: 0x{n:02X} ^ 0x{db[mod(i)]:02X} = 0x{restored:02X}  (orig 0x{o:02X}) [{status}]")
    print(f"  {label} overall: {'PASS' if all_ok else 'FAIL'}")
