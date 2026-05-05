#!/usr/bin/env python3
"""
inject_hash.py — Post-build hash injection ("push bytes")

Run AFTER compiling libsystem.so. This script:
1. Reads the .so binary
2. Finds ALL integrity markers (MARKER_1 and MARKER_2)
3. Zeros all hash fields
4. Computes SHA-256 of the entire file (with all hashes zeroed)
5. Writes the SAME SHA-256 into each hash field
6. Saves the patched .so

Usage:
    python inject_hash.py                                    # patches arm64-v8a
    python inject_hash.py path/to/libsystem.so               # patch a specific file
    python inject_hash.py --verify path/to/libsystem.so      # verify without patching
"""

import hashlib
import sys
import os

# Must match INTEGRITY_MARKER / INTEGRITY_MARKER_2 in native-lib.cpp exactly
MARKERS = [
    {
        "name": "MARKER_1",
        "bytes": bytes([
            0x7E, 0x4A, 0x57, 0x4B, 0x53, 0x59, 0x53, 0x48,
            0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18
        ]),
    },
    {
        "name": "MARKER_2",
        "bytes": bytes([
            0xD3, 0x19, 0x6C, 0x82, 0xAF, 0x4E, 0x71, 0x5B,
            0x93, 0xE7, 0x28, 0xFC, 0x3A, 0x84, 0xB6, 0x0D
        ]),
    },
]
HASH_SIZE = 32  # SHA-256 = 32 bytes

# Default path (arm64-v8a debug build)
DEFAULT_SO = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "app", "build", "intermediates", "cxx", "Debug",
    "4n63m5ky", "obj", "arm64-v8a", "libsystem.so"
)


def find_all_markers(data: bytes) -> list:
    """Find all markers in the binary. Returns list of (name, offset)."""
    results = []
    for m in MARKERS:
        idx = data.find(m["bytes"])
        if idx == -1:
            continue
        if idx + len(m["bytes"]) + HASH_SIZE > len(data):
            continue
        results.append((m["name"], idx, len(m["bytes"])))
    return results


def inject(so_path: str, verify_only: bool = False) -> bool:
    """Inject SHA-256 into the .so file (or verify existing hashes)."""
    with open(so_path, "rb") as f:
        data = bytearray(f.read())

    found = find_all_markers(bytes(data))
    if not found:
        print(f"ERROR: No integrity markers found in {so_path}")
        return False

    print(f"  Found {len(found)} marker(s):")
    for name, off, mlen in found:
        hash_off = off + mlen
        stored = bytes(data[hash_off:hash_off + HASH_SIZE])
        print(f"    {name} at 0x{off:X}, hash at 0x{hash_off:X}: {stored.hex()[:32]}...")

    if len(found) != len(MARKERS):
        missing = set(m["name"] for m in MARKERS) - set(name for name, _, _ in found)
        print(f"  WARNING: Missing markers: {', '.join(missing)}")

    if verify_only:
        # Zero all hash fields, compute SHA-256, compare each
        for _, off, mlen in found:
            data[off + mlen:off + mlen + HASH_SIZE] = b'\x00' * HASH_SIZE
        computed = hashlib.sha256(bytes(data)).digest()
        print(f"  Computed SHA-256: {computed.hex()}")

        # Re-read original to get stored hashes
        with open(so_path, "rb") as f:
            orig = f.read()
        all_ok = True
        for name, off, mlen in found:
            stored = orig[off + mlen:off + mlen + HASH_SIZE]
            if stored == computed:
                print(f"    {name}: [OK] matches")
            elif stored == b'\x00' * HASH_SIZE:
                print(f"    {name}: [WARN] not yet injected (all zeros)")
                all_ok = False
            else:
                print(f"    {name}: [FAIL] mismatch!")
                print(f"      stored:   {stored.hex()}")
                print(f"      computed: {computed.hex()}")
                all_ok = False
        return all_ok

    # --- Injection mode ---
    # Step 1: Zero ALL hash fields
    for _, off, mlen in found:
        data[off + mlen:off + mlen + HASH_SIZE] = b'\x00' * HASH_SIZE

    # Step 2: Compute SHA-256 of the entire file (with all hashes zeroed)
    computed = hashlib.sha256(bytes(data)).digest()
    print(f"  Computed SHA-256: {computed.hex()}")

    # Step 3: Write the SAME hash into each hash field
    for name, off, mlen in found:
        data[off + mlen:off + mlen + HASH_SIZE] = computed
        print(f"    {name}: hash injected")

    # Step 4: Save
    with open(so_path, "wb") as f:
        f.write(data)
    print(f"  [OK] Hashes injected into {os.path.basename(so_path)}")

    # Step 5: Verify round-trip
    with open(so_path, "rb") as f:
        verify_data = bytearray(f.read())
    for _, off, mlen in found:
        verify_data[off + mlen:off + mlen + HASH_SIZE] = b'\x00' * HASH_SIZE
    verify_hash = hashlib.sha256(bytes(verify_data)).digest()
    if verify_hash == computed:
        print("  [OK] Round-trip verification PASSED")
    else:
        print("  [FAIL] Round-trip verification FAILED!")
        return False

    return True


def main():
    verify_only = "--verify" in sys.argv
    args = [a for a in sys.argv[1:] if a != "--verify"]

    if args:
        so_path = args[0]
    else:
        so_path = DEFAULT_SO

    if not os.path.isfile(so_path):
        print(f"ERROR: File not found: {so_path}")
        print(f"  Build the project first with: gradlew assembleDebug")
        sys.exit(1)

    print(f"{'Verifying' if verify_only else 'Injecting hashes into'}: {so_path}")
    print(f"  File size: {os.path.getsize(so_path):,} bytes")

    success = inject(so_path, verify_only)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
