#!/usr/bin/env python3
"""
Jawaker CHETO -- Key Generator (Level 3: HWID-bound + timestamps + base36 checksum)

Key format: CCCC-EEEE-RRRR-HHHH
  Slot 1 (CCCC): Creation time -- hours since 2024-01-01 UTC, base36
  Slot 2 (EEEE): Expiry time   -- hours since 2024-01-01 UTC, base36
  Slot 3 (RRRR): Random salt for uniqueness
  Slot 4 (HHHH): Base36 checksum (FNV-1a hash % 1679616)

Usage:
  python keygen.py gen <device_id> [--count N] [--days D] [--hours H]
  python keygen.py check <key> [device_id]

Examples:
  python keygen.py gen abc123def456                     # 30-day key (default)
  python keygen.py gen abc123def456 --days 7            # 7-day key
  python keygen.py gen abc123def456 --hours 12          # 12-hour key
  python keygen.py gen abc123def456 --days 1 --hours 6  # 1 day + 6 hours
  python keygen.py gen abc123def456 --hours 1           # 1-hour key (testing)
  python keygen.py gen abc123def456 --count 5 --days 7  # 5 keys, 7 days each
  python keygen.py check XXXX-XXXX-XXXX-XXXX            # check expiry only
  python keygen.py check XXXX-XXXX-XXXX-XXXX abc123     # check expiry + HWID
"""

import sys
import random
import string
import argparse
from datetime import datetime, timezone, timedelta

# ── Constants (must match native-lib.cpp exactly) ─────────────────────────────
KEY_EPOCH    = 1704067200  # 2024-01-01 00:00:00 UTC
SECRET_SALT  = b"JwkrCh3t0_2026"
BASE36_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
BUILD_XOR    = 0x5A9E37C1


# ── Core functions ────────────────────────────────────────────────────────────

def encode_base36(value: int, length: int = 4) -> str:
    result = []
    for _ in range(length):
        result.append(BASE36_CHARS[value % 36])
        value //= 36
    return ''.join(reversed(result))


def decode_base36(s: str) -> int:
    result = 0
    for c in s.upper():
        if '0' <= c <= '9':
            digit = ord(c) - ord('0')
        elif 'A' <= c <= 'Z':
            digit = ord(c) - ord('A') + 10
        else:
            raise ValueError(f"Invalid base36 character: {c}")
        result = result * 36 + digit
    return result


def fnv1a_hash(data: bytes, device_id: str) -> int:
    h = 0x811C9DC5
    for b in data:
        h ^= b
        h = (h * 0x01000193) & 0xFFFFFFFF
    for b in SECRET_SALT:
        h ^= b
        h = (h * 0x01000193) & 0xFFFFFFFF
    for c in device_id:
        h ^= ord(c)
        h = (h * 0x01000193) & 0xFFFFFFFF
    h ^= (h >> 16)
    h = (h * 0x45D9F3B) & 0xFFFFFFFF
    h ^= (h >> 16)
    return h


def format_duration(td: timedelta) -> str:
    """Format a timedelta as a human-readable string."""
    total = int(td.total_seconds())
    if total <= 0:
        return "0m"
    days    = total // 86400
    hours   = (total % 86400) // 3600
    minutes = (total % 3600) // 60
    parts = []
    if days:    parts.append(f"{days}d")
    if hours:   parts.append(f"{hours}h")
    if minutes: parts.append(f"{minutes}m")
    return ' '.join(parts) if parts else "<1m"


# ── Key generation ────────────────────────────────────────────────────────────

def generate_key(device_id: str, expiry_hours: float) -> dict:
    now = datetime.now(timezone.utc)
    expiry = now + timedelta(hours=expiry_hours)

    create_h = int((now.timestamp() - KEY_EPOCH) / 3600)
    expiry_h = int((expiry.timestamp() - KEY_EPOCH) / 3600)

    # Ensure at least 1 hour difference so the key isn't instantly expired
    if expiry_h <= create_h:
        expiry_h = create_h + 1

    slot1 = encode_base36(create_h)
    slot2 = encode_base36(expiry_h)
    slot3 = ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))

    payload = slot1 + slot2 + slot3
    h = fnv1a_hash(payload.encode('ascii'), device_id)
    slot4 = encode_base36(h % 1679616)

    key = f"{slot1}-{slot2}-{slot3}-{slot4}"

    return {
        "key":       key,
        "created":   now,
        "expires":   expiry,
        "duration":  timedelta(hours=expiry_hours),
        "device_id": device_id,
    }


# ── Key validation ────────────────────────────────────────────────────────────

def validate_key(key: str, device_id: str = None) -> dict:
    clean = key.replace("-", "").upper()
    if len(clean) != 16:
        return {"status": "invalid", "message": "Bad format (need 16 chars)"}

    slot1, slot2, slot3, slot4 = clean[0:4], clean[4:8], clean[8:12], clean[12:16]

    # Checksum validation (requires device_id)
    if device_id:
        payload = slot1 + slot2 + slot3
        h = fnv1a_hash(payload.encode('ascii'), device_id)
        expected = encode_base36(h % 1679616)
        if slot4 != expected:
            return {"status": "invalid", "message": "Bad checksum (wrong device?)"}

    # Time validation
    now = datetime.now(timezone.utc)
    create_hours = decode_base36(slot1)
    expiry_hours = decode_base36(slot2)
    created_at = datetime.fromtimestamp(KEY_EPOCH + create_hours * 3600, tz=timezone.utc)
    expires_at = datetime.fromtimestamp(KEY_EPOCH + expiry_hours * 3600, tz=timezone.utc)
    remaining  = expires_at - now
    total_dur  = expires_at - created_at

    if remaining.total_seconds() <= 0:
        return {
            "status":  "expired",
            "message": "Key has expired",
            "created": created_at,
            "expires": expires_at,
            "total":   format_duration(total_dur),
        }

    return {
        "status":    "valid",
        "message":   f"Valid -- {format_duration(remaining)} remaining",
        "created":   created_at,
        "expires":   expires_at,
        "remaining": format_duration(remaining),
        "total":     format_duration(total_dur),
    }


# ── CLI ───────────────────────────────────────────────────────────────────────

DECOY_SALT = b"D3c0yK3y_2026"

def decoy_checksum(data: str) -> str:
    """FNV-1a checksum for decoy keys (different salt than real keys)."""
    h = 0x811C9DC5
    for c in data:
        h ^= ord(c)
        h = (h * 0x01000193) & 0xFFFFFFFF
    for b in DECOY_SALT:
        h ^= b
        h = (h * 0x01000193) & 0xFFFFFFFF
    h ^= (h >> 16)
    h = (h * 0x45D9F3B) & 0xFFFFFFFF
    h ^= (h >> 16)
    return encode_base36(h % 1679616, 4)


def generate_decoy() -> str:
    """Generate a decoy key with checksum: RRRR-RRRR-RRRR-CCCC."""
    chars = string.ascii_uppercase + string.digits
    s1 = ''.join(random.choices(chars, k=4))
    s2 = ''.join(random.choices(chars, k=4))
    s3 = ''.join(random.choices(chars, k=4))
    s4 = decoy_checksum(s1 + s2 + s3)
    return f"{s1}-{s2}-{s3}-{s4}"


def cmd_gen(args):
    total_hours = (args.days * 24) + args.hours
    if total_hours <= 0:
        print("  Error: duration must be > 0. Use --days and/or --hours.")
        sys.exit(1)

    # Format the duration label
    parts = []
    if args.days:  parts.append(f"{args.days}d")
    if args.hours: parts.append(f"{args.hours}h")
    dur_label = ' '.join(parts) if parts else f"{total_hours}h"

    pool = args.pool
    shootit = args.shootit

    print()
    print(f"  Device:   {args.device_id}")
    print(f"  Duration: {dur_label}")
    print(f"  Count:    {args.count}")
    print(f"  Pool:     {'enabled' if pool else 'disabled'}")
    print(f"  ShootIt:  {'enabled' if shootit else 'disabled'}")
    print(f"  {'-' * 50}")

    for i in range(args.count):
        info = generate_key(args.device_id, total_hours)
        decoy = generate_decoy()
        exp_str = info["expires"].strftime("%Y-%m-%d %H:%M UTC")
        dur_str = format_duration(info["duration"])
        pb_line = f"{args.device_id},{info['key']},pool={'1' if pool else '0'},shootit={'1' if shootit else '0'}"

        print(f"  Real key:  {info['key']}   expires: {exp_str}  ({dur_str})")
        print(f"  Decoy key: {decoy}   (give this to user)")
        print(f"  Pastebin:  {pb_line}")
        if args.count > 1 and i < args.count - 1:
            print(f"  {'-' * 50}")

    print()


def cmd_gen_decoy(args):
    """Generate random decoy keys (no cryptographic value)."""
    print()
    print(f"  Generating {args.count} decoy key(s):")
    print(f"  {'-' * 30}")
    for _ in range(args.count):
        print(f"  {generate_decoy()}")
    print()


def cmd_gen_public(args):
    """Generate a public/gift key (uses '*' as device_id)."""
    total_hours = (args.days * 24) + args.hours
    if total_hours <= 0:
        print("  Error: duration must be > 0. Use --days and/or --hours.")
        sys.exit(1)

    parts = []
    if args.days:  parts.append(f"{args.days}d")
    if args.hours: parts.append(f"{args.hours}h")
    dur_label = ' '.join(parts) if parts else f"{total_hours}h"

    pool = not args.no_pool
    shootit = not args.no_shootit

    print()
    print(f"  Type:     PUBLIC (gift key for all users)")
    print(f"  Duration: {dur_label}")
    print(f"  Pool:     {'enabled' if pool else 'disabled'}")
    print(f"  ShootIt:  {'enabled' if shootit else 'disabled'}")
    print(f"  {'-' * 50}")

    # Generate key with "*" as device_id (checksum will use "*")
    info = generate_key("*", total_hours)
    exp_str = info["expires"].strftime("%Y-%m-%d %H:%M UTC")
    dur_str = format_duration(info["duration"])
    pb_line = f"*,{info['key']},pool={'1' if pool else '0'},shootit={'1' if shootit else '0'}"

    print(f"  Public key: {info['key']}   expires: {exp_str}  ({dur_str})")
    print(f"  Pastebin:   {pb_line}")
    print()
    print(f"  Add the Pastebin line to your remote config pastebin.")
    print(f"  All users entering any decoy key will get access.")
    print()


def cmd_check(args):
    key = args.key
    device_id = args.device_id  # may be None

    result = validate_key(key, device_id)

    print()
    print(f"  Key:      {key}")

    if result["status"] == "invalid":
        print(f"  Status:   INVALID -- {result['message']}")
    elif result["status"] == "expired":
        print(f"  Status:   EXPIRED")
        print(f"  Created:  {result['created'].strftime('%Y-%m-%d %H:%M UTC')}")
        print(f"  Expired:  {result['expires'].strftime('%Y-%m-%d %H:%M UTC')}")
        print(f"  Duration: {result['total']}")
    else:
        print(f"  Status:   VALID")
        print(f"  Created:  {result['created'].strftime('%Y-%m-%d %H:%M UTC')}")
        print(f"  Expires:  {result['expires'].strftime('%Y-%m-%d %H:%M UTC')}")
        print(f"  Left:     {result['remaining']}")
        print(f"  Duration: {result['total']}")

    if not device_id:
        print(f"  HWID:     not verified (pass device_id to validate checksum)")
    else:
        if result["status"] != "invalid":
            print(f"  HWID:     verified for {device_id}")

    print()


def main():
    parser = argparse.ArgumentParser(
        description="Jawaker CHETO -- Key Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  %(prog)s gen abc123def456                     30-day key (default)
  %(prog)s gen abc123def456 --days 7            7-day key
  %(prog)s gen abc123def456 --hours 12          12-hour key
  %(prog)s gen abc123def456 --days 1 --hours 6  1d 6h key
  %(prog)s gen abc123def456 --hours 1           1-hour test key
  %(prog)s gen abc123def456 --count 5 --days 7  5 keys, 7 days each
  %(prog)s gen abc123def456 --no-pool           disable pool
  %(prog)s gen-public --days 3                   3-day public gift key
  %(prog)s gen-public --days 1 --no-shootit      1-day pool-only gift
  %(prog)s gen-decoy                            random decoy key
  %(prog)s gen-decoy --count 5                  5 random decoy keys
  %(prog)s check XXXX-XXXX-XXXX-XXXX           check expiry only
  %(prog)s check XXXX-XXXX-XXXX-XXXX abc123    check expiry + HWID""")

    sub = parser.add_subparsers(dest="command")

    # gen
    gen_p = sub.add_parser("gen", help="Generate real key + decoy + pastebin line")
    gen_p.add_argument("device_id",         help="Target device HWID")
    gen_p.add_argument("--count", "-n",     type=int, default=1,  help="Number of keys (default: 1)")
    gen_p.add_argument("--days",  "-d",     type=int, default=0,  help="Days until expiry")
    gen_p.add_argument("--hours", "-hr",    type=int, default=0,  help="Hours until expiry")
    gen_p.add_argument("--no-pool",         action="store_true",  help="Disable pool prediction")
    gen_p.add_argument("--no-shootit",      action="store_true",  help="Disable ShootIt prediction")

    # gen-decoy
    decoy_p = sub.add_parser("gen-decoy", help="Generate random decoy keys (no crypto value)")
    decoy_p.add_argument("--count", "-n",   type=int, default=1,  help="Number of decoy keys (default: 1)")

    # gen-public
    pub_p = sub.add_parser("gen-public", help="Generate a public/gift key for all users")
    pub_p.add_argument("--days",  "-d",     type=int, default=0,  help="Days until expiry")
    pub_p.add_argument("--hours", "-hr",    type=int, default=0,  help="Hours until expiry")
    pub_p.add_argument("--no-pool",         action="store_true",  help="Disable pool prediction")
    pub_p.add_argument("--no-shootit",      action="store_true",  help="Disable ShootIt prediction")

    # check
    chk_p = sub.add_parser("check", help="Check a key's validity")
    chk_p.add_argument("key",              help="Key to check (XXXX-XXXX-XXXX-XXXX)")
    chk_p.add_argument("device_id",        nargs="?", default=None, help="Device HWID (optional, for checksum verification)")

    args = parser.parse_args()

    if args.command == "gen":
        # Default to 30 days if neither --days nor --hours specified
        if args.days == 0 and args.hours == 0:
            args.days = 30
        args.pool = not args.no_pool
        args.shootit = not args.no_shootit
        cmd_gen(args)
    elif args.command == "gen-decoy":
        cmd_gen_decoy(args)
    elif args.command == "gen-public":
        if args.days == 0 and args.hours == 0:
            args.days = 3  # default 3 days for public keys
        cmd_gen_public(args)
    elif args.command == "check":
        cmd_check(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()