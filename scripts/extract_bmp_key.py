#!/usr/bin/env python3
"""
Extract Tuya signing secrets from t_s.bmp embedded in APK assets.

Port of nalajcie/tuya-sign-hacking C code to Python.
Uses polynomial interpolation via Gaussian elimination on rational numbers.

The BMP file is found inside any Tuya OEM APK at:
  assets/t_s.bmp

To extract it:
  apktool d your_app.apk -o decompiled
  # File is at decompiled/assets/t_s.bmp
"""

import argparse
import struct
import sys
from fractions import Fraction


def get_string_hash(s: str) -> int:
    """Java-style string hash (same as String.hashCode())."""
    acc = 0
    for ch in s:
        acc = ((acc << 5) - acc + ord(ch)) & 0xFFFFFFFF
    # Convert to signed 32-bit
    if acc >= 0x80000000:
        acc -= 0x100000000
    return acc


def bytes_to_hex(pixel_data: bytes, count: int, idx: int) -> str:
    """Read `count` bytes from pixel_data (wrapping) and return as hex string."""
    result = []
    plen = len(pixel_data)
    for _ in range(count):
        result.append(f"{pixel_data[idx % plen]:02x}")
        idx += 1
    return "".join(result)


def read_keys_from_bmp(app_id: str, bmp_path: str) -> list[str]:
    """
    Extract secret keys from a Tuya t_s.bmp file.

    The BMP contains steganographically encoded polynomial coefficients.
    The algorithm:
    1. Hash the appId to find the starting offset in pixel data
    2. Read header: key count, coefficient count, magic offset
    3. Read coefficient pairs (a_i, b_i) by following a chain of offsets
    4. For each key, construct a matrix from coefficients and solve via
       Gaussian elimination (polynomial interpolation)
    """
    with open(bmp_path, "rb") as f:
        data = f.read()

    # BMP pixel data starts at offset 0x36
    PIXEL_OFFSET = 0x36
    pixel_data = data[PIXEL_OFFSET:]
    plen = len(pixel_data)

    # Compute starting offset from appId hash
    h = get_string_hash(app_id)
    if h < 0:
        h = -h
    h = (h % plen) // 2

    print(f"  appId hash offset: {h} (0x{h:04x})")

    # Read header
    keys_cnt = pixel_data[(h + 1) % plen]
    coeffs_cnt = pixel_data[(h + 2) % plen]

    if keys_cnt < 1 or keys_cnt > 4:
        raise ValueError(f"Invalid keys_cnt={keys_cnt}. appId may not match this BMP file.")
    if coeffs_cnt == 0:
        raise ValueError(f"Invalid coeffs_cnt={coeffs_cnt}. appId may not match this BMP file.")

    print(f"  keys_cnt: {keys_cnt}, coeffs_cnt: {coeffs_cnt}")

    # Read magic offset
    magic = (
        (pixel_data[(h + 3) % plen] << 24)
        | (pixel_data[(h + 4) % plen] << 16)
        | (pixel_data[(h + 5) % plen] << 8)
        | (pixel_data[(h + 6) % plen])
    )

    offs = h ^ magic

    # Read all coefficients
    # Total coefficients = coeffs_cnt * keys_cnt
    # But they're read sequentially: coeffs_cnt entries per key
    total_coeffs = coeffs_cnt * keys_cnt
    coeffs = []

    for idx in range(total_coeffs):
        v1_off = offs % plen
        v1_len = pixel_data[v1_off]
        str1 = bytes_to_hex(pixel_data, v1_len, v1_off + 1)

        v2_off = (v1_off + v1_len + 1) % plen
        v2_len = pixel_data[v2_off]
        str2 = bytes_to_hex(pixel_data, v2_len, v2_off + 1)

        coeffs.append((str1, str2))

        # Follow chain to next entry
        vnext_off = (v2_off + v2_len + 1) % plen
        vnext = (
            (pixel_data[vnext_off] << 24)
            | (pixel_data[(vnext_off + 1) % plen] << 16)
            | (pixel_data[(vnext_off + 2) % plen] << 8)
            | (pixel_data[(vnext_off + 3) % plen])
        )
        offs = v1_off ^ vnext

    # Solve for each key
    keys = []
    for key_idx in range(keys_cnt):
        key_coeffs = coeffs[key_idx * coeffs_cnt : (key_idx + 1) * coeffs_cnt]
        key_hex = coeffs_to_key(key_coeffs, coeffs_cnt)
        # Convert hex pairs to ASCII string
        key_str = bytes.fromhex(key_hex).decode("ascii", errors="replace")
        keys.append(key_str)
        print(f"  Key[{key_idx}] hex: {key_hex}")
        print(f"  Key[{key_idx}] str: {key_str}")

    return keys


def coeffs_to_key(coeff_pairs: list[tuple[str, str]], mul: int) -> str:
    """
    Given coefficient pairs (a_i, b_i) as hex strings, construct a Vandermonde-like
    matrix and solve via Gaussian elimination to recover the polynomial constant term.

    Matrix structure (for each row i):
    [ a_i^(mul-1), a_i^(mul-2), ..., a_i^1, a_i^0, b_i ]

    This is polynomial interpolation: finding f(x) such that f(a_i) = b_i,
    then extracting the last coefficient.
    """
    # Build augmented matrix [mul rows x (mul+1) cols] using Fractions
    matrix = []
    for a_hex, b_hex in coeff_pairs:
        a = Fraction(int(a_hex, 16))
        b = Fraction(int(b_hex, 16))
        row = []
        for exp in range(mul - 1, -1, -1):
            row.append(a ** exp)
        row.append(b)
        matrix.append(row)

    # Gaussian elimination to triangular form
    for row in range(mul):
        # Ensure diagonal is non-zero (pivot)
        if matrix[row][row] == 0:
            for row2 in range(row + 1, mul):
                if matrix[row2][row] != 0:
                    matrix[row], matrix[row2] = matrix[row2], matrix[row]
                    break
            else:
                raise ValueError(f"Cannot make diagonal non-zero for row {row}")

        # Eliminate below
        for y in range(row + 1, mul):
            if matrix[y][row] != 0:
                ratio = matrix[row][row] / matrix[y][row]
                for col in range(row, mul + 1):
                    matrix[y][col] = matrix[y][col] * ratio - matrix[row][col]

    # Back-substitution: result = M[last][last+1] / M[last][last]
    last = mul - 1
    if matrix[last][last] == 0:
        raise ValueError("Final diagonal element is zero")

    result = matrix[last][last + 1] / matrix[last][last]

    if result.denominator != 1:
        raise ValueError(f"Result is not an integer: {result}")

    return format(result.numerator, "x")


def main():
    parser = argparse.ArgumentParser(
        description="Extract Tuya signing secrets from t_s.bmp",
        epilog="Example: %(prog)s --app-id ucrudpqqyf7shnyhgndm --bmp assets/t_s.bmp",
    )
    parser.add_argument("--app-id", required=True, help="Tuya clientId / appId from BuildConfig.java")
    parser.add_argument("--bmp", required=True, help="Path to t_s.bmp extracted from APK assets")
    parser.add_argument("--cert-sha256", help="APK signing certificate SHA-256 (hex, no colons)")
    parser.add_argument("--app-secret", help="App secret from BuildConfig.java")
    args = parser.parse_args()

    print(f"Extracting keys from: {args.bmp}")
    print(f"Using appId: {args.app_id}")
    print()

    keys = read_keys_from_bmp(args.app_id, args.bmp)

    print(f"\nExtracted {len(keys)} key(s)")

    if len(keys) >= 1 and args.cert_sha256 and args.app_secret:
        bmp_key = keys[0]
        composite = f"{args.cert_sha256}_{bmp_key}_{args.app_secret}"
        print(f"\n{'=' * 60}")
        print(f"Composite signing key:")
        print(f"  certSHA256: {args.cert_sha256}")
        print(f"  bmpKey:     {bmp_key}")
        print(f"  appSecret:  {args.app_secret}")
        print(f"\n  Full key: {composite}")
        print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
