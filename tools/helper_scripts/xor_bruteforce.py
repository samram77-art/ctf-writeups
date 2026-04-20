#!/usr/bin/env python3
"""
xor_bruteforce.py — Brute-force repeating-key XOR cipher
Samson Ram | https://github.com/samram77-art

Usage:
    python xor_bruteforce.py --ciphertext 3b0e0a193b5f1c0a0a1f041b
    python xor_bruteforce.py --ciphertext <hex> --max-keylen 6 --top-n 5
"""

import argparse
import itertools
from string import printable

# English character frequency table (including space)
ENGLISH_FREQ: dict[str, float] = {
    ' ': 0.130, 'e': 0.127, 't': 0.091, 'a': 0.082, 'o': 0.075,
    'i': 0.070, 'n': 0.067, 's': 0.063, 'h': 0.061, 'r': 0.060,
    'd': 0.043, 'l': 0.040, 'c': 0.028, 'u': 0.028, 'm': 0.024,
    'w': 0.024, 'f': 0.022, 'g': 0.020, 'y': 0.020, 'p': 0.019,
    'b': 0.015, 'v': 0.010, 'k': 0.008, 'j': 0.002, 'x': 0.002,
    'q': 0.001, 'z': 0.001,
}


def score_text(data: bytes) -> float:
    """Score bytes by English letter frequency. Higher = more English-like."""
    return sum(ENGLISH_FREQ.get(chr(b).lower(), 0) for b in data)


def index_of_coincidence(data: bytes) -> float:
    """Compute the Index of Coincidence for a byte sequence."""
    n = len(data)
    if n < 2:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    return sum(f * (f - 1) for f in freq) / (n * (n - 1))


def estimate_key_length(ciphertext: bytes, max_keylen: int) -> list[tuple[int, float]]:
    """Rank candidate key lengths by average Index of Coincidence across streams."""
    results = []
    for keylen in range(1, max_keylen + 1):
        streams = [ciphertext[i::keylen] for i in range(keylen)]
        avg_ioc = sum(index_of_coincidence(s) for s in streams) / keylen
        results.append((keylen, avg_ioc))
    # Sort by IoC descending (higher IoC → more likely correct key length)
    return sorted(results, key=lambda x: x[1], reverse=True)


def crack_single_byte_xor(stream: bytes) -> tuple[int, float, bytes]:
    """Find the best single-byte XOR key for a stream using frequency scoring."""
    best = (0, 0.0, b'')
    for candidate in range(256):
        decrypted = bytes(b ^ candidate for b in stream)
        s = score_text(decrypted)
        if s > best[1]:
            best = (candidate, s, decrypted)
    return best


def crack_repeating_xor(ciphertext: bytes, keylen: int) -> tuple[bytes, bytes, float]:
    """Crack a repeating-key XOR cipher given a known key length."""
    key_bytes = []
    for i in range(keylen):
        stream = ciphertext[i::keylen]
        key_byte, _, _ = crack_single_byte_xor(stream)
        key_bytes.append(key_byte)

    key = bytes(key_bytes)
    full_key = (key * (len(ciphertext) // keylen + 1))[:len(ciphertext)]
    plaintext = bytes(c ^ k for c, k in zip(ciphertext, full_key))
    total_score = score_text(plaintext)
    return key, plaintext, total_score


def is_printable(data: bytes) -> bool:
    """Return True if data consists entirely of printable ASCII characters."""
    return all(chr(b) in printable for b in data)


def main():
    parser = argparse.ArgumentParser(
        description="Brute-force repeating-key XOR cipher using frequency analysis.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example: python xor_bruteforce.py --ciphertext 3b0e0a19 --max-keylen 4",
    )
    parser.add_argument(
        "--ciphertext", required=True,
        help="Hex-encoded ciphertext (no spaces, e.g. 3b0e0a19...)"
    )
    parser.add_argument(
        "--max-keylen", type=int, default=4,
        help="Maximum key length to test (default: 4)"
    )
    parser.add_argument(
        "--top-n", type=int, default=3,
        help="Number of top candidates to display per key length (default: 3)"
    )
    args = parser.parse_args()

    # Decode hex ciphertext
    try:
        ciphertext = bytes.fromhex(args.ciphertext.strip())
    except ValueError as e:
        print(f"[!] Invalid hex string: {e}")
        return

    print(f"[*] Ciphertext length : {len(ciphertext)} bytes")
    print(f"[*] Testing key lengths: 1 – {args.max_keylen}\n")

    # Step 1: Rank key lengths by IoC
    ioc_ranking = estimate_key_length(ciphertext, args.max_keylen)
    print("[*] Key length candidates (by Index of Coincidence):")
    for keylen, ioc in ioc_ranking:
        print(f"    keylen={keylen}  avg_ioc={ioc:.4f}")
    print()

    # Step 2: Try cracking each key length
    results = []
    for keylen in range(1, args.max_keylen + 1):
        key, plaintext, score = crack_repeating_xor(ciphertext, keylen)
        results.append((score, keylen, key, plaintext))

    # Sort by score descending
    results.sort(key=lambda x: x[0], reverse=True)

    print(f"[*] Top {args.top_n} candidate(s):\n")
    for rank, (score, keylen, key, plaintext) in enumerate(results[:args.top_n], 1):
        key_repr = key.decode("latin-1") if is_printable(key) else key.hex()
        pt_repr  = plaintext.decode("latin-1") if is_printable(plaintext) else plaintext.hex()
        print(f"  [{rank}] key_length={keylen}  key={repr(key_repr)}  score={score:.3f}")
        print(f"       plaintext: {pt_repr}\n")


if __name__ == "__main__":
    main()
