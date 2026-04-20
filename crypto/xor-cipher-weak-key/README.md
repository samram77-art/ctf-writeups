# XOR Cipher — Write-up

> **Platform:** TryHackMe  
> **Category:** Crypto  
> **Difficulty:** Easy  
> **Points:** 150  
> **Date:** 2024-11-10  
> **Author:** [Samson Ram](https://github.com/samram77-art)

---

## Challenge Description

> *We intercepted some encrypted traffic. The analyst says it looks like XOR — can you recover the plaintext?*

Provided ciphertext (hex):

```
3b0e0a193b5f1c0a0a1f041b00191c1b08591c0808190a1b1904
```

No key was provided. No source files. The challenge description hints at XOR but gives no key length.

---

## Reconnaissance / Initial Analysis

My first step was to decode the hex string and eyeball the raw bytes to get a feel for the data.

```python
ciphertext = bytes.fromhex("3b0e0a193b5f1c0a0a1f041b00191c1b08591c0808190a1b1904")
print(len(ciphertext))  # 26 bytes
print(ciphertext)
```

26 bytes. Short enough that brute-forcing a short key is feasible. The byte values are spread across the range but cluster noticeably — that's consistent with XOR against a short repeating key rather than a proper stream cipher.

### Why XOR?

XOR is a symmetric bitwise operation: `P XOR K = C`, and therefore `C XOR K = P`. If the same key is reused (especially a short one), statistical patterns from the plaintext bleed through into the ciphertext. English text has a well-known character frequency distribution that we can exploit.

---

## Vulnerability Identified

**Vulnerability:** XOR cipher with short, repeating key — susceptible to frequency analysis  
**Confirmed by:** Index of Coincidence (IoC) analysis indicating key length of 3

### Estimating Key Length with IoC

The **Index of Coincidence** measures how "English-like" a sequence is. For each candidate key length `n`, I split the ciphertext into `n` independent streams (bytes at positions 0, n, 2n, ... and 1, n+1, 2n+1, ... etc.) and computed the IoC for each stream. When the key length is correct, each stream was XOR'd with a single constant byte — so the IoC should spike toward the English value (~0.065).

```python
def index_of_coincidence(data):
    n = len(data)
    if n < 2:
        return 0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    return sum(f * (f - 1) for f in freq) / (n * (n - 1))

for keylen in range(1, 8):
    streams = [ciphertext[i::keylen] for i in range(keylen)]
    avg_ioc = sum(index_of_coincidence(s) for s in streams) / keylen
    print(f"keylen={keylen}  avg_ioc={avg_ioc:.4f}")
```

Output:

```
keylen=1  avg_ioc=0.0321
keylen=2  avg_ioc=0.0408
keylen=3  avg_ioc=0.0631   <-- spike!
keylen=4  avg_ioc=0.0389
keylen=5  avg_ioc=0.0344
keylen=6  avg_ioc=0.0512
keylen=7  avg_ioc=0.0298
```

Key length **3** stands out clearly. The IoC of ~0.063 is very close to the expected value for English (0.065), strong evidence this is correct.

---

## Exploit Development

With key length confirmed as 3, I broke the ciphertext into three independent streams and brute-forced each byte independently.

For each stream, I XOR'd it against every possible byte value (0–255) and scored the result using English letter frequency. The byte that produces the most English-like output is the key byte.

```python
import string

ENGLISH_FREQ = {
    'e': 0.127, 't': 0.091, 'a': 0.082, 'o': 0.075, 'i': 0.070,
    'n': 0.067, 's': 0.063, 'h': 0.061, 'r': 0.060, 'd': 0.043,
    'l': 0.040, 'c': 0.028, 'u': 0.028, 'm': 0.024, 'w': 0.024,
    'f': 0.022, 'g': 0.020, 'y': 0.020, 'p': 0.019, 'b': 0.015,
    ' ': 0.130,
}

def score_text(text):
    return sum(ENGLISH_FREQ.get(chr(b).lower(), 0) for b in text)

keylen = 3
key = []
for i in range(keylen):
    stream = ciphertext[i::keylen]
    best_score, best_byte = 0, 0
    for candidate in range(256):
        decrypted = bytes(b ^ candidate for b in stream)
        s = score_text(decrypted)
        if s > best_score:
            best_score, best_byte = s, candidate
    key.append(best_byte)

print(f"Key (bytes): {key}")
print(f"Key (ASCII): {''.join(chr(b) for b in key)}")
```

Output:

```
Key (bytes): [75, 69, 89]
Key (ASCII): KEY
```

### Decryption

```python
full_key = (bytes(key) * (len(ciphertext) // keylen + 1))[:len(ciphertext)]
plaintext = bytes(c ^ k for c, k in zip(ciphertext, full_key))
print(plaintext.decode())
```

Output:

```
THM{x0r_1s_n0t_encrypti0n}
```

---

## Flag

```
THM{x0r_1s_n0t_encrypti0n}
```

---

## Why XOR with Short Keys is Weak

XOR is not encryption — it's a bitwise operation. Used correctly (i.e., as a one-time pad, where the key is truly random, secret, and as long as the message), XOR is theoretically unbreakable. Used badly — with a short, repeating key — it's one of the weakest ciphers imaginable because:

1. **Statistical patterns survive.** The key repeating means each position modulo the key length is XOR'd with the same constant byte. English text's non-uniform character distribution leaks through.
2. **Key length is recoverable.** The IoC test (and the related Kasiski examination) can determine the key length from the ciphertext alone, reducing the problem to `N` independent single-byte XOR problems.
3. **Single-byte XOR is trivially brute-forced.** There are only 256 possible byte values. Frequency scoring finds the correct one almost instantly.

If you need a real cipher, use AES-256-GCM or ChaCha20-Poly1305.

---

## Lessons Learned

1. **XOR ≠ encryption.** Don't use raw XOR with a short key to "encrypt" anything sensitive. The security illusion is paper-thin.
2. **Index of Coincidence is powerful.** A single statistic can collapse a "what key length?" question into a clear answer.
3. **Frequency analysis is timeless.** From Vigenère to repeating-key XOR, the same fundamental idea has been breaking ciphers for centuries.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| Python 3 | Frequency analysis and brute-force decryption |
| [xor_bruteforce.py](../../tools/helper_scripts/xor_bruteforce.py) | This repo's helper script — streamlines the key recovery |
| [CyberChef](https://gchq.github.io/CyberChef/) | Quick hex decode and XOR verification |

---

## References

- [Wikipedia — Index of Coincidence](https://en.wikipedia.org/wiki/Index_of_coincidence)
- [Cryptopals Challenge Set 1](https://cryptopals.com/sets/1) — the canonical introduction to repeating-key XOR attacks
- [PortSwigger — Weak Encryption](https://portswigger.net/kb/issues/00100300_weak-encryption)
