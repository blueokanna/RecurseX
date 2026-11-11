"""Generate a deterministic, PUBLIC TEST ONLY RSA fixture with Python's stdlib.

These primes and private key are intentionally reproducible and must never be
used outside tests. This generator is not called by cargo test or CI.
"""
import math
import pathlib
import random

rng = random.Random(20261111)


def prime():
    while True:
        candidate = rng.getrandbits(1024) | (3 << 1022) | 1
        if any(candidate % p == 0 for p in (3, 5, 7, 11, 13, 17, 19, 23, 29, 31)):
            continue
        d, s = candidate - 1, 0
        while d % 2 == 0:
            d //= 2
            s += 1
        for _ in range(32):
            x = pow(rng.randrange(2, candidate - 1), d, candidate)
            if x in (1, candidate - 1):
                continue
            for _ in range(s - 1):
                x = pow(x, 2, candidate)
                if x == candidate - 1:
                    break
            else:
                break
        else:
            if math.gcd(65537, candidate - 1) == 1:
                return candidate


def der(tag, value):
    n = len(value)
    size = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag]) + (bytes([n]) if n < 128 else bytes([128 + len(size)]) + size) + value


def integer(n):
    value = n.to_bytes(max(1, (n.bit_length() + 7) // 8), "big")
    return der(2, (b"\0" if value[0] & 128 else b"") + value)


p, q, e = prime(), prime(), 65537
n = p * q
d = pow(e, -1, (p - 1) * (q - 1))
private = der(0x30, b"".join(integer(v) for v in (0, n, e, d, p, q, d % (p - 1), d % (q - 1), pow(q, -1, p))))
algorithm = bytes.fromhex("300d06092a864886f70d0101010500")
pkcs8 = der(0x30, integer(0) + algorithm + der(4, private))
directory = pathlib.Path(__file__).parent
(directory / "rsa2048.pk8").write_bytes(pkcs8)
(directory / "rsa2048.dnskey").write_bytes(bytes([3, 1, 0, 1]) + n.to_bytes(256, "big"))
