"""
miller_rabin.py
---------------
Probabilistic (and deterministic for small inputs) primality testing using
the Miller-Rabin algorithm.

How it works:
    Write n - 1 = 2^r · d  (d odd).
    For a witness a, compute x = a^d mod n.
    If x == 1 or x == n-1, n passes this round (probably prime).
    Otherwise square x up to r-1 times; if x ever == n-1, n passes.
    If none of the squarings yield n-1, n is composite.

Deterministic for n < 3,215,031,751 with the bases {2, 3, 5, 7}.
Deterministic for n < 3,317,044,064,679,887,385,961,981 with the first
12 primes as witnesses.

Time complexity : O(k log²n) per call
Space complexity: O(1)

Usage (command line):
    python miller_rabin.py

Usage (as a library):
    from miller_rabin import is_prime
    print(is_prime(997))   # True
    print(is_prime(1000))  # False
"""

import random

# Deterministic witness sets for small n (no randomness needed)
_DETERMINISTIC_WITNESSES = [
    (3_215_031_751,          [2, 3, 5, 7]),
    (3_474_749_660_383,      [2, 3, 5, 7, 11, 13]),
    (341_550_071_728_321,    [2, 3, 5, 7, 11, 13, 17]),
    (3_825_123_056_546_413_051, [2, 3, 5, 7, 11, 13, 17, 19, 23]),
    (318_665_857_834_031_151_167_461, [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]),
]


def _miller_rabin_round(n: int, a: int) -> bool:
    """Return True if n passes a single Miller-Rabin round with witness a."""
    # Write n-1 = 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    x = pow(a, d, n)
    if x in (1, n - 1):
        return True
    for _ in range(r - 1):
        x = pow(x, 2, n)
        if x == n - 1:
            return True
    return False


def is_prime(n: int, k: int = 20) -> bool:
    """Test whether n is prime using the Miller-Rabin algorithm.

    For n < ~3.3 × 10²⁴ a deterministic witness set is used; no random
    witnesses are needed.  For larger n, k random witnesses are used
    (error probability ≤ 4^(-k)).

    Parameters
    ----------
    n : int
        Integer to test.
    k : int
        Number of random witnesses for large n (default 20).

    Returns
    -------
    bool
        False → definitely composite.
        True  → prime (deterministic for small n, probabilistic for large n).
    """
    if n < 2:
        return False
    if n in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False

    # Choose witness set
    witnesses = None
    for limit, w in _DETERMINISTIC_WITNESSES:
        if n < limit:
            witnesses = w
            break

    if witnesses is None:
        # Large n: use k random witnesses
        witnesses = random.sample(range(2, min(n - 2, 10**6)), k)

    return all(_miller_rabin_round(n, a) for a in witnesses)


def primes_up_to(limit: int) -> list:
    """Return all primes up to limit using Miller-Rabin for each candidate."""
    return [n for n in range(2, limit + 1) if is_prime(n)]


if __name__ == "__main__":
    print("Miller-Rabin Primality Test")
    print("-" * 40)
    candidates = [0, 1, 2, 97, 100, 561, 1105, 1729, 7919, 104729,
                  15_485_863,        # 1,000,000th prime
                  2**61 - 1]         # Mersenne prime M61
    for c in candidates:
        print(f"  is_prime({c}) = {is_prime(c)}")

    print()
    limit = 100
    print(f"Primes up to {limit}: {primes_up_to(limit)}")
