"""
fermat_primality_test.py
------------------------
Probabilistic primality testing using Fermat's Little Theorem.

Fermat's Little Theorem:
    If p is prime and gcd(a, p) = 1, then a^(p-1) ≡ 1 (mod p).

The test:
    Pick k random bases a in [2, n-2].  If a^(n-1) ≢ 1 (mod n) for any a,
    then n is definitely composite.  If all k tests pass, n is *probably*
    prime (a "Fermat probable prime").

Limitation – Carmichael numbers:
    These composite numbers pass the Fermat test for *all* bases coprime to
    them (e.g. 561, 1105, 1729).  Use Miller-Rabin for a stronger test.

Time complexity : O(k · log²n) per call (with fast modular exponentiation)
Space complexity: O(1)

Usage (command line):
    python fermat_primality_test.py

Usage (as a library):
    from fermat_primality_test import is_probably_prime
    print(is_probably_prime(97))    # True
    print(is_probably_prime(100))   # False
    print(is_probably_prime(561))   # True  (Carmichael – false positive!)
"""

import random


def is_probably_prime(n: int, k: int = 10) -> bool:
    """Test whether n is probably prime using k rounds of Fermat's test.

    Parameters
    ----------
    n : int
        Integer to test (n >= 2).
    k : int
        Number of random witness bases to try.  Higher k → lower error
        probability (error rate ≤ (1/2)^k for non-Carmichael composites).

    Returns
    -------
    bool
        False  → n is definitely composite.
        True   → n is probably prime (with high probability).
    """
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False

    for _ in range(k):
        a = random.randint(2, n - 2)
        if pow(a, n - 1, n) != 1:
            return False
    return True


def known_carmichael_numbers(limit: int) -> list:
    """Return Carmichael numbers up to limit (naive – for educational use)."""
    from math import gcd

    def is_carmichael(n):
        if n < 2 or is_probably_prime(n, 20):
            return False
        # Check: for every a in [2, n-1] with gcd(a,n)==1, a^(n-1) ≡ 1 (mod n)
        for a in range(2, n):
            if gcd(a, n) == 1 and pow(a, n - 1, n) != 1:
                return False
        return True

    # A simpler characterisation (Korselt): n is Carmichael iff it is
    # squarefree and for every prime p | n, (p-1) | (n-1).
    # We use that here for speed.
    def is_carmichael_korselt(n):
        if n < 3 or n % 2 == 0:
            return False
        # factorise n
        factors = []
        temp = n
        d = 3
        while d * d <= temp:
            if temp % d == 0:
                factors.append(d)
                temp //= d
                if temp % d == 0:  # not squarefree
                    return False
            d += 2
        if temp > 1:
            factors.append(temp)
        if len(factors) < 2:  # primes are not Carmichael
            return False
        for p in factors:
            if (n - 1) % (p - 1) != 0:
                return False
        return True

    return [n for n in range(3, limit + 1, 2) if is_carmichael_korselt(n)]


if __name__ == "__main__":
    print("Fermat Primality Test")
    print("-" * 40)
    candidates = [2, 3, 4, 17, 97, 100, 561, 1105, 1729, 7919]
    for c in candidates:
        result = is_probably_prime(c)
        note = " (Carmichael!)" if c in (561, 1105, 1729) else ""
        print(f"  is_probably_prime({c:>5}) = {result}{note}")

    print()
    limit = 3000
    carmichaels = known_carmichael_numbers(limit)
    print(f"Carmichael numbers up to {limit}: {carmichaels}")
    print("These composites fool the Fermat test – use Miller-Rabin instead.")
