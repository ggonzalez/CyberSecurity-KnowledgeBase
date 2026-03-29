"""
sieve_of_atkin.py
-----------------
Generate all prime numbers up to a given limit using the Sieve of Atkin
(A. O. L. Atkin & D. J. Bernstein, 2004).

How it works:
    The sieve uses three quadratic forms to flip the primality flag of
    candidates based on the number of solutions to each form modulo 60.
    After the flip phase, composite squares are eliminated.  The result
    is a more cache-friendly sieve that runs in O(n / log log n) for
    large n.

    Canonical quadratic forms:
        Form 1: 4x² + y²  ≡ {1, 13, 17, 29, 37, 41, 49, 53} (mod 60) → flip
        Form 2: 3x² + y²  ≡ {7, 19, 31, 43}                  (mod 60) → flip
        Form 3: 3x² - y²  ≡ {11, 23, 47, 59} (x>y)           (mod 60) → flip
    Then: for each prime p >= 5, mark all multiples of p² as composite.

Time complexity : O(n / log log n)  (asymptotically faster than Eratosthenes)
Space complexity: O(n)

Usage (command line):
    python sieve_of_atkin.py

Usage (as a library):
    from sieve_of_atkin import sieve_atkin
    print(sieve_atkin(50))
"""

import math


def sieve_atkin(limit: int) -> list:
    """Return all primes up to limit using the Sieve of Atkin.

    Parameters
    ----------
    limit : int
        Upper bound (inclusive).

    Returns
    -------
    list[int]
        Sorted list of primes in [2, limit].
    """
    if limit < 2:
        return []

    is_prime = bytearray(limit + 1)  # all False initially

    # 2, 3, and 5 are special wheel factors that must be seeded explicitly
    for p in (2, 3, 5):
        if p <= limit:
            is_prime[p] = 1

    sqrt_limit = math.isqrt(limit)

    for x in range(1, sqrt_limit + 1):
        x2 = x * x
        for y in range(1, sqrt_limit + 1):
            y2 = y * y

            # Form 1: n = 4x² + y²
            n = 4 * x2 + y2
            if n <= limit and n % 60 in {1, 13, 17, 29, 37, 41, 49, 53}:
                is_prime[n] ^= 1

            # Form 2: n = 3x² + y²
            n = 3 * x2 + y2
            if n <= limit and n % 60 in {7, 19, 31, 43}:
                is_prime[n] ^= 1

            # Form 3: n = 3x² - y²  (only when x > y)
            if x > y:
                n = 3 * x2 - y2
                if n <= limit and n % 60 in {11, 23, 47, 59}:
                    is_prime[n] ^= 1

    # Eliminate composites by sieving out squares of primes >= 5
    for n in range(5, sqrt_limit + 1):
        if is_prime[n]:
            n2 = n * n
            for k in range(n2, limit + 1, n2):
                is_prime[k] = 0

    return [i for i, flag in enumerate(is_prime) if flag]


if __name__ == "__main__":
    for n in [10, 50, 100, 200]:
        primes = sieve_atkin(n)
        print(f"Primes up to {n:>4}: {primes}")

    print()
    big_limit = 1_000_000
    primes = sieve_atkin(big_limit)
    print(f"Number of primes up to {big_limit:,}: {len(primes)}")
    print(f"Largest prime <= {big_limit:,}: {primes[-1]}")
