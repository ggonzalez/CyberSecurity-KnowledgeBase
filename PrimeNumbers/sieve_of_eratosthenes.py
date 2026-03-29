"""
sieve_of_eratosthenes.py
------------------------
Generate all prime numbers up to a given limit using the Sieve of
Eratosthenes – one of the oldest known algorithms (~240 BC).

How it works:
    1. Create a boolean list of size (limit + 1), all initialised to True.
    2. Starting from p = 2, mark all multiples of p (p², p²+p, …) as False.
    3. Move to the next unmarked number and repeat until p² > limit.
    4. All remaining True entries are prime.

Time complexity : O(n log log n)
Space complexity: O(n)

Usage (command line):
    python sieve_of_eratosthenes.py

Usage (as a library):
    from sieve_of_eratosthenes import sieve
    print(sieve(50))  # [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]
"""

import math


def sieve(limit: int) -> list:
    """Return a list of all primes up to and including limit.

    Parameters
    ----------
    limit : int
        Upper bound of the search (inclusive).

    Returns
    -------
    list[int]
        Sorted list of prime numbers in [2, limit].
    """
    if limit < 2:
        return []

    is_prime = bytearray([1]) * (limit + 1)
    is_prime[0] = 0
    is_prime[1] = 0

    for p in range(2, math.isqrt(limit) + 1):
        if is_prime[p]:
            # Mark multiples starting at p^2
            is_prime[p * p :: p] = bytearray(len(is_prime[p * p :: p]))

    return [i for i, flag in enumerate(is_prime) if flag]


if __name__ == "__main__":
    for n in [10, 50, 100, 200]:
        primes = sieve(n)
        print(f"Primes up to {n:>4}: {primes}")

    print()
    big_limit = 1_000_000
    primes = sieve(big_limit)
    print(f"Number of primes up to {big_limit:,}: {len(primes)}")
    print(f"Largest prime <= {big_limit:,}: {primes[-1]}")
