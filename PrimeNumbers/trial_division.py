"""
trial_division.py
-----------------
Primality testing via trial division – the simplest and most direct method.

How it works:
    A number n is prime if it has no divisors other than 1 and itself.
    We only need to test divisors up to sqrt(n): if n has a factor larger
    than sqrt(n) the complementary factor must be smaller than sqrt(n) and
    would already have been found.  We also skip even numbers after 2.

Time complexity : O(sqrt(n))
Space complexity: O(1)

Usage (command line):
    python trial_division.py

Usage (as a library):
    from trial_division import is_prime
    print(is_prime(97))   # True
    print(is_prime(100))  # False
"""

import math


def is_prime(n: int) -> bool:
    """Determine whether n is prime using trial division.

    Parameters
    ----------
    n : int
        Integer to test.

    Returns
    -------
    bool
        True if n is prime, False otherwise.
    """
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    if n == 3:
        return True
    if n % 3 == 0:
        return False
    # All primes > 3 are of the form 6k ± 1
    i = 5
    while i <= math.isqrt(n):
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True


def primes_up_to(limit: int) -> list:
    """Return a list of all primes up to and including limit."""
    return [n for n in range(2, limit + 1) if is_prime(n)]


if __name__ == "__main__":
    # Demonstrate primality checks
    candidates = [0, 1, 2, 3, 4, 17, 18, 97, 100, 7919]
    print("Trial Division Primality Test")
    print("-" * 35)
    for c in candidates:
        print(f"  is_prime({c:>5}) = {is_prime(c)}")

    print()
    limit = 50
    print(f"Primes up to {limit}: {primes_up_to(limit)}")
