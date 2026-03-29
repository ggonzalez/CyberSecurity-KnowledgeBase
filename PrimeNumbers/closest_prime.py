"""
closest_prime.py
----------------
Find the closest prime number to a given integer.

If two primes are equidistant (e.g. n=6 is 1 away from both 5 and 7),
the smaller prime is returned.

Usage (command line):
    python closest_prime.py

Usage (as a library):
    from closest_prime import closest_prime
    print(closest_prime(100))  # 101
"""

import math


def is_prime(n: int) -> bool:
    """Return True if n is a prime number, False otherwise."""
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    for i in range(3, math.isqrt(n) + 1, 2):
        if n % i == 0:
            return False
    return True


def closest_prime(n: int) -> int:
    """Return the prime number closest to n.

    Parameters
    ----------
    n : int
        The reference integer (must be >= 0).

    Returns
    -------
    int
        The prime closest to n.  When two primes are equidistant the
        smaller one is returned.
    """
    if n < 2:
        return 2

    if is_prime(n):
        return n

    lower = n - 1
    upper = n + 1

    while True:
        lower_is_prime = is_prime(lower)
        upper_is_prime = is_prime(upper)

        if lower_is_prime and upper_is_prime:
            # equidistant – return the smaller one
            return lower
        if lower_is_prime:
            return lower
        if upper_is_prime:
            return upper

        lower -= 1
        upper += 1


if __name__ == "__main__":
    test_values = [0, 1, 10, 14, 20, 50, 100, 200, 1000]
    for val in test_values:
        print(f"Closest prime to {val:>6} -> {closest_prime(val)}")
