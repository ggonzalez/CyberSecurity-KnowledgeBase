"""
lucas_lehmer.py
---------------
Test whether a Mersenne number M_p = 2^p - 1 is prime using the
Lucas-Lehmer primality test.

How it works:
    M_p is prime iff the sequence  s_0 = 4,  s_{i+1} = (s_i² - 2) mod M_p
    satisfies  s_{p-2} ≡ 0 (mod M_p).

    This test is *exact* (no false positives or negatives) and is the
    primary method used to find large Mersenne primes (GIMPS project).

Requirement:
    p itself must be prime (a necessary, but not sufficient, condition for
    M_p to be prime).

Known Mersenne prime exponents (first few):
    2, 3, 5, 7, 13, 17, 19, 31, 61, 89, 107, 127, ...

Time complexity : O(p² · M(p))  where M(p) is the cost of big-int multiply
Space complexity: O(p)           (the numbers involved have O(p) bits)

Usage (command line):
    python lucas_lehmer.py

Usage (as a library):
    from lucas_lehmer import is_mersenne_prime
    print(is_mersenne_prime(31))  # True  (M_31 = 2147483647)
    print(is_mersenne_prime(11))  # False (M_11 = 2047 = 23 × 89)
"""


def is_prime_simple(n: int) -> bool:
    """Simple primality test used to validate the exponent p."""
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    i = 3
    while i * i <= n:
        if n % i == 0:
            return False
        i += 2
    return True


def is_mersenne_prime(p: int) -> bool:
    """Determine whether the Mersenne number M_p = 2^p - 1 is prime.

    Parameters
    ----------
    p : int
        The exponent.  Must be a prime >= 2.

    Returns
    -------
    bool
        True if 2^p - 1 is prime, False otherwise.

    Raises
    ------
    ValueError
        If p is not a prime number.
    """
    if not is_prime_simple(p):
        raise ValueError(f"{p} is not prime; M_p can only be prime when p is prime.")

    if p == 2:
        return True  # M_2 = 3

    m = (1 << p) - 1  # 2^p - 1
    s = 4
    for _ in range(p - 2):
        s = (s * s - 2) % m

    return s == 0


if __name__ == "__main__":
    print("Lucas-Lehmer Test for Mersenne Primes  (M_p = 2^p - 1)")
    print("-" * 55)

    # Test exponents up to 130
    exponents = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41,
                 43, 47, 53, 59, 61, 67, 71, 89, 107, 127]
    known_mersenne_prime_exponents = {
        2, 3, 5, 7, 13, 17, 19, 31, 61, 89, 107, 127
    }

    for p in exponents:
        result = is_mersenne_prime(p)
        marker = "✓ PRIME" if result else "  composite"
        mp = (1 << p) - 1
        print(f"  M_{p:<3} = 2^{p:<3}-1  →  {marker}")

    print()
    print("Checking a large exponent (p=521)...")
    result = is_mersenne_prime(521)
    print(f"  M_521 is {'prime' if result else 'composite'}.")
