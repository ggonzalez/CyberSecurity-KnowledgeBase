"""
aks_primality_test.py
---------------------
Deterministic polynomial-time primality testing using the AKS algorithm
(Agrawal, Kayal & Saxena, 2002 – "PRIMES is in P").

How it works (high-level):
    1. If n = a^b for integers a >= 1, b >= 2, return COMPOSITE.
    2. Find the smallest r such that ord_r(n) > log₂(n)².
    3. If 1 < gcd(a, n) < n for some a <= r, return COMPOSITE.
    4. If n <= r, return PRIME.
    5. For a = 1 to floor(sqrt(φ(r)) · log₂(n)):
           if (X + a)^n ≢ X^n + a  in  (Z/nZ)[X] / (X^r - 1), return COMPOSITE.
    6. Return PRIME.

Note on practicality:
    The AKS algorithm is theoretically important (first deterministic
    polynomial-time test) but is much slower in practice than Miller-Rabin
    for numbers used in cryptography.  This implementation is suitable for
    educational use on small-to-medium inputs.

Time complexity : Õ(log^{7.5} n)   (original; improved variants exist)
Space complexity: O(r · log n)

Usage (command line):
    python aks_primality_test.py

Usage (as a library):
    from aks_primality_test import is_prime
    print(is_prime(97))   # True
    print(is_prime(100))  # False
"""

import math


def _is_perfect_power(n: int) -> bool:
    """Return True if n = a^b for integers a >= 2, b >= 2."""
    if n < 4:
        return False
    # Only exponents b up to log2(n) are possible
    max_b = math.floor(math.log2(n))
    for b in range(2, max_b + 1):
        # Binary search for a such that a^b == n
        lo, hi = 2, math.isqrt(n) + 1
        while lo <= hi:
            mid = (lo + hi) // 2
            val = mid ** b
            if val == n:
                return True
            elif val < n:
                lo = mid + 1
            else:
                hi = mid - 1
    return False


def _multiplicative_order(a: int, n: int, limit: int) -> int:
    """Return ord_n(a), or limit+1 if the order exceeds limit.

    ord_n(a) is the smallest positive integer k such that a^k ≡ 1 (mod n).
    Returns limit+1 when gcd(a,n) != 1 or the order is not found within limit.
    """
    if math.gcd(a, n) != 1:
        return limit + 1
    power = 1
    for k in range(1, limit + 1):
        power = (power * a) % n
        if power == 1:
            return k
    return limit + 1


def _poly_mod_mult(p1: list, p2: list, mod_poly_degree: int, n: int) -> list:
    """Multiply two polynomials modulo (X^r - 1) and modulo n.

    Polynomials are represented as coefficient lists (index = degree).
    """
    result = [0] * mod_poly_degree
    for i, c1 in enumerate(p1):
        if c1 == 0:
            continue
        for j, c2 in enumerate(p2):
            if c2 == 0:
                continue
            result[(i + j) % mod_poly_degree] = (
                result[(i + j) % mod_poly_degree] + c1 * c2
            ) % n
    return result


def _poly_mod_pow(base: list, exp: int, mod_poly_degree: int, n: int) -> list:
    """Compute base^exp in (Z/nZ)[X] / (X^r - 1)."""
    result = [0] * mod_poly_degree
    result[0] = 1  # multiplicative identity
    while exp > 0:
        if exp % 2 == 1:
            result = _poly_mod_mult(result, base, mod_poly_degree, n)
        base = _poly_mod_mult(base, base, mod_poly_degree, n)
        exp //= 2
    return result


def is_prime(n: int) -> bool:
    """Determine whether n is prime using the AKS primality test.

    Parameters
    ----------
    n : int
        Integer to test (n >= 2).

    Returns
    -------
    bool
        True if n is prime, False otherwise.
    """
    # Handle trivial cases
    if n < 2:
        return False
    if n in (2, 3, 5, 7):
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False

    # Step 1: Check if n is a perfect power
    if _is_perfect_power(n):
        return False

    # Step 2: Find smallest r with ord_r(n) > log2(n)^2
    log2n = math.log2(n)
    log2n_sq = math.ceil(log2n ** 2)

    r = 2
    while True:
        if math.gcd(r, n) == 1:
            order = _multiplicative_order(n % r, r, log2n_sq)
            if order > log2n_sq:
                break
        r += 1

    # Step 3: Check gcds for a in [2, r]
    for a in range(2, r + 1):
        g = math.gcd(a, n)
        if 1 < g < n:
            return False

    # Step 4: If n <= r, n is prime
    if n <= r:
        return True

    # Step 5: Polynomial congruence checks
    # Compute Euler's totient phi(r) – we only need floor(sqrt(phi(r)) * log2(n))
    # Simple phi calculation
    phi_r = r
    temp = r
    p = 2
    while p * p <= temp:
        if temp % p == 0:
            while temp % p == 0:
                temp //= p
            phi_r -= phi_r // p
        p += 1
    if temp > 1:
        phi_r -= phi_r // temp

    upper = math.floor(math.sqrt(phi_r) * log2n)

    for a in range(1, upper + 1):
        # Build (X + a) as a polynomial of degree r
        lhs_poly = [0] * r
        lhs_poly[0] = a % n      # constant term
        if r > 1:
            lhs_poly[1] = 1      # coefficient of X

        # Compute (X + a)^n mod (X^r - 1, n)
        lhs = _poly_mod_pow(lhs_poly, n, r, n)

        # Build X^n + a  mod (X^r - 1, n)
        rhs = [0] * r
        rhs[n % r] = 1
        rhs[0] = (rhs[0] + a) % n

        if lhs != rhs:
            return False

    return True


if __name__ == "__main__":
    print("AKS Primality Test")
    print("-" * 40)
    candidates = [2, 3, 4, 5, 16, 17, 97, 100, 101, 561, 7919]
    for c in candidates:
        print(f"  is_prime({c:>5}) = {is_prime(c)}")

    print()
    limit = 50
    primes = [n for n in range(2, limit + 1) if is_prime(n)]
    print(f"Primes up to {limit}: {primes}")
