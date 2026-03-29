"""
sieve_of_sundaram.py
--------------------
Generate all odd prime numbers up to a given limit using the Sieve of
Sundaram (S. P. Sundaram, 1934).

How it works:
    1. From the list of integers 1..k (where k = (limit-2)//2), remove all
       numbers of the form  i + j + 2ij  where 1 <= i <= j and i + j + 2ij <= k.
    2. The remaining numbers n yield primes via  2n + 1.
    3. Prepend 2 to obtain the complete list of primes.

Time complexity : O(n log n)
Space complexity: O(n)

Usage (command line):
    python sieve_of_sundaram.py

Usage (as a library):
    from sieve_of_sundaram import sieve_sundaram
    print(sieve_sundaram(50))
"""


def sieve_sundaram(limit: int) -> list:
    """Return all primes up to limit using the Sieve of Sundaram.

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
    if limit == 2:
        return [2]

    # We generate odd primes up to `limit` via 2n+1 form.
    # k is the upper index: largest n where 2n+1 <= limit => n <= (limit-1)//2
    k = (limit - 1) // 2

    marked = bytearray(k + 1)  # marked[i] = 1 means i is NOT prime-generating

    i = 1
    while True:
        # For fixed i, j starts at i; increase j until i+j+2ij > k
        j = i
        step = 2 * i + 1          # i + j + 2ij increases by (2i+1) as j increases by 1
        base = i + i + 2 * i * i  # i + j + 2ij at j = i
        while base <= k:
            marked[base] = 1
            base += step
            j += 1
        # Advance i; if the minimum value i+i+2i*i > k, we're done
        i += 1
        if i + i + 2 * i * i > k:
            break

    primes = [2]
    for n in range(1, k + 1):
        if not marked[n]:
            primes.append(2 * n + 1)

    return primes


if __name__ == "__main__":
    for n in [10, 50, 100, 200]:
        primes = sieve_sundaram(n)
        print(f"Primes up to {n:>4}: {primes}")

    print()
    big_limit = 1_000_000
    primes = sieve_sundaram(big_limit)
    print(f"Number of primes up to {big_limit:,}: {len(primes)}")
    print(f"Largest prime <= {big_limit:,}: {primes[-1]}")
