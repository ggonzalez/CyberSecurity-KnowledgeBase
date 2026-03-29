# Prime Numbers

A collection of Python scripts for working in the prime number space.

## Quick Start – main entry point

`prime_finder.py` is the main interactive script. Given any integer it finds
the closest prime, the nearest prime below, and the nearest prime above using
whichever strategy you choose.

```bash
# Interactive menu (choose number and strategy at the prompts)
python prime_finder.py

# Non-interactive – pick a specific strategy (1–7)
python prime_finder.py 100 --strategy 2      # Miller-Rabin
python prime_finder.py 100 -s 5             # Sieve of Eratosthenes

# Run all strategies and print a comparison/benchmark table
python prime_finder.py 100 --all
python prime_finder.py 100               # --all is the default when no strategy is given
```

### Available strategies

| # | Name | Complexity | Type |
|---|------|-----------|------|
| 1 | Trial Division | O(√n) per test | deterministic |
| 2 | Miller-Rabin | O(k·log²n) per test | deterministic¹ |
| 3 | Fermat Primality Test | O(k·log²n) per test | probabilistic² |
| 4 | AKS Primality Test | Õ(log^7.5 n) per test | deterministic |
| 5 | Sieve of Eratosthenes | O(n log log n) | deterministic |
| 6 | Sieve of Sundaram | O(n log n) | deterministic |
| 7 | Sieve of Atkin | O(n / log log n) | deterministic |

¹ Deterministic for n < ~3.3 × 10²⁴ via fixed witness sets.  
² Carmichael numbers are a known false-positive case; prefer Miller-Rabin for reliability.  
³ AKS is automatically skipped in `--all` mode for n > 5,000 because it is very slow in practice;
  use `--strategy 4` to force it for any input.

---

## Individual scripts

Each script below can also be run standalone or imported as a library.

| Script | Description |
|--------|-------------|
| `prime_finder.py` | **Main entry point** – interactive strategy selector |
| `closest_prime.py` | Find the closest prime number to a given input |
| `trial_division.py` | Check primality using trial division |
| `sieve_of_eratosthenes.py` | Generate all primes up to N using the Sieve of Eratosthenes |
| `sieve_of_sundaram.py` | Generate all primes up to N using the Sieve of Sundaram |
| `sieve_of_atkin.py` | Generate all primes up to N using the Sieve of Atkin |
| `fermat_primality_test.py` | Probabilistic primality test based on Fermat's little theorem |
| `miller_rabin.py` | Miller-Rabin probabilistic primality test |
| `lucas_lehmer.py` | Lucas-Lehmer test for Mersenne primes (2^p − 1) |
| `aks_primality_test.py` | AKS deterministic polynomial-time primality test |

Most scripts expose a callable function for library use, for example:

```python
from miller_rabin import is_prime
print(is_prime(2**61 - 1))   # True  (Mersenne prime M61)

from sieve_of_eratosthenes import sieve
print(sieve(50))              # [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]

from lucas_lehmer import is_mersenne_prime
print(is_mersenne_prime(521)) # True
```
