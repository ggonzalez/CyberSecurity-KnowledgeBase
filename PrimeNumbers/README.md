# Prime Numbers

A collection of Python scripts for working in the prime number space.

## Scripts

| Script | Description |
|--------|-------------|
| `closest_prime.py` | Find the closest prime number to a given input |
| `trial_division.py` | Check primality using trial division |
| `sieve_of_eratosthenes.py` | Generate all primes up to N using the Sieve of Eratosthenes |
| `sieve_of_sundaram.py` | Generate all primes up to N using the Sieve of Sundaram |
| `sieve_of_atkin.py` | Generate all primes up to N using the Sieve of Atkin |
| `fermat_primality_test.py` | Probabilistic primality test based on Fermat's little theorem |
| `miller_rabin.py` | Miller-Rabin probabilistic primality test |
| `lucas_lehmer.py` | Lucas-Lehmer test for Mersenne primes (2^p - 1) |
| `aks_primality_test.py` | AKS deterministic polynomial-time primality test |

## Usage

Each script can be run directly from the command line. For example:

```bash
python closest_prime.py
python sieve_of_eratosthenes.py
python miller_rabin.py
```

Most scripts expose a callable function so they can also be imported and used as a library.
