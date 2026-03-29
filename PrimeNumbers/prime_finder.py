#!/usr/bin/env python3
"""
prime_finder.py
---------------
Main entry-point for the PrimeNumbers toolkit.

Given an integer n, this script finds:
  • the closest prime to n
  • the nearest prime strictly below n
  • the nearest prime strictly above n

…using whichever primality strategy you choose from the menu.

Strategies
----------
  1. Trial Division         – O(√n) per test, deterministic, O(1) memory
  2. Miller-Rabin           – O(k·log²n) per test, deterministic for n<3.3×10²⁴
  3. Fermat Primality Test  – O(k·log²n) per test, probabilistic (Carmichael caveat)
  4. AKS Primality Test     – Õ(log^7.5 n) per test, deterministic polynomial-time
  5. Sieve of Eratosthenes  – O(n log log n), fast for dense range queries
  6. Sieve of Sundaram      – O(n log n), classic 1934 alternative sieve
  7. Sieve of Atkin         – O(n / log log n), asymptotically fastest sieve
  8. Run ALL strategies     – benchmark and compare every strategy

Usage
-----
  Interactive:
      python prime_finder.py

  Non-interactive (CLI):
      python prime_finder.py <number>
      python prime_finder.py <number> --strategy <1-7>
      python prime_finder.py <number> --all
"""

import argparse
import bisect
import importlib
import pathlib
import sys
import time

# ---------------------------------------------------------------------------
# Ensure that the directory containing this script is on sys.path so that
# sibling modules (trial_division.py, miller_rabin.py, …) can be imported.
# ---------------------------------------------------------------------------
_HERE = pathlib.Path(__file__).parent.resolve()
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

# ---------------------------------------------------------------------------
# Strategy registry
# ---------------------------------------------------------------------------
STRATEGIES = {
    1: {
        "name": "Trial Division",
        "module": "trial_division",
        "fn": "is_prime",
        "type": "pointwise",
        "deterministic": True,
        "complexity": "O(√n) per test",
        "description": (
            "Checks divisibility by all integers up to √n (6k±1 optimisation). "
            "Simple, exact, and requires no extra memory."
        ),
    },
    2: {
        "name": "Miller-Rabin",
        "module": "miller_rabin",
        "fn": "is_prime",
        "type": "pointwise",
        "deterministic": True,
        "complexity": "O(k·log²n) per test",
        "description": (
            "Witness-based strong pseudoprime test. Deterministic for n < ~3.3×10²⁴ "
            "via fixed witness sets; probabilistic with 20 random witnesses otherwise. "
            "Fastest pointwise test in practice."
        ),
    },
    3: {
        "name": "Fermat Primality Test",
        "module": "fermat_primality_test",
        "fn": "is_probably_prime",
        "type": "pointwise",
        "deterministic": False,
        "complexity": "O(k·log²n) per test",
        "description": (
            "Based on Fermat's Little Theorem. Probabilistic: Carmichael numbers "
            "(e.g. 561, 1105, 1729) always pass but are composite. "
            "Prefer Miller-Rabin for reliable results."
        ),
    },
    4: {
        "name": "AKS Primality Test",
        "module": "aks_primality_test",
        "fn": "is_prime",
        "type": "pointwise",
        "deterministic": True,
        "complexity": "Õ(log^7.5 n) per test",
        "max_n": 5_000,   # skip automatically in --all mode above this threshold
        "description": (
            "The landmark 2002 'PRIMES is in P' algorithm – the first "
            "deterministic polynomial-time test. Theoretically important but "
            "much slower than Miller-Rabin. Best used on small-to-medium inputs."
        ),
    },
    5: {
        "name": "Sieve of Eratosthenes",
        "module": "sieve_of_eratosthenes",
        "fn": "sieve",
        "type": "sieve",
        "deterministic": True,
        "complexity": "O(n log log n)",
        "description": (
            "Classic ~240 BC algorithm. Generates all primes up to a limit by "
            "marking multiples. Very fast for dense range queries near the input."
        ),
    },
    6: {
        "name": "Sieve of Sundaram",
        "module": "sieve_of_sundaram",
        "fn": "sieve_sundaram",
        "type": "sieve",
        "deterministic": True,
        "complexity": "O(n log n)",
        "description": (
            "1934 algorithm that sieves odd primes via the exclusion set i+j+2ij. "
            "Slightly slower than Eratosthenes but historically significant."
        ),
    },
    7: {
        "name": "Sieve of Atkin",
        "module": "sieve_of_atkin",
        "fn": "sieve_atkin",
        "type": "sieve",
        "deterministic": True,
        "complexity": "O(n / log log n)",
        "description": (
            "Atkin & Bernstein 2004. Uses three quadratic forms modulo 60; "
            "asymptotically the fastest sieve for large n."
        ),
    },
}

# ---------------------------------------------------------------------------
# Core helpers
# ---------------------------------------------------------------------------

def _load_fn(strategy_id: int):
    """Import a strategy module and return the primality/sieve callable."""
    info = STRATEGIES[strategy_id]
    mod = importlib.import_module(info["module"])
    return getattr(mod, info["fn"])


def _closest_pointwise(n: int, is_prime_fn) -> dict:
    """Walk outward from n to find the nearest prime using is_prime_fn."""
    if n < 2:
        # The only prime <= 2 is 2 itself
        return {"closest": 2, "below": None, "above": 2}

    # Find nearest prime strictly below n
    lo = n - 1
    while lo >= 2 and not is_prime_fn(lo):
        lo -= 1
    below = lo if lo >= 2 else None

    # Find nearest prime strictly above n
    hi = n + 1
    while not is_prime_fn(hi):
        hi += 1
    above = hi

    if is_prime_fn(n):
        return {"closest": n, "below": below, "above": above}

    # n is not prime – determine closest
    dist_above = above - n
    dist_below = (n - below) if below is not None else float("inf")

    if dist_above < dist_below:
        closest = above
    elif dist_below < dist_above:
        closest = below
    else:
        closest = below  # equidistant → smaller prime

    return {"closest": closest, "below": below, "above": above}


def _closest_sieve(n: int, sieve_fn) -> dict:
    """Build a sieve around n and binary-search for the nearest prime."""
    if n < 2:
        return {"closest": 2, "below": None, "above": 2}

    # Choose a margin wide enough to cover any realistic prime gap.
    # Known maximal prime gap up to 10^18 is ~1476; use a generous margin.
    margin = max(1500, int(n ** 0.5) + 100)
    upper = n + margin

    primes = sieve_fn(upper)

    if not primes:
        return {"closest": 2, "below": None, "above": 2}

    # index of the first prime >= n
    idx = bisect.bisect_left(primes, n)

    # Is n itself prime?
    n_is_prime = idx < len(primes) and primes[idx] == n
    above_idx = idx + 1 if n_is_prime else idx
    below_idx = (idx - 1) if n_is_prime else (idx - 1)

    below = primes[below_idx] if below_idx >= 0 else None

    # above may fall outside the sieve range – extend if needed
    if above_idx < len(primes):
        above = primes[above_idx]
    else:
        extended = sieve_fn(upper + margin)
        ext_idx = bisect.bisect_right(extended, n)
        above = extended[ext_idx] if ext_idx < len(extended) else None

    if n_is_prime:
        return {"closest": n, "below": below, "above": above}

    if above is None and below is None:
        return {"closest": None, "below": None, "above": None}
    if above is None:
        return {"closest": below, "below": below, "above": None}
    if below is None:
        return {"closest": above, "below": None, "above": above}

    dist_above = above - n
    dist_below = n - below
    if dist_above < dist_below:
        closest = above
    elif dist_below < dist_above:
        closest = below
    else:
        closest = below  # equidistant → smaller prime

    return {"closest": closest, "below": below, "above": above}


# ---------------------------------------------------------------------------
# Strategy runner
# ---------------------------------------------------------------------------

def run_strategy(strategy_id: int, n: int, force: bool = False) -> dict:
    """Run strategy *strategy_id* for input *n*.

    Parameters
    ----------
    strategy_id : int
        Key into STRATEGIES.
    n : int
        The reference integer.
    force : bool
        If True, run even when n exceeds the strategy's max_n limit.
        Default is False (used when running all strategies to avoid hangs).

    Returns a dict:
        strategy_id, name, closest, below, above, elapsed_ms, error, skipped
    """
    info = STRATEGIES[strategy_id]
    result = {
        "strategy_id": strategy_id,
        "name": info["name"],
        "closest": None,
        "below": None,
        "above": None,
        "elapsed_ms": None,
        "error": None,
        "skipped": False,
    }

    # Enforce optional per-strategy size limit (only when not forced)
    max_n = info.get("max_n")
    if not force and max_n is not None and n > max_n:
        result["skipped"] = True
        result["error"] = (
            f"n={n:,} exceeds recommended limit ({max_n:,}) for this strategy "
            f"(use --strategy {strategy_id} to force)"
        )
        return result

    try:
        fn = _load_fn(strategy_id)
        t0 = time.perf_counter()

        if info["type"] == "pointwise":
            res = _closest_pointwise(n, fn)
        else:
            res = _closest_sieve(n, fn)

        elapsed = (time.perf_counter() - t0) * 1000.0
        result.update({**res, "elapsed_ms": elapsed})

    except (ImportError, AttributeError, ValueError, ArithmeticError, MemoryError) as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"

    return result


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------

_SEP = "=" * 66


def _print_banner():
    print(_SEP)
    print("  Prime Number Finder  –  Strategy Selector")
    print(_SEP)
    print()


def _print_menu():
    print("Available strategies:")
    print()
    for sid, info in STRATEGIES.items():
        det = "deterministic" if info["deterministic"] else "probabilistic"
        print(f"  [{sid}] {info['name']}")
        print(f"       Complexity : {info['complexity']}  ({det})")
        print(f"       {info['description']}")
        print()
    print("  [8] Run ALL strategies (benchmark & compare)")
    print()


def _print_single_result(result: dict, n: int):
    if result.get("error"):
        print(f"  ERROR in {result['name']}: {result['error']}")
        return

    closest = result["closest"]
    below = result["below"]
    above = result["above"]
    ms = result["elapsed_ms"]
    dist = abs(closest - n) if closest is not None else "?"

    print(f"  Strategy : {result['name']}")
    print(f"  Input    : {n:,}")
    print(f"  Closest  : {closest:,}  (distance {dist})")
    if below is not None:
        print(f"  Below    : {below:,}  (distance {n - below:,})")
    else:
        print("  Below    : none (n is smaller than any prime)")
    if above is not None:
        print(f"  Above    : {above:,}  (distance {above - n:,})")
    print(f"  Time     : {ms:.4f} ms")


def _print_comparison(results: list, n: int):
    """Print a side-by-side benchmark table for all strategies."""
    print()
    header = f"  {'Strategy':<28} {'Closest':>14}  {'Below':>14}  {'Above':>14}  {'ms':>9}"
    print(header)
    print("  " + "-" * (len(header) - 2))
    for r in results:
        if r.get("skipped"):
            print(f"  {r['name']:<28}  (skipped – {r['error']})")
            continue
        if r.get("error"):
            print(f"  {r['name']:<28}  ERROR: {r['error']}")
            continue
        c = f"{r['closest']:,}" if r["closest"] is not None else "N/A"
        b = f"{r['below']:,}"   if r["below"]   is not None else "N/A"
        a = f"{r['above']:,}"   if r["above"]   is not None else "N/A"
        print(f"  {r['name']:<28} {c:>14}  {b:>14}  {a:>14}  {r['elapsed_ms']:>9.4f}")
    print()
    ok = [r for r in results if not r.get("error") and not r.get("skipped")]
    if ok:
        fastest = min(ok, key=lambda r: r["elapsed_ms"])
        print(f"  Fastest strategy: {fastest['name']} ({fastest['elapsed_ms']:.4f} ms)")
    print()


# ---------------------------------------------------------------------------
# Interactive mode
# ---------------------------------------------------------------------------

def _prompt_int(prompt: str) -> int:
    while True:
        raw = input(prompt).strip()
        try:
            value = int(raw)
            if value < 0:
                print("  Please enter a non-negative integer.")
                continue
            return value
        except ValueError:
            print("  Invalid input – please enter a whole number.")


def _prompt_strategy() -> int:
    while True:
        raw = input("Choose a strategy [1-8]: ").strip()
        try:
            choice = int(raw)
            if 1 <= choice <= 8:
                return choice
            print("  Please enter a number between 1 and 8.")
        except ValueError:
            print("  Invalid input – please enter a number between 1 and 8.")


def interactive_mode():
    _print_banner()
    n = _prompt_int("Enter a positive integer: ")
    print()
    _print_menu()
    choice = _prompt_strategy()
    print()

    if choice == 8:
        # Run all strategies
        print(f"  Running all strategies for n = {n:,} …")
        print()
        results = []
        for sid in STRATEGIES:
            info = STRATEGIES[sid]
            max_n = info.get("max_n")
            if max_n is not None and n > max_n:
                r = run_strategy(sid, n, force=False)  # returns skipped result
                results.append(r)
                print(f"    [{sid}] {info['name']:<28}  (skipped – n > {max_n:,})")
                continue
            print(f"    [{sid}] {info['name']:<28}", end="", flush=True)
            r = run_strategy(sid, n, force=False)
            results.append(r)
            if r.get("error"):
                print(f"  ERROR: {r['error']}")
            else:
                print(f"  {r['elapsed_ms']:.3f} ms")
        print()
        print(_SEP)
        _print_comparison(results, n)
        print(_SEP)
    else:
        name = STRATEGIES[choice]["name"]
        print(f"  Running {name} for n = {n:,} …")
        print()
        r = run_strategy(choice, n, force=True)   # force=True: user chose it explicitly
        print(_SEP)
        _print_single_result(r, n)
        print(_SEP)

    print()
    try:
        again = input("Find another prime? [y/N]: ").strip().lower()
    except EOFError:
        again = "n"
    if again == "y":
        print()
        interactive_mode()


# ---------------------------------------------------------------------------
# CLI (non-interactive) mode
# ---------------------------------------------------------------------------

def cli_mode():
    parser = argparse.ArgumentParser(
        prog="prime_finder.py",
        description=(
            "Find the closest prime(s) to a given integer using a chosen strategy."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Strategies:\n"
            "  1  Trial Division\n"
            "  2  Miller-Rabin\n"
            "  3  Fermat Primality Test\n"
            "  4  AKS Primality Test\n"
            "  5  Sieve of Eratosthenes\n"
            "  6  Sieve of Sundaram\n"
            "  7  Sieve of Atkin\n"
        ),
    )
    parser.add_argument("number", type=int, help="The reference integer (>= 0)")
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--strategy", "-s",
        type=int,
        choices=range(1, 8),
        metavar="N",
        help="Strategy number (1–7); omit to run all",
    )
    group.add_argument(
        "--all", "-a",
        action="store_true",
        help="Run all strategies and print a comparison table",
    )
    args = parser.parse_args()
    n = args.number

    _print_banner()

    if args.strategy:
        r = run_strategy(args.strategy, n, force=True)
        _print_single_result(r, n)
        print()
    else:
        # Default: run all strategies
        print(f"  Input: {n:,}  –  running all strategies …")
        print()
        results = [run_strategy(sid, n, force=False) for sid in STRATEGIES]
        _print_comparison(results, n)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    try:
        if len(sys.argv) > 1:
            cli_mode()
        else:
            interactive_mode()
    except (KeyboardInterrupt, EOFError):
        print("\n\nBye!")
        sys.exit(0)
