####### 
### Remove non C strings from the standard input
### Specially usefull for piping with strings command
###
### Gabriel Gonzalez Garcia - www.gabrielcybersecurity.com
###
import ipaddress
import argparse
import math
import sys
import re
from collections import Counter


debug_enabled = False

# --- English letter frequencies (normalized) ---
EN_FREQ = {
    'a': 0.08167, 'b': 0.01492, 'c': 0.02782, 'd': 0.04253,
    'e': 0.12702, 'f': 0.02228, 'g': 0.02015, 'h': 0.06094,
    'i': 0.06966, 'j': 0.00153, 'k': 0.00772, 'l': 0.04025,
    'm': 0.02406, 'n': 0.06749, 'o': 0.07507, 'p': 0.01929,
    'q': 0.00095, 'r': 0.05987, 's': 0.06327, 't': 0.09056,
    'u': 0.02758, 'v': 0.00978, 'w': 0.02360, 'x': 0.00150,
    'y': 0.01974, 'z': 0.00074
}

# --- Simple English word list (extendable) ---
try:
    with open("/Users/ggonzalez/bin/words_alpha.txt") as f:
        DICT = set(x.strip().lower() for x in f)
except:
   # fallback tiny dictionary
    DICT = {"error", "file", "user", "login", "network", "version", "failed", "success", "config", "system"}


def parse_args():
    parser = argparse.ArgumentParser(
        description="Filter strings and keep only valid English-like readable text."
    )

    parser.add_argument(
        "-n", "--negate",
        action="store_true",
        help="Print rejected strings instead of accepted ones."
    )

    parser.add_argument(
        "-d", "--debug",
        action="store_true",
        help="Print debugging info from the different heuristics."
    )

    parser.add_argument(
        "input",
        nargs="?",
        type=str,
        default="-",
        help="Only works with stdin. Useful for piping `strings` output."
    )

    return parser.parse_args()


def chi_square_english_score(s):
    s = ''.join([c for c in s.lower() if c.isalpha()])
    if len(s) < 5:
        return 9999   # reject short strings

    counts = Counter(s)
    total = len(s)
    chi = 0
    for letter, expected_freq in EN_FREQ.items():
        observed = counts.get(letter, 0)
        expected = expected_freq * total
        chi += (observed - expected)**2 / (expected + 1e-9)
    return chi

# -------------------------------------------------------

def english_bigram_score(s):
    s = s.lower()
    bigram_freq = {
        "th": 0.027, "he": 0.023, "in": 0.020, "er": 0.017,
        "an": 0.016, "re": 0.014, "on": 0.013, "at": 0.012,
        "en": 0.012, "nd": 0.011, "ti": 0.011
    }
    score = 0.0
    for i in range(len(s) - 1):
        bg = s[i:i+2]
        score += bigram_freq.get(bg, 0)
    return score

def printf_format_match(s):
    ret_tokens = []

    tin = s.split()

    format_str  = re.compile(
       r'''
       (?:0x)?                # Optional 0x prefix
       %
       (?:[-+ #0]*)           # Optional flags
       (?:\d+)?               # Optional width
       (?:\.\d+)?             # Optional precision
       (?:hh|h|ll|l|j|z|t|L)? # Optional length modifier
       (?:
           [diuoxXfFeEgGaAcspn%] | # Standard specifiers
           \[[^\]]*\]              # Scanset, e.g. %[^...]
       )
       ''',
       re.VERBOSE
    )

    for t in tin:
       fmt = format_str.findall(t)
       for f in fmt:
          ret_tokens.append(f)

    return ret_tokens

def tokenize_c_string(s: str):
    """
    NOT YET 
    Tokenize C-style strings and identifiers, including splitting camelCase,
    PascalCase, and mixed alphanumeric segments.
    """
    # 1. Replace all non-alphanumerics with space
    s = re.sub(r'[^A-Za-z0-9]+', ' ', s)

    # 2. Split into "raw tokens" split on whitespace
    raw_tokens = s.split()

    final_tokens = []

    camel_case_pattern = re.compile(
        r'''
        [A-Z]+(?=[A-Z][a-z]) |   # XML in XMLHttpRequest
        [A-Z]?[a-z]+           | # Words: add, Item, Request
        [A-Z]+                 | # All caps words
        \d+                      # Numbers
        ''',
        re.VERBOSE
    )

    for tok in raw_tokens:
        # Detect CamelCase / mixedCase / PascalCase / letters+numbers
        parts = camel_case_pattern.findall(tok)
        for p in parts:
            final_tokens.append(p.lower())

    return final_tokens

def is_ip(s: str) -> bool:
    """
    Returns True if string is a valid IPv4 or IPv6 address (optionally with /mask).
    Uses ipaddress for reliability.
    """
    try:
        # Handle "IP" or "IP/mask"
        if "/" in s:
            ipaddress.ip_network(s, strict=False)
        else:
            ipaddress.ip_address(s)
        return True
    except ValueError:
        return False

def is_oid(s: str) -> bool:
    _oid_re = re.compile(r"^[0-2](?:\.\d+)*$")
    """
    Returns True if string is a valid SNMP numeric OID.
    Valid examples:
      1.3.6.1.2.1
      1.3.6.1.4.1.2021.4.5
    """
    if not _oid_re.match(s):
        return False

    # Additional sanity checks (optional)
    try:
        parts = s.split(".")
        return all(int(p) >= 0 for p in parts)
    except ValueError:
        return False

def looks_english(s):
    # printable & allowed char ratio
    allowed = sum(c.isalnum() or c in " .,:;'-_/%[]{}()" for c in s)

    # dictionary heuristic
    tokens = re.findall(r"[A-Za-z]+", s.lower())
    dict_hits = sum(1 for t in tokens if len(t) > 3 and t in DICT)

    '''
    # chi-square test (English ≈ low chi²)
    chi = chi_square_english_score(s)
    #print(f"[DEBUG] {chi}")
    if chi < 100:  # good threshold
        #print("[DEBUG]: Passed Xsquare")
        return True
    # Let's optimize this to get frequencies per token not per "sentence"
    '''

    chitokens = re.findall(r"[A-Za-z_\.]+", s.lower())
    chi_hits = sum(1 for t in chitokens if chi_square_english_score(t) < 100)

    # Format Strings Matches
    fmt_tokens = printf_format_match(s)

    # bigram score
    bigram_score = english_bigram_score(s)

    '''
	DEBUG CODE FOR FINE TUNING
    '''

    if debug_enabled:
       print("-------")
       print("[DEBUG] len < 4 rejected", len(s))
       print("[DEBUG] allowed chars ratio < 0.85 rejected", allowed / len(s))
       print("[DEBUG] dict token", tokens)
       print("[DEBUG] dict hits >= 1 passes", dict_hits)
       print("[DEBUG] chitokens", chitokens)
       print("[DEBUG] chi hits >= 1 pases", chi_hits)
       print("[DEBUG] fmt tokens >= 1 pases", fmt_tokens)
       print("[DEBUG] bigram score > 0.03 pases", chi_hits)
       print("[DEBUG] is IP Address?", is_ip(s))
       print("[DEBUG] is SNMP OID?", is_oid(s))

    # length check
    if len(s) < 4:
        if debug_enabled:
           print("[DEBUG] rejected", s)
        return False


    if dict_hits >= 1:
        return True

    if chi_hits >= 1:
      return True

    if len(fmt_tokens) >= 1:
      return True

    if bigram_score > 0.03:
        return True

    if is_ip(s):
        return True

    if is_oid(s):
        return True

    if allowed / len(s) < 0.85:
        if debug_enabled:
           print("[DEBUG] rejected", s)
        return False

    if debug_enabled:
       print("[DEBUG] rejected", s)

    return False

def main():
    global debug_enabled
    args = parse_args()

    if args.debug:
       debug_enabled = True

    for line in sys.stdin:
        s = line.strip()
        if len(s) < 1:
           continue

        if args.negate:
           if not looks_english(s):
              print(s)
        else:
           if looks_english(s):
              print(s)
    print(args.negate)

if __name__ == "__main__":
    main()
