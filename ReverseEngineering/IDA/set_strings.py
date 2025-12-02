import idautils
import ida_nalt
import math
import re
from collections import Counter

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


# -------------------------------------------------------

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

# -------------------------------------------------------

def looks_english(s):
    # length check
    if len(s) < 4:
        return False

    # printable & allowed char ratio
    allowed = sum(c.isalnum() or c in " .,:;'-_/%[]{}()" for c in s)
    if allowed / len(s) < 0.85:
        return False

    # dictionary heuristic
    tokens = re.findall(r"[A-Za-z_]+", s.lower())
    print("[DEBUG] token", tokens)
    dict_hits = sum(1 for t in tokens if len(t) > 3 and t in DICT)
    if dict_hits >= 1:
        print("[DEBUG]: Passed dict")
        return True
    '''
    # chi-square test (English ≈ low chi²)
    chi = chi_square_english_score(s)
    print(f"[DEBUG] {chi}")
    if chi < 100:  # good threshold
        #print("[DEBUG]: Passed Xsquare")
        return True
    '''
    chi_hits = sum(1 for t in tokens if chi_square_english_score(t) < 100)
    print(chi_hits)
    if chi_hits >= 2:
      print("[DEBUG]: Chi passed")
      return True
        
    # bigram score
    if english_bigram_score(s) > 0.03:
        #print("[DEBUG]: Passed bigram")
        return True

    return False

# -------------------------------------------------------

def set_all_strings():
    strings = idautils.Strings()

    # Make sure IDA has populated the string list
    strings.setup()

    for s in strings:
        ea = s.ea
        text = str(s)
        len_s = len(text)
        print(f"0x{ea:X}: {text} {len_s}")
        if looks_english(text.strip()):
            ida_bytes.create_strlit(ea, len_s + 1, ida_nalt.STRTYPE_C)
            print("Created")
        else:
            print(f"Skipping: 0x{ea:X}: {text} {len_s}")

set_all_strings()

