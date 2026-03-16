# Set only those strings that look like English-readable text in Ghidra.
#
#@author Gabriel Gonzalez Garcia (www.gabrielcybersecurity.com)
#@category Strings
#@keybinding
#@menupath
#@toolbar
#@version 1.0
#@description Scan for string candidates and create string data types for those that look like English-readable text. Uses chi-square, bigram, dictionary, and format-string heuristics.
#@runtime Jython

from __future__ import print_function
from ghidra.program.util.string import StringSearcher, FoundStringCallback
from ghidra.program.model.data import StringDataType, TerminatedStringDataType
from ghidra.util.task import TaskMonitor
from collections import Counter
import re
import sys
import os

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
    _script_dir = os.path.dirname(getSourceFile().getAbsolutePath())
    _words_path = os.path.join(_script_dir, "..", "words_alpha.txt")
    with open(_words_path) as _f:
        DICT = set(x.strip().lower() for x in _f)
except Exception:
    # fallback tiny dictionary
    DICT = {"error", "file", "user", "login", "network", "version", "failed", "success", "config", "system"}

def chi_square_english_score(s):
    s = ''.join([c for c in s.lower() if c.isalpha()])
    if len(s) < 5:
        return 9999   # reject short strings

    counts = Counter(s)
    total = len(s)
    chi = 0.0
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

    format_str = re.compile(
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

def tokenize_c_string(s):
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

def is_ip(s):
    # Regex for IPv4
    ip4_re = re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:/\d{1,2})?$")
    if ip4_re.match(s):
        return True
    return False

def is_oid(s):
    _oid_re = re.compile(r"^[0-2](?:\.\d+)*$")
    if not _oid_re.match(s):
        return False
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

    chitokens = re.findall(r"[A-Za-z_\.]+", s.lower())
    chi_hits = sum(1 for t in chitokens if chi_square_english_score(t) < 100)

    # Format Strings Matches
    fmt_tokens = printf_format_match(s)

    # bigram score
    bigram_score = english_bigram_score(s)

    if debug_enabled:
       print("-------")
       print("[DEBUG] len < 4 rejected", len(s))
       print("[DEBUG] allowed chars ratio < 0.85 rejected", float(allowed) / len(s) if len(s) > 0 else 0)
       print("[DEBUG] dict token", tokens)
       print("[DEBUG] dict hits >= 1 passes", dict_hits)
       print("[DEBUG] chitokens", chitokens)
       print("[DEBUG] chi hits >= 1 passes", chi_hits)
       print("[DEBUG] fmt tokens >= 1 passes", fmt_tokens)
       print("[DEBUG] bigram score > 0.03 passes", bigram_score)
       print("[DEBUG] is IP Address?", is_ip(s))
       print("[DEBUG] is SNMP OID?", is_oid(s))

    # length check
    if len(s) < 4:
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

    if len(s) > 0 and (float(allowed) / len(s)) < 0.85:
        if debug_enabled:
           print("[DEBUG] rejected", s)
        return False

    if debug_enabled:
       print("[DEBUG] rejected", s)

    return False

class StringCollector(FoundStringCallback):
    def __init__(self, list_ref):
        self.list = list_ref
    
    def stringFound(self, foundString):
        self.list.append(foundString)

def set_all_strings():
    print("Scanning for strings...")
    found_strings = []
    callback = StringCollector(found_strings)
    
    # StringSearcher(program, minLength, alignment, nullTermination, allowPascal)
    # Adjust params as needed. 4 is min len in script heuristics.
    searcher = StringSearcher(currentProgram, 4, 1, True, False) 
    
    # search whole memory
    searcher.search(currentProgram.getMemory(), callback, False, TaskMonitor.DUMMY)
    
    print("Found {} candidates. Filtering...".format(len(found_strings)))
    
    count_created = 0
    for fs in found_strings:
        try:
            addr = fs.getAddress()
            # fs.getString(Memory) returns the string content
            text = fs.getString(currentProgram.getMemory())
            
            # Clean up text for analysis (strip nulls if any, though getString usually handles it)
            clean_text = text.strip()
            
            if looks_english(clean_text):
                # Skip addresses that already have a string defined
                existing_data = getDataAt(addr)
                if existing_data is not None:
                    if existing_data.isDefined() and existing_data.getDataType().getName().lower().find("string") != -1:
                        continue

                # Skip addresses that are part of disassembled instructions
                if getInstructionAt(addr) is not None:
                    if debug_enabled:
                        print("Skipping instruction at {}: {}".format(addr, clean_text[:20]))
                    continue

                # Create the string
                try:
                    createAsciiString(addr)
                    count_created += 1
                    print("Created string at {}: {}...".format(addr, clean_text[:20]))
                except:
                    # Catch both Python and Java exceptions (e.g. CodeUnitInsertionException)
                    pass
            else:
                if debug_enabled:
                    print("Skipping: {}: {}".format(addr, clean_text[:20]))
                    
        except Exception as e:
            print("Error processing string at {}: {}".format(fs.getAddress(), e))

    print("Finished. Created {} new strings.".format(count_created))

if currentProgram is not None:
    set_all_strings()
else:
    print("No program loaded.")
