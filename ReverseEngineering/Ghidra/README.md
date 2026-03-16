# Ghidra Scripts

## set_strings.py

Scans all memory of the loaded program for string candidates and automatically creates ASCII string data types for those that look like English-readable text. Strings that are part of disassembled instructions or already typed as strings are safely skipped.

### How it works

Each string candidate is scored using multiple heuristics:

| Heuristic | Description |
|---|---|
| Dictionary | Matches tokens against a full English word list (`words_alpha.txt`) |
| Chi-square | Compares letter frequency against expected English distribution |
| Bigrams | Scores common English bigrams (th, he, in, er, …) |
| Printf format | Detects C-style format strings (`%s`, `%d`, `%x`, …) |
| IP address | Matches valid IPv4 addresses and CIDR notation |
| SNMP OID | Matches dotted-numeric OID notation |

A string passes if **any** heuristic fires. Strings shorter than 4 characters are always rejected.

---

### Requirements

- Ghidra 10.x or later
- Jython runtime (bundled with Ghidra — no extra install needed)

---

### Setup

#### 1. Copy the word list

The script expects `words_alpha.txt` to be located one directory above the script itself:

```
ReverseEngineering/
├── words_alpha.txt          <-- place it here
└── Ghidra/
    └── set_strings.py
```

`words_alpha.txt` is already included in `ReverseEngineering/` in this repository. If you move the script to a different location, place `words_alpha.txt` in the parent directory of wherever `set_strings.py` lives.

If the file is not found, the script falls back to a small built-in dictionary and continues without error.

#### 2. Add the script to Ghidra's Script Manager

1. Open Ghidra and load a program.
2. In the **CodeBrowser**, go to **Window → Script Manager** (or press `Shift+F3`).
3. Click the **Manage Script Directories** button (the folder icon with a green `+` in the toolbar).
4. Click **Add** (the `+` button) and browse to the directory containing `set_strings.py`:
   ```
   <repo>/ReverseEngineering/Ghidra/
   ```
5. Click **OK** and then **Refresh** (circular arrow icon) in the Script Manager.
6. The script will appear under the **Strings** category as **set_strings.py**.

---

### Running the script

1. Open a program in the Ghidra **CodeBrowser**.
2. Open the **Script Manager** (`Window → Script Manager`).
3. Find **set_strings.py** under the **Strings** category.
4. Double-click it (or select it and click the **Run** button ▶).
5. Progress is printed in the **Console** window. Example output:
   ```
   Scanning for strings...
   Found 17158 candidates. Filtering...
   Created string at 00401234: Copyright (C) 2003...
   Created string at 00403A10: Invalid argument...
   Finished. Created 412 new strings.
   ```

---

### Enabling debug output

To see per-string scoring details, open the script and change line:

```python
debug_enabled = False
```

to:

```python
debug_enabled = True
```

Then re-run. Each candidate will print which heuristics fired or why it was rejected.

---

### Author

Gabriel Gonzalez Garcia — [www.gabrielcybersecurity.com](https://www.gabrielcybersecurity.com)
