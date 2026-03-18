# IDA ↔ Ghidra Symbol Exchange

Bi-directional export / import of reverse-engineering symbols between
**IDA Pro** and **Ghidra** through a shared JSON file format.

## Shared JSON format (v1.0)

Both scripts read and write the **same** JSON schema, so you can:

| Workflow | Steps |
|---|---|
| **IDA → Ghidra** | Export from IDA → open JSON in Ghidra import |
| **Ghidra → IDA** | Export from Ghidra → open JSON in IDA import |
| **IDA → IDA** | Transfer symbols between two IDB files |
| **Ghidra → Ghidra** | Transfer symbols between two Ghidra projects |

### Supported symbol categories

| Category | Includes |
|---|---|
| **Functions** | Entry-point address, name, prototype / signature |
| **Labels** | Named addresses that are *not* function entries |
| **Comments** | EOL, repeatable, pre/post, plate, function comments |
| **Structs** | Full struct definition with typed members |
| **Enums** | Name + member/value pairs |

### JSON structure (abbreviated)

```json
{
  "format_version": "1.0",
  "source": "ida | ghidra",
  "export_date": "2026-03-14 12:00:00",
  "binary_name": "firmware.elf",
  "image_base": "0x8000000",
  "symbols": {
    "functions": [
      { "address": "0x8001000", "name": "main", "prototype": "int main(int argc, char **argv)" }
    ],
    "labels": [
      { "address": "0x20000000", "name": "g_globalFlag" }
    ],
    "comments": [
      { "address": "0x8001000", "type": "eol", "text": "entry point" }
    ],
    "structs": [
      {
        "name": "my_struct", "size": 8,
        "members": [
          { "offset": 0, "name": "id",   "type": "uint32_t", "size": 4 },
          { "offset": 4, "name": "flags", "type": "uint16_t", "size": 2 }
        ]
      }
    ],
    "enums": [
      {
        "name": "color_t", "width": 4,
        "members": [
          { "name": "RED",   "value": 0 },
          { "name": "GREEN", "value": 1 },
          { "name": "BLUE",  "value": 2 }
        ]
      }
    ]
  }
}
```

---

## Scripts

| File | Tool | Runtime |
|---|---|---|
| `ida_export_import.py` | IDA Pro | IDAPython (Python 2/3) |
| `ghidra_export_import.py` | Ghidra | Jython *or* Ghidrathon (Python 3) |

---

## Usage

### IDA Pro

1. **File → Script file…** → select `ida_export_import.py`
2. A dialog asks **Export** (YES) or **Import** (NO).
3. On export, select which categories to include (functions, labels, comments, structs, enums) and choose a save path.
4. On import, select the `.json` file — symbols are applied to the current IDB.

### Ghidra

1. Open the **Script Manager** (Window → Script Manager).
2. Add the `fromIDAtoGhidra/` folder to the script directories (if not done yet).
3. Run `ghidra_export_import.py`.
4. A dialog asks **Export** or **Import**.
5. On export choose categories and a save path.
6. On import select the `.json` file — symbols are applied inside a single undo-able transaction.

---

## Notes

- **Image-base awareness** — the JSON records the original image base.
  If the binary is loaded at a different base in the target tool, you will
  need to adjust addresses manually (or extend the scripts with a rebase
  offset – PRs welcome).
- Struct imports in Ghidra are placed under the `/imported` category path
  to avoid conflicts with auto-analysis types.
- Comment type mapping:
  - `eol` = end-of-line (IDA regular comment / Ghidra EOL comment)
  - `repeatable` = IDA repeatable comment / Ghidra repeatable comment
  - `pre` / `post` / `plate` = Ghidra-specific; imported as `pre` in IDA where applicable
  - `func` / `func_repeatable` = function-level comments in both tools

## Author

Gabriel Gonzalez Garcia — [www.gabrielcybersecurity.com](https://www.gabrielcybersecurity.com)
