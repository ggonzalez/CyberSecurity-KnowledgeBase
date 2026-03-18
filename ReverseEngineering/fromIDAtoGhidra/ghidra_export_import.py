# -*- coding: utf-8 -*-
# Ghidra <-> IDA Symbol Exchange -- Ghidra side
# ==============================================
# Export / import symbols using a shared JSON format so the same file
# can be consumed by the companion IDA script.
#
# Supported symbol types:
#   - Functions  (address + name + optional signature)
#   - Labels     (named addresses that are NOT functions)
#   - Comments   (EOL, repeatable/pre/post/plate, function comments)
#   - Structs    (full definition with typed members)
#   - Enums      (name + member/value pairs)
#   - Segments   (name, start/end address, permissions, type)
#
# Usage:
#   Ghidra -> Script Manager -> Run this script
#   (works with both Jython and Ghidrathon / Python 3)
#
# Author : Gabriel Gonzalez Garcia -- www.gabrielcybersecurity.com
# @category Symbol Exchange
# @menupath Tools.Symbol Exchange
# @runtime Jython

from __future__ import print_function

import json
import os

# Ghidra Java API imports -- available when running inside Ghidra
from ghidra.program.model.symbol import SymbolType, SourceType
from ghidra.program.model.data import (
    StructureDataType, CategoryPath, EnumDataType,
    ByteDataType, WordDataType, DWordDataType, QWordDataType,
    CharDataType, UnsignedCharDataType, ArrayDataType,
    ShortDataType, UnsignedShortDataType,
    IntegerDataType, UnsignedIntegerDataType,
    LongLongDataType, UnsignedLongLongDataType,
    Undefined1DataType, Undefined2DataType, Undefined4DataType, Undefined8DataType,
)
from ghidra.program.model.listing import CodeUnit
from ghidra.app.cmd.function import CreateFunctionCmd
from ghidra.program.model.mem import MemoryBlockType

try:
    # Python 3 / Ghidrathon
    from datetime import datetime
    _now_str = lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S")
except Exception:
    import time
    _now_str = lambda: time.strftime("%Y-%m-%d %H:%M:%S")


# ------------------------------------------------------------------ #
#  File-format version (must match the IDA script)                    #
# ------------------------------------------------------------------ #
FORMAT_VERSION = "1.1"


# ------------------------------------------------------------------ #
#  Convenience wrappers for the Ghidra flat-API objects               #
# ------------------------------------------------------------------ #
def _addr(offset):
    """Create an Address from an integer or hex string."""
    if isinstance(offset, str):
        offset = int(offset, 16)
    return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset)


def _txn(label):
    """Start a Ghidra transaction (returns id for commit)."""
    return currentProgram.startTransaction(label)


def _commit(tid):
    currentProgram.endTransaction(tid, True)


# ================================================================== #
#  EXPORT helpers                                                     #
# ================================================================== #

def _export_functions():
    fm = currentProgram.getFunctionManager()
    result = []
    for func in fm.getFunctions(True):  # forward iteration
        entry = func.getEntryPoint()
        sig = func.getSignature().getPrototypeString() if func.getSignature() else ""
        result.append({
            "address": "0x{:X}".format(entry.getOffset()),
            "name": func.getName(),
            "prototype": sig,
        })
    return result


def _export_labels():
    st = currentProgram.getSymbolTable()
    fm = currentProgram.getFunctionManager()
    result = []
    for sym in st.getAllSymbols(True):
        # Skip function symbols -- already covered
        if sym.getSymbolType() == SymbolType.FUNCTION:
            continue
        # Skip default/dynamic names
        if sym.getSource() == SourceType.DEFAULT:
            continue
        addr = sym.getAddress()
        if addr is None or addr.isExternalAddress():
            continue
        result.append({
            "address": "0x{:X}".format(addr.getOffset()),
            "name": sym.getName(),
        })
    return result


def _export_comments():
    listing = currentProgram.getListing()
    addrSet = currentProgram.getMemory()
    result = []

    # Only visit addresses that carry a comment (fast indexed lookup)
    _COMMENT_TYPES = [
        (CodeUnit.EOL_COMMENT,        "eol"),
        (CodeUnit.REPEATABLE_COMMENT, "repeatable"),
        (CodeUnit.PRE_COMMENT,        "pre"),
        (CodeUnit.POST_COMMENT,       "post"),
        (CodeUnit.PLATE_COMMENT,      "plate"),
    ]

    for ghidra_type, label in _COMMENT_TYPES:
        it = listing.getCommentAddressIterator(ghidra_type, addrSet, True)
        while it.hasNext():
            addr = it.next()
            cu = listing.getCodeUnitAt(addr)
            if cu is None:
                continue
            text = cu.getComment(ghidra_type)
            if text:
                result.append({
                    "address": "0x{:X}".format(addr.getOffset()),
                    "type": label,
                    "text": text,
                })

    # Function-level comments
    fm = currentProgram.getFunctionManager()
    for func in fm.getFunctions(True):
        cmt = func.getComment()
        if cmt:
            result.append({
                "address": "0x{:X}".format(func.getEntryPoint().getOffset()),
                "type": "func",
                "text": cmt,
            })
        rcmt = func.getRepeatableComment()
        if rcmt:
            result.append({
                "address": "0x{:X}".format(func.getEntryPoint().getOffset()),
                "type": "func_repeatable",
                "text": rcmt,
            })

    return result


def _ghidra_type_str(dt, size):
    """Return a portable C-style type string for a data-type component."""
    name = dt.getName() if dt else ""
    if not name:
        return "uint8_t[{}]".format(size)
    return name


def _export_structs():
    dtm = currentProgram.getDataTypeManager()
    result = []
    for dt in dtm.getAllStructures():
        members = []
        for comp in dt.getComponents():
            members.append({
                "offset": comp.getOffset(),
                "name": comp.getFieldName() or "field_{:X}".format(comp.getOffset()),
                "type": _ghidra_type_str(comp.getDataType(), comp.getLength()),
                "size": comp.getLength(),
            })
        result.append({
            "name": dt.getName(),
            "size": dt.getLength(),
            "members": members,
        })
    return result


def _export_segments():
    """Export all memory blocks (segments) with address ranges and permissions."""
    mem = currentProgram.getMemory()
    result = []
    for block in mem.getBlocks():
        perms = ""
        if block.isRead():    perms += "r"
        if block.isWrite():   perms += "w"
        if block.isExecute(): perms += "x"

        start = block.getStart().getOffset()
        end   = block.getEnd().getOffset() + 1  # Ghidra end is inclusive

        # Determine type string
        if block.isInitialized():
            stype = "CODE" if block.isExecute() else "DATA"
        else:
            stype = "BSS"

        result.append({
            "name":        block.getName(),
            "start":       "0x{:X}".format(start),
            "end":         "0x{:X}".format(end),
            "size":        end - start,
            "permissions": perms,
            "type":        stype,
            "class":       "",
            "bitness":     2 if currentProgram.getDefaultPointerSize() == 8 else 1,
            "align":       0,
            "initialized": block.isInitialized(),
            "volatile":    block.isVolatile(),
        })
    return result


def _export_enums():
    dtm = currentProgram.getDataTypeManager()
    result = []
    for dt in dtm.getAllDataTypes():
        if not isinstance(dt, EnumDataType):
            continue
        members = []
        for name in dt.getNames():
            members.append({"name": name, "value": dt.getValue(name)})
        result.append({
            "name": dt.getName(),
            "width": dt.getLength(),
            "members": members,
        })
    return result


# ================================================================== #
#  IMPORT helpers                                                     #
# ================================================================== #

def _import_functions(entries):
    fm = currentProgram.getFunctionManager()
    ok = 0
    for e in entries:
        addr = _addr(e["address"])
        name = e["name"]

        func = fm.getFunctionAt(addr)
        if func is None:
            # Try to create the function first
            cmd = CreateFunctionCmd(addr)
            cmd.applyTo(currentProgram)
            func = fm.getFunctionAt(addr)

        if func is not None:
            func.setName(name, SourceType.USER_DEFINED)
            ok += 1
        else:
            # At minimum set a label
            currentProgram.getSymbolTable().createLabel(addr, name, SourceType.USER_DEFINED)
            ok += 1
    return ok


def _import_labels(entries):
    st = currentProgram.getSymbolTable()
    ok = 0
    for e in entries:
        addr = _addr(e["address"])
        name = e["name"]
        st.createLabel(addr, name, SourceType.USER_DEFINED)
        ok += 1
    return ok


_COMMENT_MAP = {
    "eol":       CodeUnit.EOL_COMMENT,
    "repeatable": CodeUnit.REPEATABLE_COMMENT,
    "pre":       CodeUnit.PRE_COMMENT,
    "post":      CodeUnit.POST_COMMENT,
    "plate":     CodeUnit.PLATE_COMMENT,
}

def _import_comments(entries):
    listing = currentProgram.getListing()
    fm = currentProgram.getFunctionManager()
    ok = 0
    for e in entries:
        addr = _addr(e["address"])
        ctype = e["type"]
        text = e["text"]

        if ctype in _COMMENT_MAP:
            cu = listing.getCodeUnitAt(addr)
            if cu is not None:
                cu.setComment(_COMMENT_MAP[ctype], text)
                ok += 1
        elif ctype == "func":
            func = fm.getFunctionAt(addr)
            if func:
                func.setComment(text)
                ok += 1
        elif ctype == "func_repeatable":
            func = fm.getFunctionAt(addr)
            if func:
                func.setRepeatableComment(text)
                ok += 1
    return ok


def _resolve_dt(type_str, size):
    """Map a portable type-name to a Ghidra DataType."""
    t = type_str.lower().strip()

    # Handle arrays  e.g. "uint8_t[16]"  or "char[32]"
    if "[" in t and "]" in t:
        base = t.split("[")[0].strip()
        try:
            count = int(t.split("[")[1].split("]")[0])
        except ValueError:
            count = size
        inner = _resolve_dt(base, 1)
        return ArrayDataType(inner, count, inner.getLength())

    if t in ("uint8_t", "unsigned char", "uchar", "byte"):
        return UnsignedCharDataType.dataType
    if t in ("int8_t", "signed char", "char"):
        return CharDataType.dataType
    if t in ("uint16_t", "unsigned short", "ushort", "word"):
        return UnsignedShortDataType.dataType
    if t in ("int16_t", "short"):
        return ShortDataType.dataType
    if t in ("uint32_t", "unsigned int", "uint", "dword"):
        return UnsignedIntegerDataType.dataType
    if t in ("int32_t", "int"):
        return IntegerDataType.dataType
    if t in ("uint64_t", "unsigned long long", "qword"):
        return UnsignedLongLongDataType.dataType
    if t in ("int64_t", "long long"):
        return LongLongDataType.dataType

    # Fallback by size
    return {1: Undefined1DataType.dataType,
            2: Undefined2DataType.dataType,
            4: Undefined4DataType.dataType,
            8: Undefined8DataType.dataType}.get(size, Undefined1DataType.dataType)


def _import_structs(entries):
    dtm = currentProgram.getDataTypeManager()
    cat = CategoryPath("/imported")
    ok = 0
    for s in entries:
        sname = s["name"]
        ssize = s["size"]

        # Remove existing struct with the same name under /imported
        existing = dtm.getDataType(cat, sname)
        if existing is not None:
            dtm.remove(existing, monitor)

        struct = StructureDataType(cat, sname, 0)
        for m in s.get("members", []):
            dt = _resolve_dt(m["type"], m["size"])
            struct.insertAtOffset(m["offset"], dt, m["size"], m["name"], None)

        dtm.addDataType(struct, None)
        ok += 1
    return ok


def _import_segments(entries):
    """Import segments as Ghidra memory blocks."""
    mem = currentProgram.getMemory()
    ok = 0
    for s in entries:
        name  = s["name"]
        start = _addr(s["start"])
        size  = s["size"]

        perms = s.get("permissions", "")
        is_read    = "r" in perms
        is_write   = "w" in perms
        is_execute = "x" in perms
        is_volatile = s.get("volatile", False)

        stype = s.get("type", "DATA")

        # Check if a block already exists at this address
        existing_block = mem.getBlock(start)
        if existing_block is not None:
            # Update name and permissions on the existing block
            try:
                existing_block.setName(name)
                existing_block.setRead(is_read)
                existing_block.setWrite(is_write)
                existing_block.setExecute(is_execute)
                existing_block.setVolatile(is_volatile)
                ok += 1
            except Exception as ex:
                print("Warning: could not update block '{}': {}".format(name, ex))
            continue

        # Create a new memory block
        try:
            if stype == "BSS" or not s.get("initialized", True):
                block = mem.createUninitializedBlock(name, start, size, False)
            else:
                block = mem.createInitializedBlock(name, start, size, 0, monitor, False)

            block.setRead(is_read)
            block.setWrite(is_write)
            block.setExecute(is_execute)
            block.setVolatile(is_volatile)
            ok += 1
        except Exception as ex:
            print("Warning: could not create block '{}' at {}: {}".format(name, s["start"], ex))

    return ok


def _import_enums(entries):
    dtm = currentProgram.getDataTypeManager()
    cat = CategoryPath("/imported")
    ok = 0
    for e in entries:
        existing = dtm.getDataType(cat, e["name"])
        if existing is not None:
            dtm.remove(existing, monitor)

        width = e.get("width", 4)
        if width < 1:
            width = 4
        enum = EnumDataType(cat, e["name"], width)
        for m in e.get("members", []):
            enum.add(m["name"], m["value"])

        dtm.addDataType(enum, None)
        ok += 1
    return ok


# ================================================================== #
#  Top-level export / import                                          #
# ================================================================== #

def do_export(filepath, what):
    data = {
        "format_version": FORMAT_VERSION,
        "source": "ghidra",
        "export_date": _now_str(),
        "binary_name": currentProgram.getName(),
        "image_base": "0x{:X}".format(currentProgram.getImageBase().getOffset()),
        "symbols": {},
    }

    counts = {}
    if what.get("functions"):
        lst = _export_functions()
        data["symbols"]["functions"] = lst
        counts["functions"] = len(lst)

    if what.get("labels"):
        lst = _export_labels()
        data["symbols"]["labels"] = lst
        counts["labels"] = len(lst)

    if what.get("comments"):
        lst = _export_comments()
        data["symbols"]["comments"] = lst
        counts["comments"] = len(lst)

    if what.get("structs"):
        lst = _export_structs()
        data["symbols"]["structs"] = lst
        counts["structs"] = len(lst)

    if what.get("enums"):
        lst = _export_enums()
        data["symbols"]["enums"] = lst
        counts["enums"] = len(lst)

    if what.get("segments"):
        lst = _export_segments()
        data["symbols"]["segments"] = lst
        counts["segments"] = len(lst)

    with open(filepath, "w") as f:
        json.dump(data, f, indent=2)

    msg = "Export complete -> {}\n".format(filepath)
    for k, v in counts.items():
        msg += "  {}: {}\n".format(k, v)
    print(msg)
    popup(msg)


def do_import(filepath):
    with open(filepath, "r") as f:
        raw = f.read()
    data = json.loads(raw)

    ver = data.get("format_version", "?")
    src = data.get("source", "unknown")
    print("Importing {} (format v{}, exported from {})".format(filepath, ver, src))

    syms = data.get("symbols", {})
    counts = {}

    tid = _txn("Symbol Exchange Import")
    try:
        # Import segments first so address spaces exist for everything else
        if "segments" in syms:
            counts["segments"] = _import_segments(syms["segments"])
        if "functions" in syms:
            counts["functions"] = _import_functions(syms["functions"])
        if "labels" in syms:
            counts["labels"] = _import_labels(syms["labels"])
        if "comments" in syms:
            counts["comments"] = _import_comments(syms["comments"])
        if "structs" in syms:
            counts["structs"] = _import_structs(syms["structs"])
        if "enums" in syms:
            counts["enums"] = _import_enums(syms["enums"])
    finally:
        _commit(tid)

    msg = "Import complete <- {}\n".format(filepath)
    for k, v in counts.items():
        msg += "  {}: {}\n".format(k, v)
    print(msg)
    popup(msg)


# ================================================================== #
#  UI entry point                                                     #
# ================================================================== #

def main():
    choice = askChoice("Symbol Exchange",
                       "Select operation:",
                       ["Export symbols to JSON", "Import symbols from JSON"],
                       "Export symbols to JSON")

    if choice is None:
        return

    if "Export" in choice:
        categories = askChoices("Export options",
                                "Select what to export:",
                                ["functions", "labels", "comments", "structs", "enums", "segments"])
        if not categories:
            popup("Nothing selected.")
            return

        what = {c: True for c in categories}

        filepath = askFile("Select export file", "Save")
        if filepath is None:
            return
        filepath = filepath.getAbsolutePath()
        if not filepath.endswith(".json"):
            filepath += ".json"

        do_export(filepath, what)

    else:  # Import
        f = askFile("Select symbol exchange JSON file", "Open")
        if f is None:
            return
        do_import(f.getAbsolutePath())


# ================================================================== #
if __name__ == "__main__":
    main()
