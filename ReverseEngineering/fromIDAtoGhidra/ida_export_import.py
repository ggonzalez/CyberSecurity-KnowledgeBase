"""
IDA <-> Ghidra Symbol Exchange — IDA side
==========================================
Export / import symbols using a shared JSON format so the same file
can be consumed by the companion Ghidra script.

Supported symbol types:
  - Functions  (address + name + optional prototype)
  - Labels     (named addresses that are NOT functions)
  - Comments   (EOL, repeatable/anterior/posterior, function comments)
  - Structs    (full definition with typed members)
  - Enums      (name + member/value pairs)
  - Segments   (name, start/end address, permissions, class/type)

Usage (inside IDA):
  File -> Script file…  ->  ida_export_import.py
  Then follow the dialog prompts.

Author : Gabriel Gonzalez Garcia — www.gabrielcybersecurity.com
"""

from __future__ import print_function

import json
import datetime
import os

import ida_kernwin
import ida_funcs
import ida_name
import ida_struct
import ida_typeinf
import ida_idaapi
import ida_bytes
import ida_nalt
import ida_enum
import ida_segment
import idautils
import idc

# ------------------------------------------------------------------ #
#  File-format version (bump when schema changes)                     #
# ------------------------------------------------------------------ #
FORMAT_VERSION = "1.1"


# ================================================================== #
#  EXPORT helpers                                                     #
# ================================================================== #

def _export_functions():
    """Return list of {address, name, prototype}."""
    result = []
    for ea in idautils.Functions():
        name = ida_funcs.get_func_name(ea)
        if not name:
            continue

        # Try to grab the demangled / prototype string
        proto = idc.get_type(ea) or ""

        result.append({
            "address": "0x{:X}".format(ea),
            "name": name,
            "prototype": proto,
        })
    return result


def _export_labels():
    """Return named addresses that are *not* function entry points."""
    func_addrs = set(idautils.Functions())
    result = []
    for ea, name in idautils.Names():
        if ea in func_addrs:
            continue
        result.append({
            "address": "0x{:X}".format(ea),
            "name": name,
        })
    return result


def _export_comments():
    """Export all user comments (EOL, repeatable, anterior, posterior, function)."""
    result = []

    for ea in idautils.Heads():
        # Regular (EOL) comment
        cmt = idc.get_cmt(ea, 0)
        if cmt:
            result.append({"address": "0x{:X}".format(ea), "type": "eol", "text": cmt})

        # Repeatable comment
        rcmt = idc.get_cmt(ea, 1)
        if rcmt:
            result.append({"address": "0x{:X}".format(ea), "type": "repeatable", "text": rcmt})

    # Function comments
    for ea in idautils.Functions():
        fcmt = idc.get_func_cmt(ea, 0)
        if fcmt:
            result.append({"address": "0x{:X}".format(ea), "type": "func", "text": fcmt})
        frcmt = idc.get_func_cmt(ea, 1)
        if frcmt:
            result.append({"address": "0x{:X}".format(ea), "type": "func_repeatable", "text": frcmt})

    return result


def _get_member_type_str(member):
    """Best-effort type string for a struct member."""
    tif = ida_typeinf.tinfo_t()
    if ida_struct.get_member_tinfo(tif, member):
        s = str(tif)
        if s:
            return s

    flag = member.flag
    size = ida_struct.get_member_size(member)

    if ida_bytes.is_byte(flag):
        return {1: "uint8_t", 2: "uint16_t", 4: "uint32_t", 8: "uint64_t"}.get(size, "uint8_t[{}]".format(size))
    if ida_bytes.is_word(flag):
        return "uint16_t"
    if ida_bytes.is_dword(flag):
        return "uint32_t"
    if ida_bytes.is_qword(flag):
        return "uint64_t"
    if ida_bytes.is_strlit(flag):
        return "char[{}]".format(size)
    return "uint8_t[{}]".format(size)


def _export_structs():
    """Export every struct definition."""
    result = []
    for idx in range(ida_struct.get_struc_qty()):
        sid = ida_struct.get_struc_by_idx(idx)
        sobj = ida_struct.get_struc(sid)
        if not sobj:
            continue

        sname = ida_struct.get_struc_name(sid)
        ssize = ida_struct.get_struc_size(sobj)
        members = []

        for midx in range(sobj.memqty):
            m = sobj.get_member(midx)
            if not m:
                continue
            members.append({
                "offset": m.soff,
                "name": ida_struct.get_member_name(m.id),
                "type": _get_member_type_str(m),
                "size": ida_struct.get_member_size(m),
            })

        result.append({"name": sname, "size": ssize, "members": members})
    return result


def _export_segments():
    """Export all segments with address ranges, permissions, and class."""
    result = []
    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        if not seg:
            continue

        name = ida_segment.get_segm_name(seg) or ""
        seg_class = ida_segment.get_segm_class(seg) or ""

        # Permission bitmask: 1=read, 2=write, 4=exec
        perms = ""
        if seg.perm & 1: perms += "r"
        if seg.perm & 2: perms += "w"
        if seg.perm & 4: perms += "x"

        # Segment type
        seg_type_map = {
            ida_segment.SEG_NORM: "CODE",
            ida_segment.SEG_DATA: "DATA",
            ida_segment.SEG_BSS:  "BSS",
            ida_segment.SEG_XTRN: "EXTERN",
            ida_segment.SEG_NULL: "NULL",
        }
        stype = seg_type_map.get(seg.type, "OTHER")

        result.append({
            "name":       name,
            "start":      "0x{:X}".format(seg.start_ea),
            "end":        "0x{:X}".format(seg.end_ea),
            "size":       seg.end_ea - seg.start_ea,
            "permissions": perms,
            "type":       stype,
            "class":      seg_class,
            "bitness":    seg.bitness,   # 0=16, 1=32, 2=64
            "align":      seg.align,
        })
    return result


def _export_enums():
    """Export every enum definition."""
    result = []
    for i in range(ida_enum.get_enum_qty()):
        eid = ida_enum.getn_enum(i)
        ename = ida_enum.get_enum_name(eid)
        members = []

        # Walk all enum members using the visitor pattern
        bmask = ida_enum.DEFMASK
        val = ida_enum.get_first_enum_member(eid, bmask)
        while val != ida_idaapi.BADADDR:
            cid = ida_enum.get_enum_member(eid, val, 0, bmask)
            if cid != ida_idaapi.BADADDR:
                mname = ida_enum.get_enum_member_name(cid)
                if mname:
                    members.append({"name": mname, "value": val})
            val = ida_enum.get_next_enum_member(eid, val, bmask)

        result.append({"name": ename, "width": ida_enum.get_enum_width(eid), "members": members})
    return result


# ================================================================== #
#  IMPORT helpers                                                     #
# ================================================================== #

def _import_functions(entries):
    ok = 0
    for e in entries:
        ea = int(e["address"], 16)
        name = e["name"]
        proto = e.get("prototype", "")

        # Ensure a function exists at the address
        if not ida_funcs.get_func(ea):
            ida_funcs.add_func(ea)

        if ida_name.set_name(ea, name, ida_name.SN_NOWARN | ida_name.SN_NOCHECK):
            ok += 1

        # Apply prototype if available
        if proto:
            idc.SetType(ea, proto)

    return ok


def _import_labels(entries):
    ok = 0
    for e in entries:
        ea = int(e["address"], 16)
        name = e["name"]
        if ida_name.set_name(ea, name, ida_name.SN_NOWARN | ida_name.SN_NOCHECK):
            ok += 1
    return ok


def _import_comments(entries):
    ok = 0
    for e in entries:
        ea = int(e["address"], 16)
        ctype = e["type"]
        text = e["text"]
        try:
            if ctype == "eol":
                idc.set_cmt(ea, text, 0)
            elif ctype == "repeatable":
                idc.set_cmt(ea, text, 1)
            elif ctype == "func":
                idc.set_func_cmt(ea, text, 0)
            elif ctype == "func_repeatable":
                idc.set_func_cmt(ea, text, 1)
            ok += 1
        except Exception:
            pass
    return ok


def _parse_member_type(type_str):
    """Return (base, array_size|None)."""
    if "[" in type_str and "]" in type_str:
        base = type_str.split("[")[0]
        try:
            arr = int(type_str.split("[")[1].split("]")[0])
            return base, arr
        except ValueError:
            pass
    return type_str, None


def _import_structs(entries):
    ok = 0
    for s in entries:
        sname = s["name"]

        # Remove existing struct with the same name
        sid = ida_struct.get_struc_id(sname)
        if sid != ida_idaapi.BADADDR:
            ida_struct.del_struc(ida_struct.get_struc(sid))

        sid = ida_struct.add_struc(ida_idaapi.BADADDR, sname, 0)
        if sid == ida_idaapi.BADADDR:
            continue

        sobj = ida_struct.get_struc(sid)

        for m in s.get("members", []):
            base, arr = _parse_member_type(m["type"])
            msize = m["size"]

            if "int8" in base or "char" in base:
                flag = ida_bytes.FF_BYTE; unit = 1
            elif "int16" in base:
                flag = ida_bytes.FF_WORD; unit = 2
            elif "int32" in base:
                flag = ida_bytes.FF_DWORD; unit = 4
            elif "int64" in base:
                flag = ida_bytes.FF_QWORD; unit = 8
            else:
                flag = ida_bytes.FF_BYTE; unit = msize

            total = (unit * arr) if arr else unit
            ida_struct.add_struc_member(sobj, m["name"], m["offset"], flag, None, total)

        ok += 1
    return ok


def _import_segments(entries):
    """Import segments — create or rename segments to match the export."""
    ok = 0
    for s in entries:
        name  = s["name"]
        start = int(s["start"], 16)
        end   = int(s["end"], 16)
        sclass = s.get("class", "")

        # Parse permissions — bitmask: 1=read, 2=write, 4=exec
        perm_str = s.get("permissions", "")
        perm = 0
        if "r" in perm_str: perm |= 1
        if "w" in perm_str: perm |= 2
        if "x" in perm_str: perm |= 4

        bitness = s.get("bitness", 1)  # default 32-bit
        align   = s.get("align", 0)

        # Check if a segment already covers this range
        existing = ida_segment.getseg(start)
        if existing and existing.start_ea == start and existing.end_ea == end:
            # Just rename / update permissions
            ida_segment.set_segm_name(existing, name)
            existing.perm = perm
            ida_segment.update_segm(existing)
            ok += 1
            continue

        # Create a new segment
        seg = ida_segment.segment_t()
        seg.start_ea = start
        seg.end_ea   = end
        seg.perm     = perm
        seg.bitness  = bitness
        seg.align    = align

        if ida_segment.add_segm_ex(seg, name, sclass, ida_segment.ADDSEG_NOSREG | ida_segment.ADDSEG_OR_DIE):
            ok += 1
        else:
            print("Warning: could not create segment '{}' at 0x{:X}-0x{:X}".format(name, start, end))

    return ok


def _import_enums(entries):
    ok = 0
    for e in entries:
        ename = e["name"]
        width = e.get("width", 0)

        eid = ida_enum.get_enum(ename)
        if eid != ida_idaapi.BADADDR:
            ida_enum.del_enum(eid)

        eid = ida_enum.add_enum(ida_idaapi.BADADDR, ename, 0)
        if eid == ida_idaapi.BADADDR:
            continue

        if width:
            ida_enum.set_enum_width(eid, width)

        for m in e.get("members", []):
            ida_enum.add_enum_member(eid, m["name"], m["value"])

        ok += 1
    return ok


# ================================================================== #
#  Top-level export / import                                          #
# ================================================================== #

def do_export(filepath, what):
    """
    Parameters
    ----------
    filepath : str
    what     : dict  –  keys are category names, values are bool
    """
    data = {
        "format_version": FORMAT_VERSION,
        "source": "ida",
        "export_date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "binary_name": os.path.basename(idc.get_input_file_path()),
        "image_base": "0x{:X}".format(idautils.peutils_t().imagebase if hasattr(idautils, "peutils_t") else ida_nalt.get_imagebase()),
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

    msg = "Export complete → {}\n\n".format(filepath)
    for k, v in counts.items():
        msg += "  {}: {}\n".format(k, v)
    print(msg)
    ida_kernwin.info(msg)


def do_import(filepath):
    with open(filepath, "r") as f:
        data = json.load(f)

    ver = data.get("format_version", "?")
    src = data.get("source", "unknown")
    print("Importing {} (format v{}, exported from {})".format(filepath, ver, src))

    syms = data.get("symbols", {})
    counts = {}

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

    msg = "Import complete ← {}\n\n".format(filepath)
    for k, v in counts.items():
        msg += "  {}: {}\n".format(k, v)
    print(msg)
    ida_kernwin.info(msg)
    ida_kernwin.refresh_idaview_anyway()


# ================================================================== #
#  UI – IDA Form for export options (checkboxes)                      #
# ================================================================== #

class ExportForm(ida_kernwin.Form):
    """A form with checkboxes for selecting what to export."""

    def __init__(self):
        ida_kernwin.Form.__init__(self, r"""STARTITEM 0
IDA <-> Ghidra Symbol Exchange  --  Export

<Functions:{cbFunctions}>
<Labels / Names:{cbLabels}>
<Comments:{cbComments}>
<Structs:{cbStructs}>
<Enums:{cbEnums}>
<Segments:{cbSegments}>
""", {
            "cbFunctions": ida_kernwin.Form.ChkGroupItemControl("grpExport", 0),
            "cbLabels":    ida_kernwin.Form.ChkGroupItemControl("grpExport", 1),
            "cbComments":  ida_kernwin.Form.ChkGroupItemControl("grpExport", 2),
            "cbStructs":   ida_kernwin.Form.ChkGroupItemControl("grpExport", 3),
            "cbEnums":     ida_kernwin.Form.ChkGroupItemControl("grpExport", 4),
            "cbSegments":  ida_kernwin.Form.ChkGroupItemControl("grpExport", 5),
            "grpExport":   ida_kernwin.Form.ChkGroupControl(
                ("cbFunctions", "cbLabels", "cbComments",
                 "cbStructs", "cbEnums", "cbSegments"),
                value=0x3F),  # all checked by default (6 bits)
        })


# ================================================================== #
#  UI entry point                                                     #
# ================================================================== #

def main():
    # Step 1 – Dropdown: Export or Import
    choice = ida_kernwin.ask_buttons(
        "Export", "Import", "Cancel",
        ida_kernwin.ASKBTN_YES,
        "IDA <-> Ghidra Symbol Exchange\n\n"
        "Choose an operation:")

    if choice == ida_kernwin.ASKBTN_CANCEL:  # Cancel
        return

    if choice == ida_kernwin.ASKBTN_YES:  # Export
        # Step 2 – Checkbox form
        form = ExportForm()
        form.Compile()
        ok = form.Execute()
        if ok != 1:
            form.Free()
            return

        grp = form.grpExport.value
        form.Free()

        what = {
            "functions": bool(grp & (1 << 0)),
            "labels":    bool(grp & (1 << 1)),
            "comments":  bool(grp & (1 << 2)),
            "structs":   bool(grp & (1 << 3)),
            "enums":     bool(grp & (1 << 4)),
            "segments":  bool(grp & (1 << 5)),
        }

        if not any(what.values()):
            ida_kernwin.warning("Nothing selected -- aborting.")
            return

        filepath = ida_kernwin.ask_file(1, "*.json", "Save symbol exchange file")
        if not filepath:
            return
        do_export(filepath, what)

    else:  # Import
        filepath = ida_kernwin.ask_file(0, "*.json", "Open symbol exchange file")
        if not filepath:
            return
        do_import(filepath)


if __name__ == "__main__":
    main()
