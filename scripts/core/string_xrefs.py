"""
title: String Xrefs
description: |
  Lists string literals and their data xrefs.
"""

import ida_kernwin
import ida_nalt
import idautils


def string_xrefs():
    strings = idautils.Strings(False)
    strings.setup(strtypes=[ida_nalt.STRTYPE_C, ida_nalt.STRTYPE_C_16])

    count = 0
    for s in strings:
        if s is None:
            continue
        sval = str(s).replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
        ida_kernwin.msg(f"{s.ea:08X}: {sval}\n")
        has_ref = False
        for ref in idautils.DataRefsTo(s.ea):
            ida_kernwin.msg(f"  xref {ref:08X}\n")
            has_ref = True
        if not has_ref:
            ida_kernwin.msg("  (no data xrefs)\n")
        count += 1

    ida_kernwin.msg(f"Total strings: {count}\n")


string_xrefs()
