"""
title: List Structures
description: |
  Prints the name and size of all structures in the database.
"""

import ida_auto
import ida_kernwin
import ida_typeinf


def list_structs():
    # Wait for auto-analysis to finish.
    ida_auto.auto_wait()

    structs = []
    limit = ida_typeinf.get_ordinal_limit()
    for ordinal in range(1, limit):
        tif = ida_typeinf.tinfo_t()
        if not tif.get_numbered_type(ordinal, ida_typeinf.BTF_STRUCT):
            continue
        name = tif.get_type_name()
        size = tif.get_size()
        structs.append((name, size, ordinal))

    ida_kernwin.msg(f"Structs: {len(structs)}\n")
    if not structs:
        return

    for name, size, ordinal in structs:
        ida_kernwin.msg(f"  {name} size={size} (ord={ordinal})\n")


list_structs()
