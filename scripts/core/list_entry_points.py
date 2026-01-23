"""
title: List Entry Points
description: |
  Lists entry points and their ordinals.
"""

import ida_auto
import ida_entry
import ida_idaapi
import ida_kernwin


def list_entry_points():
    # Wait for auto-analysis to finish.
    ida_auto.auto_wait()

    qty = ida_entry.get_entry_qty()
    ida_kernwin.msg(f"Entry points: {qty}\n")
    if qty == 0:
        return

    for i in range(qty):
        ordinal = ida_entry.get_entry_ordinal(i)
        ea = ida_entry.get_entry(ordinal)
        if ea == ida_idaapi.BADADDR:
            continue
        name = ida_entry.get_entry_name(ordinal)
        ida_kernwin.msg(f"  {name} ord={ordinal} ea={ea:#x}\n")


list_entry_points()
