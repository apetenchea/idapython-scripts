"""
title: List Xrefs From Cursor
description: |
  Lists all xrefs originating from the current address.
"""

import ida_auto
import ida_kernwin
import idautils


def list_xrefs_from_cursor():
    # Wait for auto-analysis to finish.
    ida_auto.auto_wait()

    ea = ida_kernwin.get_screen_ea()
    ida_kernwin.msg(f"Xrefs from {ea:#x}:\n")

    any_xref = False
    for xref in idautils.XrefsFrom(ea, 0):
        any_xref = True
        ida_kernwin.msg(f"  to {xref.to:#x} type={xref.type}\n")

    if not any_xref:
        ida_kernwin.msg("  <none>\n")


list_xrefs_from_cursor()
