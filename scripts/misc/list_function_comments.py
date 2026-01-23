"""
title: List Function Comments
description: |
  Prints regular and repeatable comments within the current function.
"""

import ida_auto
import ida_bytes
import ida_funcs
import ida_kernwin
import idautils


def list_function_comments():
    # Wait for auto-analysis to finish.
    ida_auto.auto_wait()

    ea = ida_kernwin.get_screen_ea()
    func = ida_funcs.get_func(ea)
    if not func:
        ida_kernwin.msg("No function at the cursor.\n")
        return

    name = ida_funcs.get_func_name(func.start_ea)
    ida_kernwin.msg(f"Comments in {name} ({func.start_ea:#x}):\n")

    found = False
    for item in idautils.FuncItems(func.start_ea):
        cmt = ida_bytes.get_cmt(item, 0)
        rcmt = ida_bytes.get_cmt(item, 1)
        if cmt:
            ida_kernwin.msg(f"  {item:#x} cmt: {cmt}\n")
            found = True
        if rcmt:
            ida_kernwin.msg(f"  {item:#x} rcmt: {rcmt}\n")
            found = True

    if not found:
        ida_kernwin.msg("  <none>\n")


list_function_comments()
