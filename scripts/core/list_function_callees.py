"""
title: List Function Callees
description: |
  Walks the current function and prints call targets for each call
  instruction found.
"""

import ida_funcs
import ida_idp
import ida_kernwin
import ida_ua
import idautils


def list_function_callees():
    ea = ida_kernwin.get_screen_ea()
    func = ida_funcs.get_func(ea)
    if not func:
        ida_kernwin.msg("No function at the current cursor location.\n")
        return

    func_name = ida_funcs.get_func_name(func.start_ea) or "<unnamed>"
    ida_kernwin.msg(
        f"Callees from {func_name} ({func.start_ea:08X})\n"
    )

    insn = ida_ua.insn_t()
    found = False
    for item_ea in idautils.FuncItems(func.start_ea):
        if not ida_ua.decode_insn(insn, item_ea):
            continue
        if not ida_idp.is_call_insn(insn):
            continue
        for callee_ea in idautils.CodeRefsFrom(item_ea, 0):
            callee_name = ida_funcs.get_func_name(callee_ea)
            if callee_name:
                ida_kernwin.msg(
                    f"  {item_ea:08X} -> {callee_ea:08X} {callee_name}\n"
                )
            else:
                ida_kernwin.msg(
                    f"  {item_ea:08X} -> {callee_ea:08X}\n"
                )
            found = True

    if not found:
        ida_kernwin.msg("No call references found in this function.\n")


list_function_callees()
