"""
title: Trace Register Values
description: |
  Walks the current function and prints points where a register's known value changes.
"""

import ida_auto
import ida_funcs
import ida_idp
import ida_kernwin
import ida_regfinder
import ida_ua
import idautils


def trace_register_values():
    # Wait for auto-analysis to finish.
    ida_auto.auto_wait()

    ea = ida_kernwin.get_screen_ea()
    func = ida_funcs.get_func(ea)
    if not func:
        ida_kernwin.msg("No function at the cursor.\n")
        return

    reg_name = ida_kernwin.ask_str("eax", 0, "Register name to trace")
    if not reg_name:
        return

    reg = ida_idp.str2reg(reg_name)
    if reg == -1:
        ida_kernwin.msg(f"Unknown register: {reg_name}\n")
        return

    last_val = None
    for insn_ea in idautils.FuncItems(func.start_ea):
        val = ida_regfinder.find_reg_value(insn_ea, reg)
        if val is None:
            continue
        if last_val is None or val != last_val:
            mnem = ida_ua.print_insn_mnem(insn_ea)
            ida_kernwin.msg(
                f"{insn_ea:#x} {mnem} -> {reg_name} = {val:#x}\n"
            )
            last_val = val


trace_register_values()
