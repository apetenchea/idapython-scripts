"""
title: List Function Callers
description: |
  Lists callers of the function at the cursor, grouped by caller function.
"""

import ida_auto
import ida_funcs
import ida_kernwin
import idautils


def list_function_callers():
    # Wait for auto-analysis to finish.
    ida_auto.auto_wait()

    ea = ida_kernwin.get_screen_ea()
    callee = ida_funcs.get_func(ea)
    if not callee:
        ida_kernwin.msg("No function at the cursor.\n")
        return

    callers = {}
    orphans = []

    for xref in idautils.CodeRefsTo(callee.start_ea, 0):
        caller = ida_funcs.get_func(xref)
        if caller:
            callers.setdefault(caller.start_ea, []).append(xref)
        else:
            orphans.append(xref)

    callee_name = ida_funcs.get_func_name(callee.start_ea)
    ida_kernwin.msg(f"Callers of {callee_name} ({callee.start_ea:#x}):\n")

    if not callers and not orphans:
        ida_kernwin.msg("  <none>\n")
        return

    for caller_ea in sorted(callers.keys()):
        name = ida_funcs.get_func_name(caller_ea)
        sites = " ".join(f"{site:#x}" for site in sorted(callers[caller_ea]))
        ida_kernwin.msg(f"  {name} ({caller_ea:#x}): {sites}\n")

    if orphans:
        sites = " ".join(f"{site:#x}" for site in sorted(orphans))
        ida_kernwin.msg(f"  <no_func>: {sites}\n")


list_function_callers()
