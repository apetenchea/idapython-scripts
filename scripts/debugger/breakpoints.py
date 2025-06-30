"""
title: Breakpoints
description: |
  For debugger interaction, the debugger settings need to be configured first.
"""

import ida_dbg


def set_debugger_breakpoint(pid: int, ea: int):
    # Attach to the process with the given PID.
    # The process will be suspended.
    ida_dbg.attach_process(pid)

    # Set a breakpoint at the specified address.
    # Later on you can use the `ida_dbg.del_bpt(ea)` function to remove it.
    ida_dbg.add_bpt(ea)

    # Continue the process execution.
    ida_dbg.continue_process()
