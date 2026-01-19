"""
title: Register Values
description: |
  You can get the values of registers that IDA obtains through static analysis.
"""

import ida_auto
import ida_idp
import ida_kernwin
import ida_regfinder


def register_values():
    # Wait for auto-analysis to finish.
    ida_auto.auto_wait()

    # Get the register number for eax.
    reg: int = ida_idp.str2reg("eax")

    # Get the value **before** the instruction at address 0x140001A53.
    value: int | None = ida_regfinder.find_reg_value(0x140001A53, reg)
    ida_kernwin.msg(f"{value}\n")


register_values()
