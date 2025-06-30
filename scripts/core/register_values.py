"""
title: Register Values
description: |
  You can get the values of registers that IDA obtains through static analysis.
"""

import sys

import ida_auto
import ida_idp
import ida_pro
import ida_regfinder
import idc


def main(output):
    # Wait for auto-analysis to finish.
    ida_auto.auto_wait()

    # Get the register number for eax.
    reg: int = ida_idp.str2reg("eax")

    # Get the value **before** the instruction at address 0x140001A53.
    value: int | None = ida_regfinder.find_reg_value(0x140001A53, reg)
    print(value, file=output)


if __name__ == "__main__":
    if len(idc.ARGV) > 1:
        with open(idc.ARGV[1], "w") as f:
            main(f)
            f.flush()
    else:
        main(sys.stdout)
    ida_pro.qexit(0)
