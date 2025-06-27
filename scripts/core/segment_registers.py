"""
title: Segment Registers
description: |
  Segment register are usually fixed registers whose values can be set by the user.
  These are, for example, the T register on ARM, or the TOC register on PowerPC.
"""

import sys

import ida_idp
import ida_pro
import ida_segment
import ida_segregs
import idc


def main(output):
    # Get the segment register number for the global segment.
    reg: int = ida_idp.str2sreg("gs")

    # Get the .pdata segment object.
    seg: ida_segment.segment_t = ida_segment.get_segm_by_name(".pdata")

    # Set the default value of the code segment register for the '.pdata' segment.
    res: bool = ida_segregs.set_default_sreg_value(seg, reg, 0x4000)
    print(res, file=output)

    # Going from address 0x4624F4 downwards, change the value of the segment register.
    ea = 0x140001A01
    res: bool = ida_segregs.split_sreg_range(ea, reg, 0x401000, ida_segregs.SR_user)
    print(res, file=output)

    # Get the value of the segment register.
    ea = 0x140001A16
    val: int = ida_segregs.get_sreg(ea, reg)
    print(hex(val), file=output)

    # Get how many ranges the segment register has.
    qty: int = ida_segregs.get_sreg_ranges_qty(reg)
    print(qty, file=output)


if __name__ == "__main__":
    if len(idc.ARGV) > 1:
        with open(idc.ARGV[1], "w") as f:
            main(f)
            f.flush()
    else:
        main(sys.stdout)
    ida_pro.qexit(0)
