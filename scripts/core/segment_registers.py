"""
title: Segment Registers
description: |
  Segment register are usually fixed registers whose values can be set by the user.
  These are, for example, the T register on ARM, or the TOC register on PowerPC.
"""

import ida_auto
import ida_idp
import ida_kernwin
import ida_segment
import ida_segregs


def segment_registers():
    # Wait for auto-analysis to finish.
    ida_auto.auto_wait()

    # Get the segment register number for the global segment.
    reg: int = ida_idp.str2sreg("gs")

    # Get the .pdata segment object.
    seg: ida_segment.segment_t = ida_segment.get_segm_by_name(".pdata")

    # Set the default value of the code segment register for the '.pdata' segment.
    res: bool = ida_segregs.set_default_sreg_value(seg, reg, 0x4000)
    ida_kernwin.msg(f"{res}\n")

    # Going from address 0x4624F4 downwards, change the value of the segment register.
    ea = 0x140001A01
    res: bool = ida_segregs.split_sreg_range(ea, reg, 0x401000, ida_segregs.SR_user)
    ida_kernwin.msg(f"{res}\n")

    # Get the value of the segment register.
    ea = 0x140001A16
    val: int = ida_segregs.get_sreg(ea, reg)
    ida_kernwin.msg(f"{hex(val)}\n")

    # Get how many ranges the segment register has.
    qty: int = ida_segregs.get_sreg_ranges_qty(reg)
    ida_kernwin.msg(f"{qty}\n")


segment_registers()
