"""
title: Discover Code
description: |
  This script discovers code in the loaded database by creating instructions
  for all unknown bytes in the segments. It is useful for analyzing flash memory
  dumps or other binary data where code may not be automatically recognized.
"""

import ida_auto
import ida_kernwin
import ida_segment
import ida_ua
import idautils
import ida_search


def discover_code():
    # Wait for auto-analysis to finish.
    # Usually, this is not needed when working with flash memory dumps,
    ida_auto.auto_wait()

    # Iterate through all segments
    for start in idautils.Segments():
        # Get segment end addresses
        seg: ida_segment.segment_t = ida_segment.getseg(start)

        # Create instructions for all unknown bytes in the segment
        ea = start
        while ea < seg.end_ea:
            # Create an instruction at the current address.
            insn_len = ida_ua.create_insn(ea)
            ida_kernwin.msg(f"{insn_len} {hex(ea)}\n")
            # Search for the next unknown byte.
            ea = ida_search.find_unknown(ea + 1, ida_search.SEARCH_DOWN)


discover_code()
