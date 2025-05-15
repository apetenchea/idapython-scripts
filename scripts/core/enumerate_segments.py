"""
title: Enumerate Segments
description: |
  Walks all segments in the loaded database, printing each segment’s name,
  start/end addresses, and permissions.
"""

import sys

import ida_pro
import ida_segment
import idaapi
import idautils
import idc


def format_perms(perm):
    """
    Turn the segment permission bits into an R/W/X string.
    """
    return "".join([
        "R" if perm & idaapi.SEGPERM_READ else "-",
        "W" if perm & idaapi.SEGPERM_WRITE else "-",
        "X" if perm & idaapi.SEGPERM_EXEC else "-"
    ])


def format_type(typ):
    """
    Turn the segment type into a string.
    """
    result = ""
    if typ == ida_segment.SEG_NORM:
        result = "unknown type, no assumptions"
    elif typ == ida_segment.SEG_XTRN:
        result = "segment with 'extern' definitions"
    elif typ == ida_segment.SEG_CODE:
        result = "code segment"
    elif typ == ida_segment.SEG_DATA:
        result = "data segment"
    elif typ == ida_segment.SEG_IMP:
        result = "java: implementation segment"
    elif typ == ida_segment.SEG_GRP:
        result = "group of segments"
    elif typ == ida_segment.SEG_NULL:
        result = "zero-length segment"
    elif typ == ida_segment.SEG_UNDF:
        result = "undefined segment type (not used)"
    elif typ == ida_segment.SEG_BSS:
        result = "uninitialized segment"
    elif typ == ida_segment.SEG_ABSSYM:
        result = "segment with definitions of absolute symbols"
    elif typ == ida_segment.SEG_COMM:
        result = "segment with communal definitions"
    elif typ == ida_segment.SEG_IMEM:
        result = "internal processor memory & sfr (8051)"
    return result


def main(output):
    # Iterate over all segments.
    # It enumerates the starting address of each segment, in ascending order.
    for ea in idautils.Segments():
        # Get the segment object associated with the address.
        seg: ida_segment.segment_t = ida_segment.getseg(ea)

        # The name property is just an index in a global array of names.
        # You need to use the get_segm_name function to get the actual name.
        name = ida_segment.get_segm_name(seg)

        # Each segment has its [start, end) addresses and represents
        # a contiguous range. The end address is excluded from the segment.
        start = seg.start_ea
        end = seg.end_ea

        # Permissions and type.
        perms = format_perms(seg.perm)
        typ = format_type(seg.type)

        print(
            f"{name}: {hex(start)} - {hex(end)} ({perms}) {typ}",
            file=output
        )


if __name__ == "__main__":
    if len(idc.ARGV) > 1:
        with open(idc.ARGV[1], "w") as f:
            main(f)
            f.flush()
    else:
        main(sys.stdout)
    ida_pro.qexit(0)
