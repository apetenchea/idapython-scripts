"""
title: Enumerate Segments
description: |
  Walks all segments in the loaded database,
  printing each segment’s name, start/end addresses,
  and permissions.
"""

import sys

import ida_auto
import ida_pro
import idaapi
import idautils
import idc


def format_perms(perm):
    """
    Turn the segment permission bits into an R/W/X string.
    """
    return "".join([
        "R" if perm & idaapi.SEGPERM_READ  else "-",
        "W" if perm & idaapi.SEGPERM_WRITE else "-",
        "X" if perm & idaapi.SEGPERM_EXEC  else "-"
    ])


def main(output):
    # Wait for the auto-analysis to finish
    ida_auto.auto_wait()

    # Iterate over all segments
    for ea in idautils.Segments():
        seg = idaapi.getseg(ea)
        name = idc.get_segm_name(ea)
        start = seg.start_ea
        end = seg.end_ea
        perms = format_perms(seg.perm)
        print(f"{name}: {hex(start)} - {hex(end)} ({perms})", file=output)


if __name__ == "__main__":
    if len(idc.ARGV) > 1:
        with open(idc.ARGV[1], "w") as f:
            main(f)
            f.flush()
    else:
        main(sys.stdout)
    ida_pro.qexit(0)
