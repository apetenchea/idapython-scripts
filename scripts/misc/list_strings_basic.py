"""
title: List Strings (Basic)
description: |
  Enumerates strings recognized by IDA using the current string settings.
"""

import ida_auto
import ida_kernwin
import idautils


def list_strings_basic():
    # Wait for auto-analysis to finish.
    ida_auto.auto_wait()

    strings = idautils.Strings()
    strings.setup()

    count = 0
    for s in strings:
        count += 1
        ida_kernwin.msg(f"{s.ea:#x}: {str(s)}\n")

    ida_kernwin.msg(f"Total strings: {count}\n")


list_strings_basic()
