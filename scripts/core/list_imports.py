"""
title: List Imports
description: |
  Enumerates import modules and their imported symbols.
"""

import ida_kernwin
import ida_nalt


def list_imports():
    nimps = ida_nalt.get_import_module_qty()
    ida_kernwin.msg(f"Found {nimps} import module(s)\n")

    for i in range(nimps):
        module_name = ida_nalt.get_import_module_name(i) or "<unnamed>"
        ida_kernwin.msg(f"[{i}] {module_name}\n")

        def imp_cb(ea, imp_name, ordinal):
            if imp_name:
                ida_kernwin.msg(
                    f"  {ea:08X}: {imp_name} (ordinal {ordinal})\n"
                )
            else:
                ida_kernwin.msg(f"  {ea:08X}: ordinal {ordinal}\n")
            return True

        ida_nalt.enum_import_names(i, imp_cb)

    ida_kernwin.msg("All done.\n")


list_imports()
