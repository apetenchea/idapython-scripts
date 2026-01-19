"""
title: Load & Apply PDB Symbols
description: |
  Loads PDB symbols from a file via the PDB plugin, then prints a report
  of all renamed symbols to the Output window.
"""

import ida_auto
import ida_kernwin
import ida_loader
import ida_nalt
import ida_netnode
import idautils
import idc


def load_pdb(pdb_path):
    """Drive the PDB plugin to load symbols for the current image."""
    base = ida_nalt.get_imagebase()

    # Create a new netnode to store the pdb plugin information in the database.
    # Netnodes are modeled on top of a BTree data structure.
    # The netnode for the PDB plugin is "$ pdb".
    n = ida_netnode.netnode()
    n.create("$ pdb")

    # The PDB plugin expects the base address in the altval array.
    n.altset(0, base)
    # The PDB plugin expects the PDB path in the supval array.
    n.supset(0, pdb_path)

    # 3 = don't ask the user for data, but use the information
    # stored in the netnode.
    if ida_loader.load_and_run_plugin("pdb", 3) == 0:
        raise RuntimeError(f"Failed to load PDB plugin for {pdb_path}")

    # After running the plugin, wait for it to finish.
    ida_auto.auto_wait()


def load_and_apply_pdb(pdb_path=None):
    # Wait for initial auto-analysis to finish.
    ida_auto.auto_wait()

    if pdb_path is None:
        ida_kernwin.msg("PDB path not provided\n")
        return

    # Snapshot the set of names before loading the PDB.
    before = {name for ea, name in idautils.Names()}

    load_pdb(pdb_path)

    # Snapshot again.
    after = {name for ea, name in idautils.Names()}

    # Compute the newly added names.
    new_names = after - before

    # Write the new names to the output file.
    for ea, name in idautils.Names():
        if name in new_names:
            ida_kernwin.msg(f"{hex(ea)}: {name}\n")


load_and_apply_pdb()
