"""
title: Load & Apply PDB Symbols
description: |
  Loads PDB symbols from a file via the PDB plugin, then writes a report
  of all renamed symbols to disk.
"""

import ida_auto
import ida_loader
import ida_nalt
import ida_netnode
import ida_pro
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


def main(output, pdb_path):
    # Wait for initial auto-analysis to finish.
    ida_auto.auto_wait()

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
            print(f"{hex(ea)}: {name}", file=output)


if __name__ == "__main__":
    if len(idc.ARGV) < 3:
        print("Usage: load_and_apply_pdb.py <output_path> <pdb_path>")
        ida_pro.qexit(0)
    with open(idc.ARGV[1], "w") as f:
        main(f, idc.ARGV[2])
        f.flush()
    ida_pro.qexit(0)
