"""
title: Netnode Inspector
description: |
  Dumps alt/sup/hash contents for a netnode by name or address.
"""

import ida_auto
import ida_idaapi
import ida_kernwin
import ida_netnode

MAX_ITEMS = 200


def _format_sup(data):
    if data is None:
        return "<none>"
    if isinstance(data, (bytes, bytearray)):
        try:
            text = data.decode("utf-8")
            if text.isprintable():
                return f"{text!r}"
        except UnicodeDecodeError:
            pass
        return f"bytes len={len(data)}"
    return str(data)


def _get_node_from_input():
    target = ida_kernwin.ask_str(
        "",
        0,
        "Netnode name or EA (hex). Empty = current EA",
    )
    if target is None:
        return None

    target = target.strip()
    if not target:
        ea = ida_kernwin.get_screen_ea()
        if ea == ida_idaapi.BADADDR:
            ida_kernwin.msg("No valid address under cursor.\n")
            return None
        return ida_netnode.netnode(ea)

    try:
        if target.startswith("0x") or target.isdigit():
            ea = int(target, 0)
            return ida_netnode.netnode(ea)
    except ValueError:
        pass

    if not ida_netnode.netnode.exist(target):
        ida_kernwin.msg(f"Netnode '{target}' does not exist; showing empty view.\n")
    return ida_netnode.netnode(target, 0, True)


def _dump_altvals(node):
    ida_kernwin.msg("Altvals (tag 'A'):\n")
    idx = node.altfirst(ida_netnode.atag)
    count = 0
    while idx != ida_netnode.BADNODE:
        val = node.altval(idx, ida_netnode.atag)
        ida_kernwin.msg(f"  [{idx:#x}] = {val:#x}\n")
        count += 1
        if count >= MAX_ITEMS:
            ida_kernwin.msg("  <truncated>\n")
            break
        idx = node.altnext(idx, ida_netnode.atag)
    if count == 0:
        ida_kernwin.msg("  <none>\n")


def _dump_supvals(node):
    ida_kernwin.msg("Supvals (tag 'S'):\n")
    idx = node.supfirst(ida_netnode.stag)
    count = 0
    while idx != ida_netnode.BADNODE:
        data = node.supval(idx, ida_netnode.stag)
        ida_kernwin.msg(f"  [{idx:#x}] = {_format_sup(data)}\n")
        count += 1
        if count >= MAX_ITEMS:
            ida_kernwin.msg("  <truncated>\n")
            break
        idx = node.supnext(idx, ida_netnode.stag)
    if count == 0:
        ida_kernwin.msg("  <none>\n")


def _dump_hashvals(node):
    ida_kernwin.msg("Hashvals (tag 'H'):\n")
    key = node.hashfirst()
    count = 0
    while key is not None:
        sval = node.hashstr(key)
        if sval is not None:
            desc = repr(sval)
        else:
            desc = f"{node.hashval_long(key):#x}"
        ida_kernwin.msg(f"  {key!r} = {desc}\n")
        count += 1
        if count >= MAX_ITEMS:
            ida_kernwin.msg("  <truncated>\n")
            break
        key = node.hashnext(key)
    if count == 0:
        ida_kernwin.msg("  <none>\n")


def netnode_inspector():
    # Wait for auto-analysis to finish.
    ida_auto.auto_wait()

    node = _get_node_from_input()
    if not node:
        return

    name = node.get_name()
    if not name:
        name = "<unnamed>"
    ida_kernwin.msg(f"Netnode index={node.index():#x} name={name}\n")

    _dump_altvals(node)
    _dump_supvals(node)
    _dump_hashvals(node)


netnode_inspector()
