"""
title: Function Tags via Netnode
description: |
  Stores a short label per function using a netnode supval array.
  Side effect: creates/updates netnode "$ py_func_tags".
"""

import ida_auto
import ida_funcs
import ida_kernwin
import ida_netnode
import idautils

NODE_NAME = "$ py_func_tags"
TAG = 'T'


def _get_node():
    if ida_netnode.netnode.exist(NODE_NAME):
        return ida_netnode.netnode(NODE_NAME, 0, True)
    node = ida_netnode.netnode()
    if not node.create(NODE_NAME):
        return ida_netnode.netnode(NODE_NAME, 0, True)
    return node


def _decode_label(data):
    if data is None:
        return None
    if isinstance(data, (bytes, bytearray)):
        return data.decode("utf-8", "replace")
    return str(data)


def _list_tags(node):
    found = False
    for ea in idautils.Functions():
        label = node.supval_ea(ea, TAG)
        if not label:
            continue
        name = ida_funcs.get_func_name(ea)
        text = _decode_label(label)
        ida_kernwin.msg(f"{name} {ea:#x}: {text}\n")
        found = True
    if not found:
        ida_kernwin.msg("No stored function tags.\n")


def function_tags():
    # Wait for auto-analysis to finish.
    ida_auto.auto_wait()

    node = _get_node()
    if not node:
        ida_kernwin.msg("Failed to open netnode.\n")
        return

    prompt = "Label for current function (empty=list, '-'=clear)"
    label = ida_kernwin.ask_str("", 0, prompt)
    if label is None:
        return

    if label == "":
        _list_tags(node)
        return

    func = ida_funcs.get_func(ida_kernwin.get_screen_ea())
    if not func:
        ida_kernwin.msg("No function at the cursor.\n")
        return

    if label.strip() == "-":
        node.supdel_ea(func.start_ea, TAG)
        ida_kernwin.msg("Tag cleared.\n")
    else:
        node.supset_ea(func.start_ea, label.encode("utf-8"), TAG)
        ida_kernwin.msg("Tag stored.\n")

    _list_tags(node)


function_tags()
