"""
title: Netnode Blob Cache
description: |
  Stores a JSON snapshot of function summaries in a netnode blob.
  Side effect: creates/updates netnode "$ py_func_cache".
"""

import json

import ida_auto
import ida_funcs
import ida_kernwin
import ida_netnode
import idautils

NODE_NAME = "$ py_func_cache"
TAG = 'B'
INDEX = 0
PREVIEW_LIMIT = 10


def _get_node():
    if ida_netnode.netnode.exist(NODE_NAME):
        return ida_netnode.netnode(NODE_NAME, 0, True)
    node = ida_netnode.netnode()
    if not node.create(NODE_NAME):
        return ida_netnode.netnode(NODE_NAME, 0, True)
    return node


def _build_snapshot():
    items = []
    for ea in idautils.Functions():
        func = ida_funcs.get_func(ea)
        if not func:
            continue
        items.append(
            {
                "ea": ea,
                "name": ida_funcs.get_func_name(ea),
                "size": func.end_ea - func.start_ea,
            }
        )
    return items


def _load_snapshot(node):
    data = node.getblob(INDEX, TAG)
    if not data:
        return None
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None


def _store_snapshot(node, snapshot):
    payload = json.dumps(snapshot).encode("utf-8")
    node.setblob(payload, INDEX, TAG)


def netnode_blob_cache():
    # Wait for auto-analysis to finish.
    ida_auto.auto_wait()

    node = _get_node()
    if not node:
        ida_kernwin.msg("Failed to open netnode.\n")
        return

    snapshot = _load_snapshot(node)
    answer = ida_kernwin.ask_yn(
        ida_kernwin.ASKBTN_NO,
        "Rebuild function snapshot cache?",
    )

    if answer == ida_kernwin.ASKBTN_YES or snapshot is None:
        snapshot = _build_snapshot()
        _store_snapshot(node, snapshot)
        size = node.blobsize(INDEX, TAG)
        ida_kernwin.msg(
            f"Stored {len(snapshot)} functions in blob (size={size}).\n"
        )
    else:
        size = node.blobsize(INDEX, TAG)
        ida_kernwin.msg(
            f"Loaded {len(snapshot)} functions from blob (size={size}).\n"
        )

    for item in snapshot[:PREVIEW_LIMIT]:
        ida_kernwin.msg(
            f"  {item['name']} {item['ea']:#x} size={item['size']}\n"
        )


netnode_blob_cache()
