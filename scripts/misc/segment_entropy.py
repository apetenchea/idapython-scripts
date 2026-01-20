"""
title: Segment Entropy
description: |
  Computes Shannon entropy for each segment to help spot packed or encrypted regions.
"""

import ida_auto
import ida_bytes
import ida_kernwin
import ida_segment
import idautils
import math

CHUNK_SIZE = 1024 * 1024


def segment_entropy(seg):
    counts = [0] * 256
    total = 0

    ea = seg.start_ea
    while ea < seg.end_ea:
        size = min(CHUNK_SIZE, seg.end_ea - ea)
        data = ida_bytes.get_bytes(ea, size)
        if data:
            total += len(data)
            for b in data:
                counts[b] += 1
        ea += size

    if total == 0:
        return 0.0

    entropy = 0.0
    for count in counts:
        if count:
            p = count / total
            entropy -= p * math.log2(p)
    return entropy


def list_segment_entropy():
    # Wait for auto-analysis to finish.
    ida_auto.auto_wait()

    results = []
    for seg_start in idautils.Segments():
        seg = ida_segment.getseg(seg_start)
        if not seg:
            continue
        ent = segment_entropy(seg)
        results.append((ent, seg))

    results.sort(reverse=True, key=lambda item: item[0])

    ida_kernwin.msg(
        "Segment entropy (higher can indicate packed/encrypted data):\n"
    )
    for ent, seg in results:
        name = ida_segment.get_segm_name(seg)
        size = seg.end_ea - seg.start_ea
        ida_kernwin.msg(
            f"  {name} {seg.start_ea:#x}-{seg.end_ea:#x} "
            f"size={size:#x} entropy={ent:.3f}\n"
        )


list_segment_entropy()
