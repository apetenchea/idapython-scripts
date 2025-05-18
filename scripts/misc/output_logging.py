"""
title: Log Messages to the Output Window
description: |
  Print something into the Output window (and, if you’ve turned on
  file-logging, into your idalog file).
"""

import ida_kernwin
import ida_pro


def main():
    ida_kernwin.info("Info\n")
    ida_kernwin.warning("Warning\n")
    ida_kernwin.msg("Message\n")

    # `error` causes IDA to exit with error code 1
    ida_kernwin.error("Error\n")


if __name__ == "__main__":
    main()
    ida_pro.qexit(0)
