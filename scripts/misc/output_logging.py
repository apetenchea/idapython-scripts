"""
title: Log Messages to the Output Window
description: |
  Print something into the Output window (and, if you’ve turned on
  file-logging, into your idalog file).
"""

import ida_kernwin
import ida_pro


def main():
    ida_kernwin.info("Info")
    ida_kernwin.warning("Warning")
    ida_kernwin.msg("Message")
    ida_kernwin.ask_for_feedback("Feedback about problematic sample")

    # First argument is the default selection.
    # Second argument is the message to display.
    # The return value is the selected options.
    # ida_kernwin.ASKBTN_YES
    # ida_kernwin.ASKBTN_NO
    # ida_kernwin.ASKBTN_CANCEL
    ida_kernwin.ask_yn(ida_kernwin.ASKBTN_YES, "Do you want to continue?")

    # `error` causes IDA to exit with error code 1
    ida_kernwin.error("Error")


if __name__ == "__main__":
    main()
    ida_pro.qexit(0)
