"""Detección de SO y privilegios. Linux primero; el resto degrada, no revienta."""
import os
import platform


def os_name() -> str:
    return platform.system()  # "Linux", "Darwin", "Windows"


def is_linux() -> bool:
    return os_name() == "Linux"


def is_root() -> bool:
    # ponytail: geteuid sólo existe en POSIX; en Windows -> False (sin elevación auto).
    return hasattr(os, "geteuid") and os.geteuid() == 0
