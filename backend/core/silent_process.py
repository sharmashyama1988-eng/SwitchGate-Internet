"""
SwitchGate - Silent Subprocess & Console Execution Hub v3.0
Eliminates 100% of terminal popups, PowerShell flickers, and console window flashes on Windows.
Enforces CREATE_NO_WINDOW and SW_HIDE across all subprocess and background executions.
"""
import os
import sys
import subprocess
from typing import Any, List, Optional, Union

# Windows kernel creation flags for 100% silent execution
if sys.platform == "win32":
    CREATE_NO_WINDOW = 0x08000000
    STARTF_USESHOWWINDOW = 0x00000001
    SW_HIDE = 0

    def get_silent_startupinfo() -> subprocess.STARTUPINFO:
        si = subprocess.STARTUPINFO()
        si.dwFlags |= STARTF_USESHOWWINDOW
        si.wShowWindow = SW_HIDE
        return si

    SILENT_CREATION_FLAGS = CREATE_NO_WINDOW
else:
    SILENT_CREATION_FLAGS = 0

    def get_silent_startupinfo() -> None:
        return None


def silent_run(cmd: Union[List[str], str], **kwargs: Any) -> subprocess.CompletedProcess:
    """
    Executes subprocess.run with guaranteed 0% console window flash on Windows.
    Applies CREATE_NO_WINDOW flag and SW_HIDE startupinfo automatically.
    """
    if sys.platform == "win32":
        if "creationflags" in kwargs:
            kwargs["creationflags"] |= SILENT_CREATION_FLAGS
        else:
            kwargs["creationflags"] = SILENT_CREATION_FLAGS

        if "startupinfo" not in kwargs:
            kwargs["startupinfo"] = get_silent_startupinfo()

    return subprocess.run(cmd, **kwargs)


def silent_check_output(cmd: Union[List[str], str], **kwargs: Any) -> Union[str, bytes]:
    """
    Executes subprocess.check_output with guaranteed 0% console window flash on Windows.
    """
    if sys.platform == "win32":
        if "creationflags" in kwargs:
            kwargs["creationflags"] |= SILENT_CREATION_FLAGS
        else:
            kwargs["creationflags"] = SILENT_CREATION_FLAGS

        if "startupinfo" not in kwargs:
            kwargs["startupinfo"] = get_silent_startupinfo()

    return subprocess.check_output(cmd, **kwargs)


def silent_popen(cmd: Union[List[str], str], **kwargs: Any) -> subprocess.Popen:
    """
    Spawns subprocess.Popen with guaranteed 0% console window flash on Windows.
    """
    if sys.platform == "win32":
        if "creationflags" in kwargs:
            kwargs["creationflags"] |= SILENT_CREATION_FLAGS
        else:
            kwargs["creationflags"] = SILENT_CREATION_FLAGS

        if "startupinfo" not in kwargs:
            kwargs["startupinfo"] = get_silent_startupinfo()

    return subprocess.Popen(cmd, **kwargs)
