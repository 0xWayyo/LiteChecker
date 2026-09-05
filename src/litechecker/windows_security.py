"""Read-only Windows path/ACL checks; provisioning belongs to the bootstrap.

The owner and every allowed DACL trustee must be this user, SYSTEM or local
Administrators. POSIX calls retain actual owner/mode checks for portable callers;
Windows never treats chmod bits as an ACL. No security descriptor is cached.
"""
from __future__ import annotations

import ctypes
import os
from pathlib import Path
import stat
import sys


def is_windows() -> bool:
    return sys.platform == "win32"


def _is_reparse_point(path: Path) -> bool:
    metadata = path.lstat()
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0) & 0x400
    )


def reject_reparse_points(path: Path) -> Path:
    """Reject nonlocal/relative paths and any existing reparse ancestor."""
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts or str(path).startswith("\\\\"):
        raise ValueError("windows-path-unsafe")
    for current in (*reversed(path.parents), path):
        try:
            if _is_reparse_point(current):
                raise ValueError("windows-reparse-path-unsafe")
        except FileNotFoundError:
            continue
    return path


def _read_directory_acl(path: Path) -> tuple[str, str, bool, tuple[tuple[int, int, str], ...]]:
    """Native OS boundary, also valid for regular file security descriptors."""
    from ctypes import wintypes as wt

    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    pointer = ctypes.c_void_p
    advapi.GetNamedSecurityInfoW.argtypes = [wt.LPWSTR, wt.DWORD, wt.DWORD, ctypes.POINTER(pointer), ctypes.POINTER(pointer), ctypes.POINTER(pointer), ctypes.POINTER(pointer), ctypes.POINTER(pointer)]
    advapi.GetNamedSecurityInfoW.restype = wt.DWORD
    advapi.ConvertSidToStringSidW.argtypes = [pointer, ctypes.POINTER(wt.LPWSTR)]
    advapi.ConvertSidToStringSidW.restype = wt.BOOL
    advapi.OpenProcessToken.argtypes = [wt.HANDLE, wt.DWORD, ctypes.POINTER(wt.HANDLE)]
    advapi.OpenProcessToken.restype = wt.BOOL
    advapi.GetTokenInformation.argtypes = [wt.HANDLE, ctypes.c_int, pointer, wt.DWORD, ctypes.POINTER(wt.DWORD)]
    advapi.GetTokenInformation.restype = wt.BOOL
    advapi.GetAce.argtypes = [pointer, wt.DWORD, ctypes.POINTER(pointer)]
    advapi.GetAce.restype = wt.BOOL
    advapi.GetAclInformation.argtypes = [pointer, pointer, wt.DWORD, ctypes.c_int]
    advapi.GetAclInformation.restype = wt.BOOL
    kernel.GetCurrentProcess.argtypes = []
    kernel.GetCurrentProcess.restype = wt.HANDLE
    kernel.CloseHandle.argtypes = [wt.HANDLE]
    kernel.CloseHandle.restype = wt.BOOL
    kernel.LocalFree.argtypes = [pointer]
    kernel.LocalFree.restype = pointer

    def sid_text(sid):
        text = wt.LPWSTR()
        if not sid or not advapi.ConvertSidToStringSidW(sid, ctypes.byref(text)):
            raise OSError("windows-security-sid-unavailable")
        try:
            return text.value
        finally:
            kernel.LocalFree(ctypes.cast(text, pointer))

    token = wt.HANDLE()
    if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 0x0008, ctypes.byref(token)):
        raise OSError("windows-security-token-unavailable")
    try:
        needed = wt.DWORD()
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))
        if not 1 <= needed.value <= 65536:
            raise OSError("windows-security-token-invalid")
        buffer = ctypes.create_string_buffer(needed.value)
        if not advapi.GetTokenInformation(token, 1, buffer, needed, ctypes.byref(needed)):
            raise OSError("windows-security-token-unavailable")
        current_user = sid_text(pointer.from_buffer(buffer).value)
    finally:
        kernel.CloseHandle(token)

    owner, dacl, descriptor = pointer(), pointer(), pointer()
    result = advapi.GetNamedSecurityInfoW(str(path), 1, 0x00000005, ctypes.byref(owner), None, ctypes.byref(dacl), None, ctypes.byref(descriptor))
    if result:
        raise OSError("windows-security-descriptor-unavailable")
    try:
        owner_sid = sid_text(owner)
        if not dacl:
            return owner_sid, current_user, False, ()

        class AclSize(ctypes.Structure):
            _fields_ = [("count", wt.DWORD), ("used", wt.DWORD), ("free", wt.DWORD)]

        size = AclSize()
        if not advapi.GetAclInformation(dacl, ctypes.byref(size), ctypes.sizeof(size), 2) or size.count > 128:
            raise OSError("windows-security-acl-invalid")
        entries = []
        for index in range(size.count):
            ace = pointer()
            if not advapi.GetAce(dacl, index, ctypes.byref(ace)):
                raise OSError("windows-security-ace-unavailable")
            header = ctypes.string_at(ace, 4)
            kind, ace_size = header[0], int.from_bytes(header[2:4], "little")
            # Only ordinary allow/deny ACEs are interpreted. Object/callback
            # and other conditional ACEs are rejected, never assumed harmless.
            if kind not in (0, 1) or ace_size < 16:
                raise ValueError("windows-security-ace-unsupported")
            mask = int.from_bytes(ctypes.string_at(ace.value + 4, 4), "little")
            entries.append((kind, mask, sid_text(ace.value + 8)))
        return owner_sid, current_user, True, tuple(entries)
    finally:
        kernel.LocalFree(descriptor)


def _assert_private(path: Path, *, directory: bool) -> Path:
    path = reject_reparse_points(path)
    metadata = path.lstat()
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected(metadata.st_mode):
        raise ValueError("windows-private-path-type-invalid")
    if not is_windows():
        if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
            raise ValueError("private-path-permissions-unsafe")
        return path
    owner, current, present, entries = _read_directory_acl(path)
    allowed = {current, "S-1-5-18", "S-1-5-32-544"}
    # A new object's owner comes from the creator's TOKEN_OWNER, not its
    # parent's owner. Elevated tokens can therefore create Administrators-
    # owned children of a current-user-owned private baseline. These are the
    # same privileged principals already trusted by our DACL policy; foreign
    # owners remain forbidden because ownership implicitly permits WRITE_DAC.
    if owner not in allowed or not present:
        raise ValueError("windows-private-owner-or-acl-unsafe")
    for kind, mask, trustee in entries:
        if kind not in (0, 1) or kind == 0 and mask and trustee not in allowed:
            raise ValueError("windows-private-acl-unsafe")
    return path


def assert_private_directory(path: Path) -> Path:
    return _assert_private(path, directory=True)


def assert_private_file(path: Path) -> Path:
    return _assert_private(path, directory=False)


validate_private_directory = assert_private_directory
