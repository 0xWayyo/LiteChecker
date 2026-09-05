"""An owned, non-inheritable Windows kill-on-close process job."""
from __future__ import annotations

import ctypes
from ctypes import wintypes
import sys


class _BasicLimits(ctypes.Structure):
    _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
                ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD)]


class _IoCounters(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint64) for name in ("ReadOperationCount", "WriteOperationCount",
                "OtherOperationCount", "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]


class _ExtendedLimits(ctypes.Structure):
    _fields_ = [("BasicLimitInformation", _BasicLimits), ("IoInfo", _IoCounters),
                ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]


class _Accounting(ctypes.Structure):
    _fields_ = [(name, ctypes.c_int64) for name in ("TotalUserTime", "TotalKernelTime",
                "ThisPeriodTotalUserTime", "ThisPeriodTotalKernelTime")] + [
                (name, wintypes.DWORD) for name in ("TotalPageFaultCount", "TotalProcesses",
                "ActiveProcesses", "TotalTerminatedProcesses")]


class WindowsJob:
    def __init__(self):
        if sys.platform != "win32":
            raise RuntimeError("windows-job-unavailable")
        api = ctypes.WinDLL("kernel32", use_last_error=True)
        signatures = {
            "CreateJobObjectW": ([ctypes.c_void_p, wintypes.LPCWSTR], wintypes.HANDLE),
            "SetInformationJobObject": ([wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD], wintypes.BOOL),
            "SetHandleInformation": ([wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD], wintypes.BOOL),
            "OpenProcess": ([wintypes.DWORD, wintypes.BOOL, wintypes.DWORD], wintypes.HANDLE),
            "AssignProcessToJobObject": ([wintypes.HANDLE, wintypes.HANDLE], wintypes.BOOL),
            "TerminateJobObject": ([wintypes.HANDLE, wintypes.UINT], wintypes.BOOL),
            "QueryInformationJobObject": ([wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
                                            ctypes.POINTER(wintypes.DWORD)], wintypes.BOOL),
            "CloseHandle": ([wintypes.HANDLE], wintypes.BOOL),
        }
        for name, (arguments, result) in signatures.items():
            function = getattr(api, name)
            function.argtypes, function.restype = arguments, result
        self._api = api
        self._handle = api.CreateJobObjectW(None, None)
        if not self._handle:
            self._error()
        try:
            limits = _ExtendedLimits()
            limits.BasicLimitInformation.LimitFlags = 0x2000  # KILL_ON_JOB_CLOSE; never allow breakaway.
            if not api.SetInformationJobObject(self._handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
                self._error()
            if not api.SetHandleInformation(self._handle, 1, 0):  # HANDLE_FLAG_INHERIT off.
                self._error()
        except BaseException:
            self.close()
            raise

    @staticmethod
    def _error():
        raise OSError(ctypes.get_last_error(), "windows-job-failed")

    def assign(self, pid: int):
        if type(pid) is not int or not 0 < pid <= 0xFFFFFFFF or not self._handle:
            raise ValueError("invalid-job-process")
        process = self._api.OpenProcess(0x0101, False, pid)  # SET_QUOTA | TERMINATE.
        if not process:
            self._error()
        try:
            if not self._api.AssignProcessToJobObject(self._handle, process):
                self._error()
        finally:
            self._api.CloseHandle(process)

    def active_processes(self) -> int:
        if not self._handle:
            return 0
        value = _Accounting()
        if not self._api.QueryInformationJobObject(self._handle, 1, ctypes.byref(value), ctypes.sizeof(value), None):
            self._error()
        return int(value.ActiveProcesses)

    def terminate(self):
        if self._handle and not self._api.TerminateJobObject(self._handle, 1):
            self._error()

    def close(self):
        if self._handle:
            handle, self._handle = self._handle, None
            self._api.CloseHandle(handle)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
