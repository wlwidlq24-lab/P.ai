"""Hardware and environment snapshots. Unavailable measurements are None with a reason, never 0."""
from __future__ import annotations

import ctypes
import os
import platform
import shutil
import subprocess
import sys
from importlib import metadata
from typing import Any

from .schemas import VramSample

TRACKED_PACKAGES = ("chromadb", "fastapi", "httpx", "pydantic", "pydantic-settings", "pypdf", "streamlit",
                    "uvicorn", "filelock", "pyyaml", "numpy")


def nvidia_smi_sample(timeout_s: float = 3.0) -> VramSample:
    exe = shutil.which("nvidia-smi")
    if not exe:
        return VramSample(unavailable_reason="nvidia-smi not found on PATH")
    try:
        out = subprocess.run([exe, "--query-gpu=memory.total,memory.used", "--format=csv,noheader,nounits"],
                             capture_output=True, text=True, timeout=timeout_s, check=True).stdout.strip()
        total, used = (int(x.strip()) for x in out.splitlines()[0].split(","))
        return VramSample(total_mib=total, used_mib=used)
    except (subprocess.SubprocessError, ValueError, IndexError, OSError) as e:
        return VramSample(unavailable_reason=f"nvidia-smi failed: {type(e).__name__}")


def _ram_bytes() -> tuple[int | None, str | None]:
    if sys.platform == "win32":
        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                        ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                        ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                        ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                        ("sullAvailExtendedVirtual", ctypes.c_ulonglong)]
        st = MEMORYSTATUSEX()
        st.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(st)):
            return int(st.ullTotalPhys), None
        return None, "GlobalMemoryStatusEx failed"
    try:
        return os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES"), None
    except (ValueError, OSError, AttributeError):
        return None, "sysconf unavailable"


def gpu_name() -> tuple[str | None, str | None]:
    exe = shutil.which("nvidia-smi")
    if not exe:
        return None, "nvidia-smi not found"
    try:
        out = subprocess.run([exe, "--query-gpu=name,driver_version", "--format=csv,noheader"], capture_output=True,
                             text=True, timeout=3, check=True).stdout.strip()
        return out.splitlines()[0], None
    except (subprocess.SubprocessError, IndexError, OSError) as e:
        return None, type(e).__name__


def hardware_snapshot() -> dict[str, Any]:
    ram, ram_reason = _ram_bytes()
    gpu, gpu_reason = gpu_name()
    vram = nvidia_smi_sample()
    return {
        "platform": platform.platform(), "python": sys.version.split()[0], "machine": platform.machine(),
        "processor": platform.processor() or None, "cpu_count": os.cpu_count(),
        "ram_bytes": ram, "ram_unavailable_reason": ram_reason,
        "gpu": gpu, "gpu_unavailable_reason": gpu_reason,
        "vram_total_mib": vram.total_mib, "vram_unavailable_reason": vram.unavailable_reason,
    }


def package_versions() -> dict[str, str]:
    out = {}
    for p in TRACKED_PACKAGES:
        try:
            out[p] = metadata.version(p)
        except metadata.PackageNotFoundError:
            out[p] = "not-installed"
    return out
