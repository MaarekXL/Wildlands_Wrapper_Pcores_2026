#!/usr/bin/env python3
"""
Ghost Recon Wildlands Deep Startup Logger v4
=============================================

But
---
Observer ce que GRW.exe EXECUTE reellement pendant son demarrage, sans
modifier son affinite CPU et sans injection dans le jeu.

La V4 combine:
  - telemetrie Python/psutil
  - suivi des threads individuels GRW.exe
  - topologie P-core / E-core
  - modules et fichiers mappes
  - fichiers ouverts (best effort)
  - connexions reseau
  - chaine Steam / Ubisoft Connect / Easy Anti-Cheat / GRW
  - detection des fenetres splash / grande fenetre
  - WPR / ETW avec call stacks (si disponible)
  - Process Monitor / Procmon (optionnel, si Procmon64.exe est present)
  - resume automatique de la session

Aucune affinite CPU n'est modifiee.
Aucune DLL n'est injectee.
Aucun patch memoire n'est applique.
Aucun contournement d'anti-cheat n'est effectue.

Prerequis Python:
    python -m pip install psutil

Utilisation:
    python wildlands_deep_logger_v4.py

Options utiles:
    --max-minutes 20
    --interval 1
    --post-main-seconds 45
    --no-wpr
    --procmon auto|on|off
    --no-auto-stop
    --open-wpa

Process Monitor:
    Si Procmon64.exe / Procmon.exe est place a cote de ce script,
    --procmon auto l'utilisera automatiquement.

Sorties:
    WildlandsTrace_YYYYMMDD_HHMMSS\
        telemetry.csv
        events.log
        summary.txt
        manifest.json
        pmu_sources.txt
        wpr_profiles.txt
        wildlands.etl        (WPR/ETW)
        wildlands_procmon.pml (si Procmon disponible)

La trace ETL est la sortie la plus importante pour savoir OU le CPU passe
son temps. Dans Windows Performance Analyzer, filtrer Process = GRW.exe
puis examiner CPU Usage (Sampled) -> Stack et CPU Usage (Precise).
"""

from __future__ import annotations

import argparse
import csv
import ctypes
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
import winreg
from collections import defaultdict
from ctypes import wintypes
from datetime import datetime
from pathlib import Path
from typing import Any

try:
    import psutil
except ImportError:
    print()
    print("ERREUR: psutil n'est pas installe.")
    print()
    print("Dans PowerShell:")
    print("  python -m pip install psutil")
    print()
    raise SystemExit(1)


if sys.platform != "win32":
    raise SystemExit("Ce logger fonctionne uniquement sous Windows.")


# ===========================================================================
# Constantes
# ===========================================================================

STEAM_APP_ID = "460930"

WATCH_EXACT = {
    "grw.exe",
    "steam.exe",
    "ubisoftconnect.exe",
    "upc.exe",
    "ubisoftgamelauncher.exe",
}

WATCH_PREFIXES = (
    "easyanticheat",
    "ubisoft",
)

RELATION_PROCESSOR_CORE = 0
ERROR_INSUFFICIENT_BUFFER = 122

DWORD = wintypes.DWORD
WORD = wintypes.WORD
BYTE = wintypes.BYTE
BOOL = wintypes.BOOL
ULONG_PTR = ctypes.c_size_t

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
user32 = ctypes.WinDLL("user32", use_last_error=True)
shell32 = ctypes.WinDLL("shell32", use_last_error=True)


# ===========================================================================
# Structures Win32
# ===========================================================================

class GROUP_AFFINITY(ctypes.Structure):
    _fields_ = [
        ("Mask", ULONG_PTR),
        ("Group", WORD),
        ("Reserved", WORD * 3),
    ]


class PROCESSOR_RELATIONSHIP(ctypes.Structure):
    _fields_ = [
        ("Flags", BYTE),
        ("EfficiencyClass", BYTE),
        ("Reserved", BYTE * 20),
        ("GroupCount", WORD),
        ("GroupMask", GROUP_AFFINITY * 1),
    ]


class RECT(ctypes.Structure):
    _fields_ = [
        ("left", ctypes.c_long),
        ("top", ctypes.c_long),
        ("right", ctypes.c_long),
        ("bottom", ctypes.c_long),
    ]


kernel32.GetLogicalProcessorInformationEx.argtypes = [
    DWORD,
    wintypes.LPVOID,
    ctypes.POINTER(DWORD),
]
kernel32.GetLogicalProcessorInformationEx.restype = BOOL

EnumWindowsProc = ctypes.WINFUNCTYPE(
    BOOL,
    wintypes.HWND,
    wintypes.LPARAM,
)

user32.EnumWindows.argtypes = [
    EnumWindowsProc,
    wintypes.LPARAM,
]
user32.EnumWindows.restype = BOOL

user32.GetWindowThreadProcessId.argtypes = [
    wintypes.HWND,
    ctypes.POINTER(DWORD),
]
user32.GetWindowThreadProcessId.restype = DWORD

user32.IsWindowVisible.argtypes = [wintypes.HWND]
user32.IsWindowVisible.restype = BOOL

user32.GetWindowTextLengthW.argtypes = [wintypes.HWND]
user32.GetWindowTextLengthW.restype = ctypes.c_int

user32.GetWindowTextW.argtypes = [
    wintypes.HWND,
    wintypes.LPWSTR,
    ctypes.c_int,
]
user32.GetWindowTextW.restype = ctypes.c_int

user32.GetWindowRect.argtypes = [
    wintypes.HWND,
    ctypes.POINTER(RECT),
]
user32.GetWindowRect.restype = BOOL


# ===========================================================================
# Helpers generaux
# ===========================================================================

def run_hidden(
    args: list[str],
    timeout: float = 30,
    check: bool = False,
) -> subprocess.CompletedProcess:
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)

    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        errors="replace",
        timeout=timeout,
        check=check,
        creationflags=flags,
    )


def safe_call(fn, default=None):
    try:
        return fn()
    except (
        psutil.NoSuchProcess,
        psutil.AccessDenied,
        psutil.ZombieProcess,
        AttributeError,
        OSError,
        RuntimeError,
    ):
        return default


def average(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def human_time(seconds: float | None) -> str:
    if seconds is None:
        return "non detecte"

    minutes, sec = divmod(float(seconds), 60)
    hours, minutes = divmod(int(minutes), 60)

    if hours:
        return f"{hours} h {minutes:02d} min {sec:05.2f} s"
    if minutes:
        return f"{minutes} min {sec:05.2f} s"
    return f"{sec:.2f} s"


def cpu_model_name() -> str:
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"HARDWARE\DESCRIPTION\System\CentralProcessor\0",
        )
        value, _ = winreg.QueryValueEx(key, "ProcessorNameString")
        winreg.CloseKey(key)
        return str(value).strip()
    except Exception:
        return platform.processor() or "Unknown CPU"


def is_admin() -> bool:
    try:
        return bool(shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin() -> None:
    script = str(Path(__file__).resolve())

    user_args = [
        arg
        for arg in sys.argv[1:]
        if arg != "--elevated"
    ]

    params = subprocess.list2cmdline(
        [script, *user_args, "--elevated"]
    )

    result = shell32.ShellExecuteW(
        None,
        "runas",
        sys.executable,
        params,
        str(Path(__file__).resolve().parent),
        1,
    )

    if int(result) <= 32:
        raise RuntimeError(
            "Elevation administrateur refusee ou impossible."
        )

    raise SystemExit(0)


# ===========================================================================
# Topologie CPU
# ===========================================================================

def enumerate_physical_cores() -> list[dict[str, Any]]:
    needed = DWORD(0)

    kernel32.GetLogicalProcessorInformationEx(
        RELATION_PROCESSOR_CORE,
        None,
        ctypes.byref(needed),
    )

    if ctypes.get_last_error() != ERROR_INSUFFICIENT_BUFFER:
        return []

    buffer = ctypes.create_string_buffer(needed.value)

    if not kernel32.GetLogicalProcessorInformationEx(
        RELATION_PROCESSOR_CORE,
        buffer,
        ctypes.byref(needed),
    ):
        return []

    cores: list[dict[str, Any]] = []
    base = ctypes.addressof(buffer)
    offset = 0

    while offset < needed.value:
        address = base + offset

        relationship = DWORD.from_address(address).value
        size = DWORD.from_address(address + 4).value

        if size <= 0:
            break

        if relationship == RELATION_PROCESSOR_CORE:
            proc = PROCESSOR_RELATIONSHIP.from_address(
                address + 8
            )

            if proc.GroupCount == 1:
                mask = int(proc.GroupMask[0].Mask)

                logical = [
                    index
                    for index in range(
                        ctypes.sizeof(ULONG_PTR) * 8
                    )
                    if mask & (1 << index)
                ]

                cores.append(
                    {
                        "efficiency": int(
                            proc.EfficiencyClass
                        ),
                        "logical": logical,
                        "group": int(
                            proc.GroupMask[0].Group
                        ),
                    }
                )

        offset += size

    return cores


def classify_logical_processors():
    cores = enumerate_physical_cores()

    if not cores:
        return [], [], []

    efficiency_classes = {
        core["efficiency"]
        for core in cores
    }

    if len(efficiency_classes) > 1:
        performance_class = max(
            efficiency_classes
        )

        pcores = [
            core
            for core in cores
            if core["efficiency"]
            == performance_class
        ]

        ecores = [
            core
            for core in cores
            if core["efficiency"]
            != performance_class
        ]

    else:
        # Fallback utile sur plusieurs Intel hybrides:
        # P-cores = SMT, E-cores = non-SMT.
        pcores = [
            core
            for core in cores
            if len(core["logical"]) > 1
        ]

        ecores = [
            core
            for core in cores
            if len(core["logical"]) == 1
        ]

        if not pcores:
            pcores = cores
            ecores = []

    p_lp = sorted(
        lp
        for core in pcores
        for lp in core["logical"]
    )

    e_lp = sorted(
        lp
        for core in ecores
        for lp in core["logical"]
    )

    return cores, p_lp, e_lp


# ===========================================================================
# Fenetres
# ===========================================================================

def windows_for_pid(
    pid: int,
) -> list[tuple[str, int, int]]:
    windows: list[tuple[str, int, int]] = []

    @EnumWindowsProc
    def callback(hwnd, _):
        target_pid = DWORD(0)

        user32.GetWindowThreadProcessId(
            hwnd,
            ctypes.byref(target_pid),
        )

        if target_pid.value != pid:
            return True

        if not user32.IsWindowVisible(hwnd):
            return True

        length = user32.GetWindowTextLengthW(
            hwnd
        )

        title = ""

        if length > 0:
            buffer = ctypes.create_unicode_buffer(
                length + 1
            )

            user32.GetWindowTextW(
                hwnd,
                buffer,
                length + 1,
            )

            title = buffer.value.strip()

        rect = RECT()
        width = 0
        height = 0

        if user32.GetWindowRect(
            hwnd,
            ctypes.byref(rect),
        ):
            width = max(
                0,
                rect.right - rect.left,
            )
            height = max(
                0,
                rect.bottom - rect.top,
            )

        if title or width or height:
            windows.append(
                (title, width, height)
            )

        return True

    user32.EnumWindows(
        callback,
        0,
    )

    return windows


# ===========================================================================
# Processus
# ===========================================================================

def is_watched_name(name: str) -> bool:
    lower = name.lower()

    if lower in WATCH_EXACT:
        return True

    return any(
        lower.startswith(prefix)
        for prefix in WATCH_PREFIXES
    )


def find_grw_processes() -> list[psutil.Process]:
    result: list[psutil.Process] = []

    for proc in psutil.process_iter(
        ["pid", "name", "create_time"]
    ):
        try:
            if (
                proc.info["name"] or ""
            ).lower() == "grw.exe":
                result.append(proc)
        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
        ):
            pass

    result.sort(
        key=lambda proc: proc.info.get(
            "create_time",
            0,
        ),
        reverse=True,
    )

    return result


def watched_process_snapshot() -> dict[int, dict]:
    snapshot: dict[int, dict] = {}

    for proc in psutil.process_iter(
        [
            "pid",
            "ppid",
            "name",
            "create_time",
        ]
    ):
        try:
            name = proc.info["name"] or ""

            if not is_watched_name(name):
                continue

            snapshot[int(proc.pid)] = {
                "pid": int(proc.pid),
                "ppid": int(
                    proc.info.get("ppid") or 0
                ),
                "name": name,
                "create_time": float(
                    proc.info.get(
                        "create_time"
                    )
                    or 0
                ),
            }

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
        ):
            continue

    return snapshot


def ancestry(proc: psutil.Process) -> list[str]:
    rows: list[str] = []
    current = proc

    for _ in range(12):
        try:
            rows.append(
                f"{current.name()}({current.pid})"
            )

            parent = current.parent()

            if parent is None:
                break

            current = parent

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
        ):
            break

    return rows


# ===========================================================================
# Threads / fichiers / modules / reseau
# ===========================================================================

def thread_cpu_snapshot(
    proc: psutil.Process,
) -> dict[int, float]:
    result: dict[int, float] = {}

    threads = safe_call(
        proc.threads,
        [],
    ) or []

    for thread in threads:
        result[int(thread.id)] = float(
            thread.user_time
            + thread.system_time
        )

    return result


def thread_cpu_deltas(
    previous: dict[int, float],
    current: dict[int, float],
    delta_t: float,
) -> list[tuple[int, float, float]]:
    """
    Retourne:
        (TID, cpu_percent_single_core, cpu_seconds_delta)
    """
    if delta_t <= 0:
        return []

    rows = []

    for tid, cpu_time in current.items():
        old = previous.get(
            tid,
            cpu_time,
        )

        cpu_seconds = max(
            0.0,
            cpu_time - old,
        )

        cpu_percent = (
            cpu_seconds
            / delta_t
            * 100.0
        )

        rows.append(
            (
                tid,
                cpu_percent,
                cpu_seconds,
            )
        )

    rows.sort(
        key=lambda row: row[1],
        reverse=True,
    )

    return rows


def open_file_set(
    proc: psutil.Process,
) -> set[str]:
    rows = safe_call(
        proc.open_files,
        [],
    ) or []

    return {
        str(row.path)
        for row in rows
        if getattr(
            row,
            "path",
            None,
        )
    }


def mapped_path_set(
    proc: psutil.Process,
) -> set[str]:
    maps = safe_call(
        lambda: proc.memory_maps(
            grouped=True
        ),
        [],
    ) or []

    paths = set()

    for row in maps:
        path = getattr(
            row,
            "path",
            "",
        )

        if not path:
            continue

        # Elimine les pseudo-mappings.
        if path.startswith("["):
            continue

        paths.add(str(path))

    return paths


def network_set(
    proc: psutil.Process,
) -> set[tuple[str, str, str]]:
    connections = safe_call(
        lambda: proc.net_connections(
            kind="inet"
        ),
        [],
    ) or []

    result = set()

    for conn in connections:
        local = ""
        remote = ""

        if conn.laddr:
            local = (
                f"{conn.laddr.ip}:"
                f"{conn.laddr.port}"
            )

        if conn.raddr:
            remote = (
                f"{conn.raddr.ip}:"
                f"{conn.raddr.port}"
            )

        result.add(
            (
                local,
                remote,
                str(conn.status),
            )
        )

    return result


# ===========================================================================
# WPR / ETW
# ===========================================================================

def find_wpr() -> str | None:
    return (
        shutil.which("wpr.exe")
        or shutil.which("wpr")
    )


def find_wpa() -> str | None:
    candidate = shutil.which("wpa.exe")

    if candidate:
        return candidate

    common = Path(
        os.environ.get(
            "ProgramFiles(x86)",
            r"C:\Program Files (x86)",
        )
    ) / (
        r"Windows Kits\10"
        r"\Windows Performance Toolkit"
        r"\wpa.exe"
    )

    if common.is_file():
        return str(common)

    return None


def find_wpaexporter() -> str | None:
    candidate = shutil.which(
        "wpaexporter.exe"
    )

    if candidate:
        return candidate

    common = Path(
        os.environ.get(
            "ProgramFiles(x86)",
            r"C:\Program Files (x86)",
        )
    ) / (
        r"Windows Kits\10"
        r"\Windows Performance Toolkit"
        r"\wpaexporter.exe"
    )

    if common.is_file():
        return str(common)

    return None


def wpr_command(
    wpr: str,
    args: list[str],
    instance: str | None = None,
    timeout: float = 60,
):
    command = [wpr, *args]

    if instance:
        # Microsoft demande que -instancename
        # soit le dernier parametre.
        command += [
            "-instancename",
            instance,
        ]

    return run_hidden(
        command,
        timeout=timeout,
    )


def wpr_profile_exists(
    wpr: str,
    profile: str,
) -> bool:
    try:
        result = run_hidden(
            [
                wpr,
                "-profiledetails",
                profile,
            ],
            timeout=20,
        )

        return result.returncode == 0

    except Exception:
        return False


def query_wpr_profiles(
    wpr: str,
) -> str:
    try:
        result = run_hidden(
            [wpr, "-profiles"],
            timeout=20,
        )

        return (
            (result.stdout or "")
            + "\n"
            + (result.stderr or "")
        ).strip()

    except Exception as exc:
        return f"WPR profiles error: {exc}"


def query_pmu_sources(
    wpr: str,
) -> str:
    try:
        result = run_hidden(
            [wpr, "-pmcsources"],
            timeout=20,
        )

        return (
            (result.stdout or "")
            + "\n"
            + (result.stderr or "")
        ).strip()

    except Exception as exc:
        return f"PMU query error: {exc}"


def start_wpr(
    wpr: str,
    instance: str,
    temp_dir: Path,
    event,
):
    """
    GeneralProfile donne deja:
    SampledProfile, CSwitch, ReadyThread,
    ProcessThread, Loader, DiskIO, etc.

    On tente ensuite FileIO / Registry /
    Network / GPU si ces profils existent.
    """
    optional_candidates = [
        "FileIO",
        "Registry",
        "Network",
        "GPU",
    ]

    optional = [
        profile
        for profile in optional_candidates
        if wpr_profile_exists(
            wpr,
            profile,
        )
    ]

    profiles = [
        "GeneralProfile",
        *optional,
    ]

    command_args = []

    for profile in profiles:
        command_args += [
            "-start",
            f"{profile}.Verbose",
        ]

    command_args += [
        "-filemode",
        "-recordtempto",
        str(temp_dir),
    ]

    event(
        "WPR start profiles: "
        + " + ".join(profiles)
    )

    result = wpr_command(
        wpr,
        command_args,
        instance=instance,
        timeout=60,
    )

    if result.returncode == 0:
        event("WPR/ETW actif.")
        return True, profiles

    event(
        "WPR combinaison complete refusee; "
        "fallback GeneralProfile.Verbose."
    )

    # Nettoie eventuellement une session
    # partiellement creee.
    try:
        wpr_command(
            wpr,
            ["-cancel"],
            instance=instance,
            timeout=20,
        )
    except Exception:
        pass

    fallback = wpr_command(
        wpr,
        [
            "-start",
            "GeneralProfile.Verbose",
            "-filemode",
            "-recordtempto",
            str(temp_dir),
        ],
        instance=instance,
        timeout=60,
    )

    if fallback.returncode == 0:
        event(
            "WPR actif: "
            "GeneralProfile.Verbose."
        )
        return True, ["GeneralProfile"]

    event("WPR n'a pas pu demarrer.")

    detail = (
        (fallback.stdout or "")
        + "\n"
        + (fallback.stderr or "")
    ).strip()

    if detail:
        event(
            "WPR error: "
            + detail.replace(
                "\n",
                " | ",
            )[:1000]
        )

    return False, []


def wpr_marker(
    wpr: str | None,
    instance: str,
    text: str,
):
    if not wpr:
        return

    try:
        wpr_command(
            wpr,
            [
                "-marker",
                text,
            ],
            instance=instance,
            timeout=10,
        )
    except Exception:
        pass


def stop_wpr(
    wpr: str,
    instance: str,
    etl_path: Path,
    event,
) -> bool:
    event(
        "Arret WPR et generation ETL..."
    )

    result = wpr_command(
        wpr,
        [
            "-stop",
            str(etl_path),
            (
                "Ghost Recon Wildlands "
                "startup deep trace"
            ),
            "-compress",
        ],
        instance=instance,
        timeout=300,
    )

    if result.returncode == 0:
        event(
            f"ETL sauvegarde: "
            f"{etl_path.name}"
        )
        return True

    event("Echec sauvegarde ETL.")

    detail = (
        (result.stdout or "")
        + "\n"
        + (result.stderr or "")
    ).strip()

    if detail:
        event(
            "WPR stop error: "
            + detail.replace(
                "\n",
                " | ",
            )[:1500]
        )

    return False


# ===========================================================================
# Process Monitor
# ===========================================================================

def find_procmon(
    script_dir: Path,
) -> str | None:
    names = [
        "Procmon64.exe",
        "procmon64.exe",
        "Procmon.exe",
        "procmon.exe",
    ]

    for name in names:
        local = script_dir / name

        if local.is_file():
            return str(local)

    for name in names:
        path = shutil.which(name)

        if path:
            return path

    return None


def procmon_already_running() -> bool:
    names = {
        "procmon.exe",
        "procmon64.exe",
        "procmon64a.exe",
    }

    for proc in psutil.process_iter(
        ["name"]
    ):
        try:
            if (
                proc.info["name"] or ""
            ).lower() in names:
                return True

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
        ):
            pass

    return False


def start_procmon(
    procmon: str,
    pml_path: Path,
    event,
) -> bool:
    if procmon_already_running():
        event(
            "Procmon deja ouvert: "
            "capture automatique ignoree "
            "pour ne pas interrompre "
            "une session existante."
        )
        return False

    command = [
        procmon,
        "-accepteula",
        "-backingfile",
        str(pml_path),
        "-quiet",
        "-minimized",
    ]

    event(
        f"Demarrage Process Monitor: "
        f"{Path(procmon).name}"
    )

    try:
        flags = getattr(
            subprocess,
            "CREATE_NO_WINDOW",
            0,
        )

        subprocess.Popen(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=flags,
        )

        # Laisse le driver / logger s'initialiser.
        time.sleep(2.0)

        if procmon_already_running():
            event(
                "Process Monitor actif."
            )
            return True

        event(
            "Process Monitor ne semble "
            "pas avoir demarre."
        )
        return False

    except Exception as exc:
        event(
            f"Procmon start error: {exc}"
        )
        return False


def stop_procmon(
    procmon: str,
    event,
):
    event(
        "Arret Process Monitor..."
    )

    try:
        result = run_hidden(
            [
                procmon,
                "-terminate",
                "-quiet",
            ],
            timeout=60,
        )

        event(
            "Process Monitor termine "
            f"(code {result.returncode})."
        )

    except Exception as exc:
        event(
            f"Procmon stop error: {exc}"
        )


# ===========================================================================
# Resume / phases
# ===========================================================================

class SessionStats:
    def __init__(self):
        self.first_grw: float | None = None
        self.first_window: float | None = None
        self.first_main_window: float | None = None

        self.max_grw_cpu = 0.0
        self.max_system_cpu = 0.0
        self.max_rss_mib = 0.0
        self.max_threads = 0
        self.max_read_mib_s = 0.0
        self.max_write_mib_s = 0.0

        self.last_read_mib_total = 0.0
        self.last_write_mib_total = 0.0

        self.samples_with_grw = 0
        self.sum_grw_cpu = 0.0
        self.sum_p_avg = 0.0
        self.sum_e_avg = 0.0

        self.thread_cpu_seconds = defaultdict(float)

        self.files_seen = set()
        self.maps_seen = set()
        self.network_seen = set()

        self.grw_pids = []
        self.watched_processes_seen = set()

        self.cpu_multithread_marker = False
        self.io_phase_marker = False

    def update_thread_seconds(
        self,
        deltas: list[
            tuple[int, float, float]
        ],
    ):
        for tid, _, cpu_seconds in deltas:
            self.thread_cpu_seconds[
                tid
            ] += cpu_seconds


def write_summary(
    path: Path,
    stats: SessionStats,
    total_elapsed: float,
    cpu_name: str,
    cores,
    p_lp,
    e_lp,
    wpr_ok: bool,
    etl_path: Path,
    procmon_ok: bool,
    pml_path: Path,
    wpa_path: str | None,
):
    top_threads = sorted(
        stats.thread_cpu_seconds.items(),
        key=lambda item: item[1],
        reverse=True,
    )

    total_thread_cpu = sum(
        stats.thread_cpu_seconds.values()
    )

    avg_grw_cpu = (
        stats.sum_grw_cpu
        / stats.samples_with_grw
        if stats.samples_with_grw
        else 0.0
    )

    avg_p = (
        stats.sum_p_avg
        / stats.samples_with_grw
        if stats.samples_with_grw
        else 0.0
    )

    avg_e = (
        stats.sum_e_avg
        / stats.samples_with_grw
        if stats.samples_with_grw
        else 0.0
    )

    lines = [
        "Ghost Recon Wildlands Deep Logger v4",
        "====================================",
        "",
        f"CPU: {cpu_name}",
        (
            f"Physical cores detected: "
            f"{len(cores)}"
        ),
        f"P-core logical processors: {p_lp}",
        f"E-core logical processors: {e_lp}",
        "",
        "TIMELINE",
        "--------",
        (
            "First GRW.exe: "
            f"{human_time(stats.first_grw)}"
        ),
        (
            "First visible GRW window: "
            f"{human_time(stats.first_window)}"
        ),
        (
            "First large/main-like window: "
            f"{human_time(stats.first_main_window)}"
        ),
        (
            "Observed duration: "
            f"{human_time(total_elapsed)}"
        ),
        "",
        "PROCESS",
        "-------",
        (
            f"GRW PIDs seen: "
            f"{stats.grw_pids}"
        ),
        (
            f"Average GRW CPU: "
            f"{avg_grw_cpu:.2f}% "
            "(100% = one fully busy logical CPU)"
        ),
        (
            f"Peak GRW CPU: "
            f"{stats.max_grw_cpu:.2f}%"
        ),
        (
            f"Average P-core load: "
            f"{avg_p:.2f}%"
        ),
        (
            f"Average E-core load: "
            f"{avg_e:.2f}%"
        ),
        (
            f"Peak RAM RSS: "
            f"{stats.max_rss_mib:.1f} MiB"
        ),
        (
            f"Peak thread count: "
            f"{stats.max_threads}"
        ),
        (
            f"Peak read speed: "
            f"{stats.max_read_mib_s:.2f} MiB/s"
        ),
        (
            f"Peak write speed: "
            f"{stats.max_write_mib_s:.2f} MiB/s"
        ),
        (
            f"Final process read bytes: "
            f"{stats.last_read_mib_total:.1f} MiB"
        ),
        (
            f"Final process write bytes: "
            f"{stats.last_write_mib_total:.1f} MiB"
        ),
        "",
        "TOP GRW THREADS BY ACCUMULATED CPU TIME",
        "---------------------------------------",
    ]

    if top_threads:
        for rank, (
            tid,
            cpu_seconds,
        ) in enumerate(
            top_threads[:15],
            start=1,
        ):
            share = (
                cpu_seconds
                / total_thread_cpu
                * 100.0
                if total_thread_cpu
                else 0.0
            )

            lines.append(
                f"{rank:02d}. "
                f"TID {tid:<7} "
                f"{cpu_seconds:9.3f} CPU-s "
                f"({share:6.2f}%)"
            )
    else:
        lines.append(
            "No thread CPU data."
        )

    lines += [
        "",
        "OBSERVED OBJECTS",
        "----------------",
        (
            f"Open-file paths seen: "
            f"{len(stats.files_seen)}"
        ),
        (
            f"Mapped paths/modules seen: "
            f"{len(stats.maps_seen)}"
        ),
        (
            f"Network endpoints seen: "
            f"{len(stats.network_seen)}"
        ),
        "",
        "DEEP TRACE",
        "----------",
        (
            f"WPR/ETW captured: "
            f"{'YES' if wpr_ok else 'NO'}"
        ),
        (
            f"ETL: "
            f"{etl_path if wpr_ok else 'not created'}"
        ),
        (
            f"Process Monitor captured: "
            f"{'YES' if procmon_ok else 'NO'}"
        ),
        (
            f"PML: "
            f"{pml_path if procmon_ok else 'not created'}"
        ),
        "",
        "HOW TO SEE WHAT GRW.EXE EXECUTED",
        "--------------------------------",
        "1. Open wildlands.etl in Windows Performance Analyzer.",
        "2. CPU Usage (Sampled): filter Process = GRW.exe.",
        "3. Expand by Thread ID and Stack.",
        (
            "   This reveals the sampled call stacks where GRW "
            "spent CPU time."
        ),
        "4. CPU Usage (Precise): inspect waits, CSwitch and ReadyThread.",
        (
            "   This distinguishes active computation from "
            "waiting/synchronization."
        ),
        "5. Inspect Disk Usage / File I/O / Generic Events / GPU as available.",
        (
            "6. If wildlands_procmon.pml exists, open it in Process Monitor "
            "and filter Process Name is GRW.exe."
        ),
        (
            "   Inspect Operation, Path and Stack to see filesystem, registry "
            "and process/thread operations."
        ),
        "",
        (
            "WPA detected: "
            f"{wpa_path or 'NO'}"
        ),
        "",
        "INTERPRETATION HINT",
        "-------------------",
    ]

    if top_threads and total_thread_cpu:
        dominant_tid, dominant_cpu = (
            top_threads[0]
        )

        dominant_share = (
            dominant_cpu
            / total_thread_cpu
            * 100.0
        )

        lines.append(
            f"Dominant TID {dominant_tid} "
            f"accounts for {dominant_share:.1f}% "
            "of sampled thread CPU time."
        )

        if dominant_share >= 60:
            lines.append(
                "A strongly dominant thread is consistent with a "
                "largely serial/mono-threaded startup phase."
            )
        else:
            lines.append(
                "CPU time is distributed across several threads; "
                "the ETL stacks are needed to identify the hot paths."
            )
    else:
        lines.append(
            "Insufficient thread CPU data for an automatic conclusion."
        )

    path.write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )


# ===========================================================================
# Main
# ===========================================================================

def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Deep runtime tracer for Ghost Recon Wildlands startup."
        )
    )

    parser.add_argument(
        "--interval",
        type=float,
        default=1.0,
        help=(
            "Telemetry interval in seconds "
            "(default: 1.0)."
        ),
    )

    parser.add_argument(
        "--max-minutes",
        type=float,
        default=20.0,
        help=(
            "Maximum trace duration "
            "(default: 20 minutes)."
        ),
    )

    parser.add_argument(
        "--post-main-seconds",
        type=float,
        default=45.0,
        help=(
            "Stop this many seconds after a "
            "large/main-like GRW window appears "
            "(default: 45)."
        ),
    )

    parser.add_argument(
        "--no-auto-stop",
        action="store_true",
        help=(
            "Do not stop automatically after "
            "the main-like window appears."
        ),
    )

    parser.add_argument(
        "--main-width",
        type=int,
        default=1100,
    )

    parser.add_argument(
        "--main-height",
        type=int,
        default=650,
    )

    parser.add_argument(
        "--no-wpr",
        action="store_true",
        help="Disable WPR/ETW capture.",
    )

    parser.add_argument(
        "--procmon",
        choices=(
            "auto",
            "on",
            "off",
        ),
        default="auto",
        help=(
            "Process Monitor capture: "
            "auto/on/off."
        ),
    )

    parser.add_argument(
        "--open-wpa",
        action="store_true",
        help=(
            "Open the ETL in WPA after capture "
            "if WPA is installed."
        ),
    )

    parser.add_argument(
        "--steam-appid",
        default=STEAM_APP_ID,
    )

    parser.add_argument(
        "--elevated",
        action="store_true",
        help=argparse.SUPPRESS,
    )

    args = parser.parse_args()

    if args.interval < 0.25:
        raise ValueError(
            "Minimum interval is 0.25 second."
        )

    script_dir = Path(
        __file__
    ).resolve().parent

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    trace_dir = (
        script_dir
        / f"WildlandsTrace_{timestamp}"
    )

    trace_dir.mkdir(
        parents=True,
        exist_ok=False,
    )

    telemetry_path = (
        trace_dir / "telemetry.csv"
    )

    events_path = (
        trace_dir / "events.log"
    )

    summary_path = (
        trace_dir / "summary.txt"
    )

    manifest_path = (
        trace_dir / "manifest.json"
    )

    pmu_path = (
        trace_dir / "pmu_sources.txt"
    )

    profiles_path = (
        trace_dir / "wpr_profiles.txt"
    )

    etl_path = (
        trace_dir / "wildlands.etl"
    )

    pml_path = (
        trace_dir
        / "wildlands_procmon.pml"
    )

    wpr_temp = (
        trace_dir / "wpr_temp"
    )

    wpr_temp.mkdir(
        exist_ok=True,
    )

    wpr = None if args.no_wpr else find_wpr()

    procmon = (
        None
        if args.procmon == "off"
        else find_procmon(script_dir)
    )

    wants_procmon = (
        args.procmon == "on"
        or (
            args.procmon == "auto"
            and procmon is not None
        )
    )

    needs_admin = (
        bool(wpr)
        or wants_procmon
    )

    if (
        needs_admin
        and not is_admin()
        and not args.elevated
    ):
        print()
        print(
            "La V4 va utiliser des traceurs "
            "Windows systeme."
        )
        print(
            "Demande des droits "
            "administrateur..."
        )

        # Supprime le dossier cree avant
        # relance, s'il est encore vide.
        try:
            shutil.rmtree(
                trace_dir,
                ignore_errors=True,
            )
        except Exception:
            pass

        relaunch_as_admin()

    event_file = events_path.open(
        "w",
        encoding="utf-8",
    )

    start_perf = time.perf_counter()

    def event(message: str):
        elapsed = (
            time.perf_counter()
            - start_perf
        )

        line = (
            f"[T+{elapsed:10.3f}s] "
            f"{message}"
        )

        print(line)

        event_file.write(
            line + "\n"
        )

        event_file.flush()

    cpu_name = cpu_model_name()

    cores, p_lp, e_lp = (
        classify_logical_processors()
    )

    logical_count = (
        psutil.cpu_count(
            logical=True
        )
        or 1
    )

    physical_count = (
        psutil.cpu_count(
            logical=False
        )
        or 0
    )

    wpa = find_wpa()
    wpaexporter = find_wpaexporter()

    event(
        "Ghost Recon Wildlands "
        "Deep Logger v4"
    )

    event(
        f"Trace folder: {trace_dir}"
    )

    event(
        f"CPU: {cpu_name}"
    )

    event(
        f"P-core logical processors: "
        f"{p_lp}"
    )

    event(
        f"E-core logical processors: "
        f"{e_lp}"
    )

    event(
        "CPU affinity: UNCHANGED"
    )

    event(
        "This is a diagnostic trace; "
        "WPR/Procmon can add small overhead."
    )

    # -----------------------------------------------------------------------
    # WPR metadata
    # -----------------------------------------------------------------------

    wpr_profiles_text = ""
    pmu_sources_text = ""

    if wpr:
        wpr_profiles_text = (
            query_wpr_profiles(wpr)
        )

        profiles_path.write_text(
            wpr_profiles_text + "\n",
            encoding="utf-8",
        )

        pmu_sources_text = (
            query_pmu_sources(wpr)
        )

        pmu_path.write_text(
            pmu_sources_text + "\n",
            encoding="utf-8",
        )

    else:
        profiles_path.write_text(
            "WPR disabled or not found.\n",
            encoding="utf-8",
        )

        pmu_path.write_text(
            "WPR disabled or not found.\n",
            encoding="utf-8",
        )

    # -----------------------------------------------------------------------
    # Manifest initial
    # -----------------------------------------------------------------------

    manifest = {
        "tool": (
            "Ghost Recon Wildlands "
            "Deep Startup Logger v4"
        ),
        "created_local": datetime.now().isoformat(),
        "python": sys.version,
        "python_executable": sys.executable,
        "psutil_version": psutil.__version__,
        "platform": platform.platform(),
        "windows_release": platform.release(),
        "windows_version": platform.version(),
        "cpu": cpu_name,
        "logical_cpu_count": logical_count,
        "physical_cpu_count": physical_count,
        "p_core_logical_processors": p_lp,
        "e_core_logical_processors": e_lp,
        "physical_core_topology": cores,
        "steam_appid": args.steam_appid,
        "interval_s": args.interval,
        "max_minutes": args.max_minutes,
        "post_main_seconds": args.post_main_seconds,
        "main_window_threshold": [
            args.main_width,
            args.main_height,
        ],
        "wpr_path": wpr,
        "wpa_path": wpa,
        "wpaexporter_path": wpaexporter,
        "procmon_path": procmon,
        "requested_procmon": args.procmon,
        "affinity_modified": False,
        "injection": False,
    }

    manifest_path.write_text(
        json.dumps(
            manifest,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    # -----------------------------------------------------------------------
    # Demarrage traceurs
    # -----------------------------------------------------------------------

    wpr_ok = False
    wpr_profiles = []

    instance = (
        "GRWV4_"
        + re.sub(
            r"[^A-Za-z0-9_]",
            "_",
            timestamp,
        )
    )

    if wpr:
        wpr_ok, wpr_profiles = start_wpr(
            wpr,
            instance,
            wpr_temp,
            event,
        )
    elif not args.no_wpr:
        event(
            "wpr.exe introuvable: "
            "ETW desactive."
        )

    procmon_ok = False

    if wants_procmon:
        if procmon:
            procmon_ok = start_procmon(
                procmon,
                pml_path,
                event,
            )
        else:
            event(
                "Procmon demande mais "
                "Procmon64.exe / Procmon.exe "
                "introuvable."
            )

    elif (
        args.procmon == "auto"
        and not procmon
    ):
        event(
            "Procmon non trouve: "
            "capture PML ignoree."
        )

    # -----------------------------------------------------------------------
    # Telemetry initialisation
    # -----------------------------------------------------------------------

    psutil.cpu_percent(
        interval=None,
        percpu=True,
    )

    stats = SessionStats()

    current_pid = None
    current_proc = None

    previous_thread_cpu = {}
    previous_thread_clock = (
        time.perf_counter()
    )

    previous_io = None
    previous_io_clock = (
        time.perf_counter()
    )

    previous_ctx = None

    current_files = set()
    current_maps = set()
    current_network = set()

    last_files_scan = -999.0
    last_maps_scan = -999.0
    last_network_scan = -999.0
    last_process_tree_scan = -999.0

    files_count = 0
    maps_count = 0
    network_count = 0

    previous_watch_snapshot = {}

    first_window_marker_sent = False
    first_main_marker_sent = False

    main_window_seen_at = None

    sample_index = 0

    # CSV columns.
    cpu_columns = [
        f"cpu_lp_{i:02d}_percent"
        for i in range(
            logical_count
        )
    ]

    fields = [
        "sample",
        "timestamp",
        "elapsed_s",
        "grw_present",
        "pid",
        "process_status",
        "process_cpu_percent",
        "process_cpu_normalized_percent",
        "system_cpu_percent",
        "pcores_avg_percent",
        "ecores_avg_percent",
        "rss_mib",
        "vms_mib",
        "threads",
        "handles",
        "ctx_voluntary_total",
        "ctx_involuntary_total",
        "ctx_voluntary_delta",
        "ctx_involuntary_delta",
        "read_mib_total",
        "write_mib_total",
        "read_ops_total",
        "write_ops_total",
        "read_mib_s",
        "write_mib_s",
        "cpu_affinity",
        "top_thread_1_tid",
        "top_thread_1_cpu_percent",
        "top_thread_2_tid",
        "top_thread_2_cpu_percent",
        "top_thread_3_tid",
        "top_thread_3_cpu_percent",
        "top_thread_4_tid",
        "top_thread_4_cpu_percent",
        "top_thread_5_tid",
        "top_thread_5_cpu_percent",
        "top_thread_6_tid",
        "top_thread_6_cpu_percent",
        "top_thread_7_tid",
        "top_thread_7_cpu_percent",
        "top_thread_8_tid",
        "top_thread_8_cpu_percent",
        "visible_windows",
        "largest_window_width",
        "largest_window_height",
        "open_files_count",
        "mapped_paths_count",
        "network_connections_count",
        "watched_process_count",
        *cpu_columns,
    ]

    # -----------------------------------------------------------------------
    # Lancement Steam
    # -----------------------------------------------------------------------

    event(
        "Requesting normal launch via "
        f"Steam AppID {args.steam_appid}."
    )

    if wpr_ok:
        wpr_marker(
            wpr,
            instance,
            "GRW_V4_STEAM_LAUNCH_REQUESTED",
        )

    os.startfile(
        "steam://rungameid/"
        + str(args.steam_appid)
    )

    # -----------------------------------------------------------------------
    # Boucle
    # -----------------------------------------------------------------------

    try:
        with telemetry_path.open(
            "w",
            newline="",
            encoding="utf-8-sig",
        ) as telemetry_file:

            writer = csv.DictWriter(
                telemetry_file,
                fieldnames=fields,
            )

            writer.writeheader()
            telemetry_file.flush()

            while True:
                loop_start = (
                    time.perf_counter()
                )

                elapsed = (
                    loop_start
                    - start_perf
                )

                # Max duration.
                if (
                    elapsed
                    >= args.max_minutes * 60
                ):
                    event(
                        "Maximum trace duration "
                        "reached."
                    )
                    break

                # -----------------------------------------------------------
                # Chaine de processus
                # -----------------------------------------------------------

                if (
                    elapsed
                    - last_process_tree_scan
                    >= 1.0
                ):
                    watch_snapshot = (
                        watched_process_snapshot()
                    )

                    new_pids = (
                        set(watch_snapshot)
                        - set(
                            previous_watch_snapshot
                        )
                    )

                    gone_pids = (
                        set(
                            previous_watch_snapshot
                        )
                        - set(watch_snapshot)
                    )

                    for pid in sorted(new_pids):
                        info = watch_snapshot[pid]

                        event(
                            "PROCESS START: "
                            f"{info['name']} "
                            f"PID={pid} "
                            f"PPID={info['ppid']}"
                        )

                        stats.watched_processes_seen.add(
                            (
                                info["name"],
                                pid,
                            )
                        )

                    for pid in sorted(gone_pids):
                        info = (
                            previous_watch_snapshot[
                                pid
                            ]
                        )

                        event(
                            "PROCESS EXIT: "
                            f"{info['name']} "
                            f"PID={pid}"
                        )

                    previous_watch_snapshot = (
                        watch_snapshot
                    )

                    last_process_tree_scan = (
                        elapsed
                    )

                # -----------------------------------------------------------
                # Trouve GRW
                # -----------------------------------------------------------

                grw_processes = (
                    find_grw_processes()
                )

                proc = (
                    grw_processes[0]
                    if grw_processes
                    else None
                )

                if (
                    proc is not None
                    and proc.pid != current_pid
                ):
                    old_pid = current_pid

                    current_pid = proc.pid
                    current_proc = proc

                    safe_call(
                        lambda: current_proc.cpu_percent(
                            interval=None
                        ),
                        0.0,
                    )

                    previous_thread_cpu = (
                        thread_cpu_snapshot(
                            current_proc
                        )
                    )

                    previous_thread_clock = (
                        time.perf_counter()
                    )

                    previous_io = safe_call(
                        current_proc.io_counters,
                        None,
                    )

                    previous_io_clock = (
                        time.perf_counter()
                    )

                    previous_ctx = safe_call(
                        current_proc.num_ctx_switches,
                        None,
                    )

                    current_files = set()
                    current_maps = set()
                    current_network = set()

                    last_files_scan = -999.0
                    last_maps_scan = -999.0
                    last_network_scan = -999.0

                    if (
                        stats.first_grw
                        is None
                    ):
                        stats.first_grw = elapsed

                    if (
                        current_pid
                        not in stats.grw_pids
                    ):
                        stats.grw_pids.append(
                            current_pid
                        )

                    if old_pid is None:
                        event(
                            f"GRW.exe detected: "
                            f"PID={current_pid}"
                        )
                    else:
                        event(
                            "GRW PID changed: "
                            f"{old_pid} -> "
                            f"{current_pid}"
                        )

                    commandline = safe_call(
                        current_proc.cmdline,
                        [],
                    ) or []

                    executable = safe_call(
                        current_proc.exe,
                        "",
                    )

                    event(
                        f"GRW executable: "
                        f"{executable}"
                    )

                    event(
                        "GRW command line: "
                        + " ".join(commandline)
                    )

                    chain = ancestry(
                        current_proc
                    )

                    event(
                        "GRW ancestry: "
                        + " <- ".join(chain)
                    )

                    if wpr_ok:
                        wpr_marker(
                            wpr,
                            instance,
                            (
                                "GRW_V4_GRW_PID_"
                                + str(current_pid)
                            ),
                        )

                elif proc is None:
                    if current_pid is not None:
                        event(
                            "GRW.exe disappeared: "
                            f"PID={current_pid}"
                        )

                        if wpr_ok:
                            wpr_marker(
                                wpr,
                                instance,
                                (
                                    "GRW_V4_GRW_EXIT_"
                                    + str(current_pid)
                                ),
                            )

                    current_pid = None
                    current_proc = None

                    previous_thread_cpu = {}
                    previous_io = None
                    previous_ctx = None

                # -----------------------------------------------------------
                # CPU systeme
                # -----------------------------------------------------------

                per_cpu = psutil.cpu_percent(
                    interval=None,
                    percpu=True,
                )

                system_cpu = average(
                    per_cpu
                )

                p_avg = average(
                    [
                        per_cpu[index]
                        for index in p_lp
                        if index
                        < len(per_cpu)
                    ]
                )

                e_avg = average(
                    [
                        per_cpu[index]
                        for index in e_lp
                        if index
                        < len(per_cpu)
                    ]
                )

                # Defaults GRW absent.
                status = ""
                proc_cpu = 0.0
                rss_mib = 0.0
                vms_mib = 0.0
                thread_count = 0
                handles = -1

                ctx_voluntary = 0
                ctx_involuntary = 0
                ctx_voluntary_delta = 0
                ctx_involuntary_delta = 0

                read_mib_total = 0.0
                write_mib_total = 0.0
                read_ops = 0
                write_ops = 0
                read_mib_s = 0.0
                write_mib_s = 0.0

                affinity_text = ""

                thread_deltas = []

                windows = []
                largest_width = 0
                largest_height = 0

                # -----------------------------------------------------------
                # GRW details
                # -----------------------------------------------------------

                if current_proc is not None:
                    try:
                        status = (
                            current_proc.status()
                        )

                        proc_cpu = (
                            current_proc.cpu_percent(
                                interval=None
                            )
                        )

                        memory = (
                            current_proc.memory_info()
                        )

                        rss_mib = (
                            memory.rss
                            / 1024
                            / 1024
                        )

                        vms_mib = (
                            memory.vms
                            / 1024
                            / 1024
                        )

                        thread_count = (
                            current_proc.num_threads()
                        )

                        handles = safe_call(
                            current_proc.num_handles,
                            -1,
                        )

                        # Context switches.
                        now_ctx = safe_call(
                            current_proc.num_ctx_switches,
                            None,
                        )

                        if now_ctx is not None:
                            ctx_voluntary = int(
                                getattr(
                                    now_ctx,
                                    "voluntary",
                                    0,
                                )
                            )

                            ctx_involuntary = int(
                                getattr(
                                    now_ctx,
                                    "involuntary",
                                    0,
                                )
                            )

                            if previous_ctx is not None:
                                ctx_voluntary_delta = max(
                                    0,
                                    (
                                        ctx_voluntary
                                        - int(
                                            getattr(
                                                previous_ctx,
                                                "voluntary",
                                                0,
                                            )
                                        )
                                    ),
                                )

                                ctx_involuntary_delta = max(
                                    0,
                                    (
                                        ctx_involuntary
                                        - int(
                                            getattr(
                                                previous_ctx,
                                                "involuntary",
                                                0,
                                            )
                                        )
                                    ),
                                )

                            previous_ctx = now_ctx

                        # I/O.
                        now_io = safe_call(
                            current_proc.io_counters,
                            None,
                        )

                        now_io_clock = (
                            time.perf_counter()
                        )

                        io_delta_t = max(
                            0.000001,
                            (
                                now_io_clock
                                - previous_io_clock
                            ),
                        )

                        if now_io is not None:
                            read_mib_total = (
                                now_io.read_bytes
                                / 1024
                                / 1024
                            )

                            write_mib_total = (
                                now_io.write_bytes
                                / 1024
                                / 1024
                            )

                            read_ops = int(
                                now_io.read_count
                            )

                            write_ops = int(
                                now_io.write_count
                            )

                            if previous_io is not None:
                                read_mib_s = (
                                    max(
                                        0,
                                        (
                                            now_io.read_bytes
                                            - previous_io.read_bytes
                                        ),
                                    )
                                    / 1024
                                    / 1024
                                    / io_delta_t
                                )

                                write_mib_s = (
                                    max(
                                        0,
                                        (
                                            now_io.write_bytes
                                            - previous_io.write_bytes
                                        ),
                                    )
                                    / 1024
                                    / 1024
                                    / io_delta_t
                                )

                            previous_io = now_io
                            previous_io_clock = (
                                now_io_clock
                            )

                        # Affinity OBSERVEE,
                        # jamais modifiee.
                        affinity = safe_call(
                            current_proc.cpu_affinity,
                            [],
                        ) or []

                        affinity_text = ",".join(
                            map(
                                str,
                                affinity,
                            )
                        )

                        # Threads.
                        now_threads = (
                            thread_cpu_snapshot(
                                current_proc
                            )
                        )

                        now_thread_clock = (
                            time.perf_counter()
                        )

                        thread_delta_t = max(
                            0.000001,
                            (
                                now_thread_clock
                                - previous_thread_clock
                            ),
                        )

                        thread_deltas = (
                            thread_cpu_deltas(
                                previous_thread_cpu,
                                now_threads,
                                thread_delta_t,
                            )
                        )

                        stats.update_thread_seconds(
                            thread_deltas
                        )

                        previous_thread_cpu = (
                            now_threads
                        )

                        previous_thread_clock = (
                            now_thread_clock
                        )

                        # Fenetres.
                        windows = windows_for_pid(
                            current_proc.pid
                        )

                        if windows:
                            largest_window = max(
                                windows,
                                key=lambda row: (
                                    row[1]
                                    * row[2]
                                ),
                            )

                            largest_width = (
                                largest_window[1]
                            )

                            largest_height = (
                                largest_window[2]
                            )

                            if (
                                stats.first_window
                                is None
                            ):
                                stats.first_window = (
                                    elapsed
                                )

                                event(
                                    "First visible GRW "
                                    "window: "
                                    f"{largest_window}"
                                )

                                if (
                                    wpr_ok
                                    and not first_window_marker_sent
                                ):
                                    wpr_marker(
                                        wpr,
                                        instance,
                                        "GRW_V4_FIRST_VISIBLE_WINDOW",
                                    )

                                    first_window_marker_sent = True

                            if (
                                largest_width
                                >= args.main_width
                                and largest_height
                                >= args.main_height
                                and stats.first_main_window
                                is None
                            ):
                                stats.first_main_window = (
                                    elapsed
                                )

                                main_window_seen_at = (
                                    elapsed
                                )

                                event(
                                    "Large/main-like GRW "
                                    "window detected: "
                                    f"{largest_window}"
                                )

                                if (
                                    wpr_ok
                                    and not first_main_marker_sent
                                ):
                                    wpr_marker(
                                        wpr,
                                        instance,
                                        "GRW_V4_MAIN_LIKE_WINDOW",
                                    )

                                    first_main_marker_sent = True

                        # -----------------------------------------------
                        # Fichiers ouverts - toutes les 3 s
                        # -----------------------------------------------

                        if (
                            elapsed
                            - last_files_scan
                            >= 3.0
                        ):
                            new_files = (
                                open_file_set(
                                    current_proc
                                )
                            )

                            for path in sorted(
                                new_files
                                - current_files
                            ):
                                event(
                                    f"FILE OPEN/SEEN: "
                                    f"{path}"
                                )

                            for path in sorted(
                                current_files
                                - new_files
                            ):
                                event(
                                    f"FILE NO LONGER OPEN: "
                                    f"{path}"
                                )

                            current_files = new_files
                            files_count = len(
                                current_files
                            )

                            stats.files_seen.update(
                                current_files
                            )

                            last_files_scan = (
                                elapsed
                            )

                        # -----------------------------------------------
                        # Mappings - toutes les 8 s
                        # -----------------------------------------------

                        if (
                            elapsed
                            - last_maps_scan
                            >= 8.0
                        ):
                            new_maps = (
                                mapped_path_set(
                                    current_proc
                                )
                            )

                            for path in sorted(
                                new_maps
                                - current_maps
                            ):
                                event(
                                    f"MAP/MODULE SEEN: "
                                    f"{path}"
                                )

                            current_maps = new_maps
                            maps_count = len(
                                current_maps
                            )

                            stats.maps_seen.update(
                                current_maps
                            )

                            last_maps_scan = (
                                elapsed
                            )

                        # -----------------------------------------------
                        # Reseau - toutes les 2 s
                        # -----------------------------------------------

                        if (
                            elapsed
                            - last_network_scan
                            >= 2.0
                        ):
                            new_network = (
                                network_set(
                                    current_proc
                                )
                            )

                            for connection in sorted(
                                new_network
                                - current_network
                            ):
                                local, remote, state = (
                                    connection
                                )

                                event(
                                    "NET NEW: "
                                    f"{local} -> "
                                    f"{remote} "
                                    f"[{state}]"
                                )

                            for connection in sorted(
                                current_network
                                - new_network
                            ):
                                local, remote, state = (
                                    connection
                                )

                                event(
                                    "NET GONE: "
                                    f"{local} -> "
                                    f"{remote} "
                                    f"[{state}]"
                                )

                            current_network = (
                                new_network
                            )

                            network_count = len(
                                current_network
                            )

                            stats.network_seen.update(
                                current_network
                            )

                            last_network_scan = (
                                elapsed
                            )

                        # -----------------------------------------------
                        # Stats
                        # -----------------------------------------------

                        stats.samples_with_grw += 1
                        stats.sum_grw_cpu += proc_cpu
                        stats.sum_p_avg += p_avg
                        stats.sum_e_avg += e_avg

                        stats.max_grw_cpu = max(
                            stats.max_grw_cpu,
                            proc_cpu,
                        )

                        stats.max_system_cpu = max(
                            stats.max_system_cpu,
                            system_cpu,
                        )

                        stats.max_rss_mib = max(
                            stats.max_rss_mib,
                            rss_mib,
                        )

                        stats.max_threads = max(
                            stats.max_threads,
                            thread_count,
                        )

                        stats.max_read_mib_s = max(
                            stats.max_read_mib_s,
                            read_mib_s,
                        )

                        stats.max_write_mib_s = max(
                            stats.max_write_mib_s,
                            write_mib_s,
                        )

                        stats.last_read_mib_total = (
                            read_mib_total
                        )

                        stats.last_write_mib_total = (
                            write_mib_total
                        )

                        # Marqueurs de phase utiles dans WPA.
                        if (
                            proc_cpu >= 200.0
                            and not stats.cpu_multithread_marker
                        ):
                            stats.cpu_multithread_marker = True

                            event(
                                "GRW crossed 200% CPU: "
                                "multi-threaded phase detected."
                            )

                            if wpr_ok:
                                wpr_marker(
                                    wpr,
                                    instance,
                                    "GRW_V4_CPU_ABOVE_200_PERCENT",
                                )

                        if (
                            read_mib_s >= 100.0
                            and not stats.io_phase_marker
                        ):
                            stats.io_phase_marker = True

                            event(
                                "GRW read speed crossed "
                                "100 MiB/s: I/O phase detected."
                            )

                            if wpr_ok:
                                wpr_marker(
                                    wpr,
                                    instance,
                                    "GRW_V4_IO_ABOVE_100_MIB_S",
                                )

                    except psutil.NoSuchProcess:
                        current_proc = None
                        current_pid = None

                # -----------------------------------------------------------
                # CSV row
                # -----------------------------------------------------------

                row = {
                    "sample": sample_index,
                    "timestamp": (
                        datetime.now().isoformat(
                            timespec="milliseconds"
                        )
                    ),
                    "elapsed_s": round(
                        elapsed,
                        3,
                    ),
                    "grw_present": int(
                        current_proc
                        is not None
                    ),
                    "pid": (
                        current_pid
                        or ""
                    ),
                    "process_status": status,
                    "process_cpu_percent": round(
                        proc_cpu,
                        3,
                    ),
                    "process_cpu_normalized_percent": round(
                        (
                            proc_cpu
                            / logical_count
                        ),
                        3,
                    ),
                    "system_cpu_percent": round(
                        system_cpu,
                        3,
                    ),
                    "pcores_avg_percent": round(
                        p_avg,
                        3,
                    ),
                    "ecores_avg_percent": round(
                        e_avg,
                        3,
                    ),
                    "rss_mib": round(
                        rss_mib,
                        3,
                    ),
                    "vms_mib": round(
                        vms_mib,
                        3,
                    ),
                    "threads": thread_count,
                    "handles": handles,
                    "ctx_voluntary_total": (
                        ctx_voluntary
                    ),
                    "ctx_involuntary_total": (
                        ctx_involuntary
                    ),
                    "ctx_voluntary_delta": (
                        ctx_voluntary_delta
                    ),
                    "ctx_involuntary_delta": (
                        ctx_involuntary_delta
                    ),
                    "read_mib_total": round(
                        read_mib_total,
                        3,
                    ),
                    "write_mib_total": round(
                        write_mib_total,
                        3,
                    ),
                    "read_ops_total": read_ops,
                    "write_ops_total": write_ops,
                    "read_mib_s": round(
                        read_mib_s,
                        3,
                    ),
                    "write_mib_s": round(
                        write_mib_s,
                        3,
                    ),
                    "cpu_affinity": (
                        affinity_text
                    ),
                    "visible_windows": " | ".join(
                        (
                            f"{title} "
                            f"[{width}x{height}]"
                        )
                        for (
                            title,
                            width,
                            height,
                        ) in windows
                    ),
                    "largest_window_width": (
                        largest_width
                    ),
                    "largest_window_height": (
                        largest_height
                    ),
                    "open_files_count": (
                        files_count
                    ),
                    "mapped_paths_count": (
                        maps_count
                    ),
                    "network_connections_count": (
                        network_count
                    ),
                    "watched_process_count": len(
                        previous_watch_snapshot
                    ),
                }

                for rank in range(1, 9):
                    if (
                        len(thread_deltas)
                        >= rank
                    ):
                        tid, percent, _ = (
                            thread_deltas[
                                rank - 1
                            ]
                        )

                        row[
                            f"top_thread_{rank}_tid"
                        ] = tid

                        row[
                            f"top_thread_{rank}_cpu_percent"
                        ] = round(
                            percent,
                            3,
                        )

                    else:
                        row[
                            f"top_thread_{rank}_tid"
                        ] = ""

                        row[
                            f"top_thread_{rank}_cpu_percent"
                        ] = ""

                for index in range(
                    logical_count
                ):
                    row[
                        f"cpu_lp_{index:02d}_percent"
                    ] = (
                        round(
                            per_cpu[index],
                            3,
                        )
                        if index
                        < len(per_cpu)
                        else ""
                    )

                writer.writerow(row)
                telemetry_file.flush()

                # Console compacte toutes les 5 s.
                console_every = max(
                    1,
                    round(
                        5.0
                        / args.interval
                    ),
                )

                if (
                    sample_index
                    % console_every
                    == 0
                ):
                    top_threads_text = " ".join(
                        (
                            f"TID{tid}:"
                            f"{percent:.0f}%"
                        )
                        for (
                            tid,
                            percent,
                            _,
                        ) in thread_deltas[:3]
                    )

                    state = (
                        f"GRW {current_pid}"
                        if current_pid
                        else "waiting GRW"
                    )

                    print(
                        f"T+{elapsed:7.1f}s | "
                        f"{state:<15} | "
                        f"GRW {proc_cpu:6.1f}% | "
                        f"P {p_avg:5.1f}% "
                        f"E {e_avg:5.1f}% | "
                        f"RAM {rss_mib:7.0f} MiB | "
                        f"Th {thread_count:3d} | "
                        f"R {read_mib_s:7.2f} MiB/s | "
                        f"{top_threads_text}"
                    )

                # -----------------------------------------------------------
                # Auto-stop apres vraie grande fenetre.
                # -----------------------------------------------------------

                if (
                    not args.no_auto_stop
                    and main_window_seen_at
                    is not None
                    and (
                        elapsed
                        - main_window_seen_at
                    )
                    >= args.post_main_seconds
                ):
                    event(
                        "Post-main capture window "
                        "completed."
                    )
                    break

                sample_index += 1

                sleep_for = (
                    args.interval
                    - (
                        time.perf_counter()
                        - loop_start
                    )
                )

                if sleep_for > 0:
                    time.sleep(
                        sleep_for
                    )

    except KeyboardInterrupt:
        event(
            "Capture stopped manually "
            "with Ctrl+C."
        )

    finally:
        # -------------------------------------------------------------------
        # Arret traceurs.
        # -------------------------------------------------------------------

        if wpr_ok:
            wpr_marker(
                wpr,
                instance,
                "GRW_V4_CAPTURE_STOPPING",
            )

        if procmon_ok and procmon:
            stop_procmon(
                procmon,
                event,
            )

        etl_ok = False

        if wpr_ok and wpr:
            etl_ok = stop_wpr(
                wpr,
                instance,
                etl_path,
                event,
            )
        else:
            etl_ok = False

        total_elapsed = (
            time.perf_counter()
            - start_perf
        )

        # Nettoyage fichiers temporaires WPR.
        try:
            shutil.rmtree(
                wpr_temp,
                ignore_errors=True,
            )
        except Exception:
            pass

        # Resume.
        try:
            write_summary(
                summary_path,
                stats,
                total_elapsed,
                cpu_name,
                cores,
                p_lp,
                e_lp,
                etl_ok,
                etl_path,
                procmon_ok,
                pml_path,
                wpa,
            )
        except Exception as exc:
            event(
                f"Summary generation error: "
                f"{exc}"
            )

        # Met a jour le manifest avec les resultats.
        manifest.update(
            {
                "finished_local": (
                    datetime.now().isoformat()
                ),
                "observed_duration_s": (
                    total_elapsed
                ),
                "first_grw_s": (
                    stats.first_grw
                ),
                "first_visible_window_s": (
                    stats.first_window
                ),
                "first_main_like_window_s": (
                    stats.first_main_window
                ),
                "wpr_started": wpr_ok,
                "wpr_profiles_used": (
                    wpr_profiles
                ),
                "etl_created": (
                    etl_ok
                    and etl_path.exists()
                ),
                "procmon_started": (
                    procmon_ok
                ),
                "pml_created": (
                    procmon_ok
                    and pml_path.exists()
                ),
                "grw_pids_seen": (
                    stats.grw_pids
                ),
                "output_files": {
                    "telemetry": str(
                        telemetry_path
                    ),
                    "events": str(
                        events_path
                    ),
                    "summary": str(
                        summary_path
                    ),
                    "etl": str(
                        etl_path
                    ),
                    "procmon_pml": str(
                        pml_path
                    ),
                    "pmu_sources": str(
                        pmu_path
                    ),
                    "wpr_profiles": str(
                        profiles_path
                    ),
                },
            }
        )

        try:
            manifest_path.write_text(
                json.dumps(
                    manifest,
                    indent=2,
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
        except Exception as exc:
            event(
                f"Manifest update error: "
                f"{exc}"
            )

        event(
            f"Capture complete in: "
            f"{trace_dir}"
        )

        event_file.close()

    # -----------------------------------------------------------------------
    # Console finale
    # -----------------------------------------------------------------------

    print()
    print(
        "=========================================="
    )
    print(
        " Ghost Recon Wildlands Deep Logger v4"
    )
    print(
        " RESULTATS"
    )
    print(
        "=========================================="
    )

    print(
        f"Trace folder : {trace_dir}"
    )

    print(
        f"Summary      : {summary_path.name}"
    )

    print(
        f"Telemetry    : {telemetry_path.name}"
    )

    print(
        f"Events       : {events_path.name}"
    )

    if (
        etl_path.exists()
    ):
        print(
            f"ETW / stacks : {etl_path.name}"
        )

    if (
        pml_path.exists()
    ):
        print(
            f"Procmon      : {pml_path.name}"
        )

    print()
    print(
        f"First GRW    : "
        f"{human_time(stats.first_grw)}"
    )

    print(
        f"First window : "
        f"{human_time(stats.first_window)}"
    )

    print(
        f"Main-like    : "
        f"{human_time(stats.first_main_window)}"
    )

    print()
    print(
        "Pour savoir ce que GRW.exe execute:"
    )
    print(
        "  1. Ouvre wildlands.etl dans WPA."
    )
    print(
        "  2. CPU Usage (Sampled)."
    )
    print(
        "  3. Filtre Process = GRW.exe."
    )
    print(
        "  4. Developpe Thread ID puis Stack."
    )

    if pml_path.exists():
        print(
            "  5. Ouvre aussi le PML dans Procmon "
            "et filtre Process Name = GRW.exe."
        )

    print(
        "=========================================="
    )
    print()

    if (
        args.open_wpa
        and wpa
        and etl_path.exists()
    ):
        try:
            subprocess.Popen(
                [
                    wpa,
                    str(etl_path),
                ]
            )
        except Exception:
            pass

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(
            main()
        )

    except Exception as exc:
        print()
        print(
            f"ERREUR V4: {exc}"
        )
        print()

        try:
            input(
                "Appuie sur Entree pour fermer..."
            )
        except Exception:
            pass

        raise SystemExit(1)
