"""Collectors de diagnóstico -> dataclasses. Sin rich/typer: solo datos.

Regla: ningún collector revienta. Dato ausente/sin permiso -> None / lista vacía.
"""
from __future__ import annotations

import platform
import time
from dataclasses import dataclass, field

import psutil

from warden.platform_utils import is_root

try:
    import distro  # solo útil en Linux
except Exception:  # pragma: no cover
    distro = None

# fs virtuales que no son discos reales -> fuera del informe de uso.
PSEUDO_FS = {
    "proc", "sysfs", "devtmpfs", "tmpfs", "squashfs", "overlay", "devpts",
    "cgroup", "cgroup2", "autofs", "mqueue", "debugfs", "tracefs", "ramfs",
    "securityfs", "pstore", "bpf", "configfs", "hugetlbfs", "fusectl",
    "binfmt_misc", "nsfs", "efivarfs",
}


def _safe(fn, default):
    try:
        return fn()
    except Exception:
        return default


@dataclass
class SystemInfo:
    os: str
    distro: str | None
    kernel: str
    hostname: str
    arch: str
    python: str
    boot_time: float | None
    uptime: float | None


@dataclass
class CpuInfo:
    percent: float | None = None
    per_core: list[float] = field(default_factory=list)
    freq_mhz: float | None = None
    cores_physical: int | None = None
    cores_logical: int | None = None
    load_avg: tuple[float, float, float] | None = None


@dataclass
class MemInfo:
    total: int | None = None
    used: int | None = None
    available: int | None = None
    percent: float | None = None
    swap_total: int | None = None
    swap_used: int | None = None
    swap_percent: float | None = None


@dataclass
class DiskInfo:
    device: str
    mountpoint: str
    fstype: str
    total: int
    used: int
    percent: float


@dataclass
class NetIface:
    name: str
    addresses: list[str]
    isup: bool
    speed_mbps: int | None


@dataclass
class NetInfo:
    bytes_sent: int | None
    bytes_recv: int | None
    ifaces: list[NetIface]


@dataclass
class ProcInfo:
    pid: int
    name: str
    cpu: float
    mem: float


@dataclass
class TempInfo:
    label: str
    current: float
    high: float | None
    critical: float | None


@dataclass
class HealthSnapshot:
    system: SystemInfo
    cpu: CpuInfo
    mem: MemInfo
    disks: list[DiskInfo]
    net: NetInfo
    procs: list[ProcInfo]
    temps: list[TempInfo]
    is_root: bool


def collect_system_info() -> SystemInfo:
    u = platform.uname()
    boot = _safe(psutil.boot_time, None)
    dist = None
    if distro and platform.system() == "Linux":
        dist = _safe(lambda: distro.name(pretty=True), None) or None
    return SystemInfo(
        os=platform.system(),
        distro=dist,
        kernel=u.release,
        hostname=u.node,
        arch=u.machine,
        python=platform.python_version(),
        boot_time=boot,
        uptime=(time.time() - boot) if boot else None,
    )


def collect_cpu(interval: float | None = None) -> CpuInfo:
    freq = _safe(psutil.cpu_freq, None)
    return CpuInfo(
        percent=_safe(lambda: psutil.cpu_percent(interval=interval), None),
        per_core=_safe(lambda: psutil.cpu_percent(interval=None, percpu=True), []),
        freq_mhz=freq.current if freq else None,
        cores_physical=_safe(lambda: psutil.cpu_count(logical=False), None),
        cores_logical=_safe(lambda: psutil.cpu_count(logical=True), None),
        load_avg=_safe(psutil.getloadavg, None),
    )


def collect_mem() -> MemInfo:
    vm = _safe(psutil.virtual_memory, None)
    sm = _safe(psutil.swap_memory, None)
    return MemInfo(
        total=vm.total if vm else None,
        used=vm.used if vm else None,
        available=vm.available if vm else None,
        percent=vm.percent if vm else None,
        swap_total=sm.total if sm else None,
        swap_used=sm.used if sm else None,
        swap_percent=sm.percent if sm else None,
    )


def collect_disks() -> list[DiskInfo]:
    out: list[DiskInfo] = []
    for p in _safe(lambda: psutil.disk_partitions(all=False), []):
        if not p.fstype or p.fstype.lower() in PSEUDO_FS:
            continue
        u = _safe(lambda mp=p.mountpoint: psutil.disk_usage(mp), None)
        if not u or u.total == 0:
            continue
        out.append(DiskInfo(p.device, p.mountpoint, p.fstype, u.total, u.used, u.percent))
    return out


def collect_net() -> NetInfo:
    io = _safe(psutil.net_io_counters, None)
    addrs = _safe(psutil.net_if_addrs, {}) or {}
    stats = _safe(psutil.net_if_stats, {}) or {}
    ifaces: list[NetIface] = []
    for name, alist in addrs.items():
        ips = [a.address for a in alist if a.family.name in ("AF_INET", "AF_INET6")]
        st = stats.get(name)
        ifaces.append(
            NetIface(name, ips, st.isup if st else False, st.speed if st and st.speed else None)
        )
    return NetInfo(
        io.bytes_sent if io else None,
        io.bytes_recv if io else None,
        ifaces,
    )


def collect_procs(limit: int = 6) -> list[ProcInfo]:
    # ponytail: cpu_percent en iteración única tiende a 0 en la 1ª lectura;
    # ordenamos por cpu y caemos a mem. Suficiente para un top. Doble muestreo
    # si algún día importa la precisión.
    procs: list[ProcInfo] = []
    for p in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent"]):
        i = p.info
        procs.append(
            ProcInfo(i["pid"], i["name"] or "?", i.get("cpu_percent") or 0.0, i.get("memory_percent") or 0.0)
        )
    procs.sort(key=lambda x: (x.cpu, x.mem), reverse=True)
    return procs[:limit]


def collect_temps() -> list[TempInfo]:
    fn = getattr(psutil, "sensors_temperatures", None)  # ausente en macOS/Windows
    if not fn:
        return []
    data = _safe(fn, {}) or {}
    out: list[TempInfo] = []
    for chip, entries in data.items():
        for e in entries:
            out.append(TempInfo(e.label or chip, e.current, e.high, e.critical))
    return out


def collect_health(cpu_interval: float | None = 0.3) -> HealthSnapshot:
    return HealthSnapshot(
        system=collect_system_info(),
        cpu=collect_cpu(cpu_interval if cpu_interval else None),
        mem=collect_mem(),
        disks=collect_disks(),
        net=collect_net(),
        procs=collect_procs(),
        temps=collect_temps(),
        is_root=is_root(),
    )
