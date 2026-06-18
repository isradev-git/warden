"""Auditoría de seguridad del host -> CheckResult. Linux primero.

core: sin rich/typer, solo datos. Ningún check revienta; lo no determinable
(sin permiso, sin Linux, sin la herramienta) -> status 'na', nunca traceback.
"""
from __future__ import annotations

import datetime
import os
import re
import shutil
import subprocess
from dataclasses import dataclass

import psutil

from warden.platform_utils import is_linux, is_root

OK, WARN, FAIL, NA = "ok", "warn", "fail", "na"
_SEV = {OK: 0, WARN: 1, FAIL: 2}
_VAL = {OK: 1.0, WARN: 0.5, FAIL: 0.0}  # peso de cada estado en el score


@dataclass
class CheckResult:
    id: str
    name: str
    status: str  # ok / warn / fail / na
    detail: str = ""
    recommendation: str = ""
    weight: int = 1


@dataclass
class AuditReport:
    checks: list[CheckResult]
    score: int  # 0-100 (sobre los checks aplicables)
    grade: str  # A-F, "—" si nada aplica
    worst: str  # ok / warn / fail
    counts: dict  # {ok, warn, fail, na}
    is_root: bool
    lynis_used: bool


# --- helpers -----------------------------------------------------------------

def _run(cmd: list[str], timeout: float = 5.0) -> tuple[int, str] | None:
    """Ejecuta cmd capturando salida. None si el binario no existe o falla."""
    if not shutil.which(cmd[0]):
        return None
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except Exception:
        return None


def _read(path: str) -> str | None:
    try:
        with open(path, "r", errors="ignore") as f:
            return f.read()
    except Exception:
        return None


def _mode(path: str) -> int | None:
    try:
        return os.stat(path).st_mode & 0o777
    except Exception:
        return None


def _svc_active(name: str) -> bool:
    # systemctl is-active no requiere root.
    r = _run(["systemctl", "is-active", name])
    return bool(r and r[1].strip() == "active")


def _directive(txt: str, key: str) -> str | None:
    """Último valor de una directiva estilo sshd_config (gana la última, ignora #)."""
    val = None
    for line in txt.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        parts = s.split(None, 1)
        if len(parts) == 2 and parts[0].lower() == key.lower():
            val = parts[1].strip().split()[0]
    return val


def _na(cid: str, name: str, detail: str, weight: int = 1) -> CheckResult:
    return CheckResult(cid, name, NA, detail, weight=weight)


# --- checks propios ----------------------------------------------------------

def _check_firewall() -> CheckResult:
    n, w = "Cortafuegos", 2
    if not is_linux():
        return _na("firewall", n, "Solo Linux por ahora.", w)
    for svc, label in (("ufw", "ufw"), ("firewalld", "firewalld"), ("nftables", "nftables")):
        if _svc_active(svc):
            return CheckResult("firewall", n, OK, f"{label} activo.", weight=w)
    if any(shutil.which(b) for b in ("ufw", "firewall-cmd", "nft")):
        return CheckResult("firewall", n, WARN, "Cortafuegos instalado pero inactivo.",
                           "Activa ufw o firewalld.", w)
    return CheckResult("firewall", n, WARN, "Sin cortafuegos detectado.",
                       "Instala y activa ufw o firewalld.", w)


def _check_ssh() -> list[CheckResult]:
    path = "/etc/ssh/sshd_config"
    if not is_linux() or not os.path.exists(path):
        return [_na("ssh_root", "SSH root login", "Sin servidor SSH (no sshd_config).", 3),
                _na("ssh_pass", "SSH password auth", "Sin servidor SSH.", 1)]
    txt = _read(path)
    if txt is None:
        return [_na("ssh_root", "SSH root login", "sshd_config no legible (requiere root).", 3),
                _na("ssh_pass", "SSH password auth", "sshd_config no legible.", 1)]

    root = (_directive(txt, "PermitRootLogin") or "").lower()
    if root == "yes":
        r = CheckResult("ssh_root", "SSH root login", FAIL, "PermitRootLogin yes.",
                        "Pon PermitRootLogin no (o prohibit-password).", 3)
    elif root in ("no",):
        r = CheckResult("ssh_root", "SSH root login", OK, "PermitRootLogin no.", weight=3)
    else:
        r = CheckResult("ssh_root", "SSH root login", WARN,
                        f"PermitRootLogin {root or 'por defecto'}.",
                        "Fija PermitRootLogin no si no usas login root.", 3)

    pw = (_directive(txt, "PasswordAuthentication") or "").lower()
    if pw == "no":
        p = CheckResult("ssh_pass", "SSH password auth", OK, "PasswordAuthentication no.", weight=1)
    else:
        p = CheckResult("ssh_pass", "SSH password auth", WARN,
                        f"PasswordAuthentication {pw or 'por defecto (yes)'}.",
                        "Usa solo claves: PasswordAuthentication no.", 1)
    return [r, p]


def _check_file_perms() -> CheckResult:
    n, w = "Permisos sensibles", 3
    if not is_linux():
        return _na("file_perms", n, "Solo Linux por ahora.", w)
    problems, critical = [], False
    m = _mode("/etc/shadow")
    if m is not None and m & 0o006:
        problems.append(f"/etc/shadow {oct(m)} legible/escribible por otros"); critical = True
    m = _mode("/etc/passwd")
    if m is not None and m & 0o002:
        problems.append("/etc/passwd escribible por otros"); critical = True
    m = _mode("/etc/sudoers")
    if m is not None and m & 0o002:
        problems.append("/etc/sudoers escribible por otros"); critical = True
    ssh = os.path.expanduser("~/.ssh")
    m = _mode(ssh)
    if m is not None and m & 0o077:
        problems.append(f"~/.ssh {oct(m)} (debería 700)")
    if not problems:
        return CheckResult("file_perms", n, OK, "shadow/passwd/sudoers/~/.ssh correctos.", weight=w)
    return CheckResult("file_perms", n, FAIL if critical else WARN, "; ".join(problems),
                       "Restringe permisos con chmod.", w)


def _check_uid0() -> CheckResult:
    n, w = "Cuentas UID 0", 3
    if not is_linux():
        return _na("uid0", n, "Solo Linux por ahora.", w)
    txt = _read("/etc/passwd")
    if txt is None:
        return _na("uid0", n, "/etc/passwd no legible.", w)
    uid0 = [l.split(":")[0] for l in txt.splitlines()
            if len(l.split(":")) >= 3 and l.split(":")[2] == "0"]
    if len(uid0) > 1:
        return CheckResult("uid0", n, FAIL, f"Varias cuentas UID 0: {', '.join(uid0)}.",
                           "Solo root debería tener UID 0.", w)
    return CheckResult("uid0", n, OK, "Solo root con UID 0.", weight=w)


def _check_updates() -> CheckResult:
    n, w = "Actualizaciones pendientes", 2
    if not is_linux():
        return _na("updates", n, "Solo Linux por ahora.", w)
    if shutil.which("apt-get"):
        r = _run(["apt-get", "-s", "upgrade"], timeout=15)  # simulado, usa listas cacheadas
        if not r:
            return _na("updates", n, "apt no determinable.", w)
        count = len(re.findall(r"(?m)^Inst ", r[1]))
        if count == 0:
            return CheckResult("updates", n, OK, "Sistema al día (apt).", weight=w)
        return CheckResult("updates", n, WARN, f"{count} paquetes actualizables (apt).",
                           "Ejecuta apt upgrade.", w)
    if shutil.which("dnf"):
        r = _run(["dnf", "-q", "check-update"], timeout=20)
        if not r:
            return _na("updates", n, "dnf no determinable.", w)
        if r[0] == 100:
            count = len([l for l in r[1].splitlines() if l.strip() and not l.startswith(" ")])
            return CheckResult("updates", n, WARN, f"~{count} paquetes actualizables (dnf).",
                               "Ejecuta dnf upgrade.", w)
        return CheckResult("updates", n, OK, "Sistema al día (dnf).", weight=w)
    return _na("updates", n, "Gestor de paquetes no reconocido.", w)


def _check_disk_encryption() -> CheckResult:
    n, w = "Cifrado de disco", 1
    if not is_linux():
        return _na("disk_crypt", n, "Solo Linux por ahora.", w)
    r = _run(["lsblk", "-o", "TYPE", "-n"])
    if r and "crypt" in r[1]:
        return CheckResult("disk_crypt", n, OK, "Volumen LUKS/crypt detectado.", weight=w)
    txt = _read("/etc/crypttab")
    if txt and any(l.strip() and not l.strip().startswith("#") for l in txt.splitlines()):
        return CheckResult("disk_crypt", n, OK, "crypttab con entradas.", weight=w)
    return CheckResult("disk_crypt", n, WARN, "Sin cifrado de disco detectado.",
                       "Considera LUKS para datos en reposo.", w)


def _check_listening() -> CheckResult:
    n, w = "Puertos a la escucha", 1
    if not is_linux():
        return _na("listen", n, "Solo Linux por ahora.", w)
    try:
        conns = psutil.net_connections(kind="inet")
    except Exception:
        return _na("listen", n, "Requiere root para enumerar sockets.", w)
    public = sorted({c.laddr.port for c in conns
                     if c.status == psutil.CONN_LISTEN and c.laddr
                     and c.laddr.ip in ("0.0.0.0", "::")})
    if not public:
        return CheckResult("listen", n, OK, "Nada escuchando en todas las interfaces.", weight=w)
    return CheckResult("listen", n, WARN,
                       f"Escuchando en 0.0.0.0/:: puertos {', '.join(map(str, public))}.",
                       "Limita binds a 127.0.0.1 o protege con cortafuegos.", w)


# --- Lynis (híbrido) ---------------------------------------------------------
# Lynis está pensado para correr por cron y dejar su report en disco. Por eso:
# auto-parseamos el report si existe (gratis), y --lynis fuerza un run fresco
# (lento, 1-3 min, mejor con root). Nunca bloqueamos el audit por defecto.

LYNIS_REPORT = "/var/log/lynis-report.dat"


def _lynis_report_age_days(txt: str) -> int | None:
    m = (re.search(r"(?m)^report_datetime_end=(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", txt)
         or re.search(r"(?m)^report_datetime_start=(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", txt))
    if not m:
        return None
    try:
        dt = datetime.datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S")
        return max(0, (datetime.datetime.now() - dt).days)
    except Exception:
        return None


def _lynis_checks(force_run: bool) -> list[CheckResult]:
    if force_run and shutil.which("lynis"):
        _run(["lynis", "audit", "system", "--quiet", "--no-colors"], timeout=600)  # lento, a propósito
    txt = _read(LYNIS_REPORT)
    if not txt:
        if force_run:
            return [_na("lynis", "Lynis", "Sin report legible (¿lynis instalado? ¿root?).", 3)]
        return []  # auto: sin report, no ensuciamos el audit
    age = _lynis_report_age_days(txt)
    age_s = f" (report de hace {age}d)" if age is not None else ""
    warns = re.findall(r"(?m)^warning\[\]=(.+)$", txt)
    sugg = re.findall(r"(?m)^suggestion\[\]=(.+)$", txt)
    idx = re.search(r"(?m)^hardening_index=(\d+)", txt)
    out: list[CheckResult] = []
    if idx:
        hi = int(idx.group(1))
        st = OK if hi >= 80 else WARN if hi >= 60 else FAIL
        if age is not None and age > 30 and st == OK:
            st = WARN  # report viejo: no te fíes del OK
        out.append(CheckResult("lynis_index", "Lynis hardening index", st, f"{hi}/100{age_s}", weight=3))
    if warns:
        first = warns[0].split("|")[1] if "|" in warns[0] else warns[0]
        out.append(CheckResult("lynis_warn", "Lynis warnings", WARN,
                               f"{len(warns)} warnings (ej: {first}).", weight=2))
    if sugg:
        out.append(CheckResult("lynis_sugg", "Lynis suggestions",
                               WARN if len(sugg) > 10 else OK, f"{len(sugg)} sugerencias."))
    return out or [_na("lynis", "Lynis", f"Report sin métricas reconocibles{age_s}.", 3)]


# --- scoring + ejecución -----------------------------------------------------

def _score(checks: list[CheckResult]) -> tuple[int, int]:
    num = den = 0.0
    for c in checks:
        if c.status == NA:
            continue
        den += c.weight
        num += c.weight * _VAL[c.status]
    if den == 0:
        return 0, 0
    return round(100 * num / den), int(den)


def _grade(score: int) -> str:
    return "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 \
        else "D" if score >= 60 else "F"


def _worst(checks: list[CheckResult]) -> str:
    sev = max((_SEV[c.status] for c in checks if c.status != NA), default=0)
    return {0: OK, 1: WARN, 2: FAIL}[sev]


def run_audit(lynis: bool = False) -> AuditReport:
    checks = [
        _check_firewall(),
        *_check_ssh(),
        _check_file_perms(),
        _check_uid0(),
        _check_updates(),
        _check_disk_encryption(),
        _check_listening(),
    ]
    checks += _lynis_checks(force_run=lynis)  # auto-parsea report; --lynis fuerza run
    lynis_used = any(c.id.startswith("lynis") and c.status != NA for c in checks)
    score, den = _score(checks)
    grade = _grade(score) if den else "—"
    counts = {s: sum(1 for c in checks if c.status == s) for s in (OK, WARN, FAIL, NA)}
    return AuditReport(checks, score, grade, _worst(checks), counts, is_root(), lynis_used)
