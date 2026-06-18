"""CVE de paquetes instalados vía OSV.dev.

Enumera paquetes del gestor del sistema (dpkg/rpm/pacman) y los consulta en
batch contra api.osv.dev. Devuelve qué paquetes tienen vulnerabilidad conocida.
core: sin rich/typer. Sin red / sin gestor -> error en el report, nunca crash.

ponytail: el match de versión lo hace OSV en servidor (best-effort); puede dar
falsos positivos binario-vs-fuente. Severidad solo si OSV trae label; parsear el
vector CVSS a número se deja para cuando importe. Cobertura exhaustiva -> grype/trivy.
"""
from __future__ import annotations

import json
import re
import shutil
import urllib.request
from dataclasses import dataclass, field

from warden.core.security import _run
from warden.platform_utils import is_linux

try:
    import distro
except Exception:  # pragma: no cover
    distro = None

_BATCH = "https://api.osv.dev/v1/querybatch"
_VULN = "https://api.osv.dev/v1/vulns/"
_CHUNK = 1000  # límite de queries por POST en querybatch


@dataclass
class Vuln:
    id: str
    aliases: list[str]  # CVE-...
    summary: str
    severity: str  # label (HIGH/...) o "CVSS" o "—"


@dataclass
class PkgVulns:
    package: str
    version: str
    vulns: list[Vuln] = field(default_factory=list)


@dataclass
class CveReport:
    ecosystem: str
    pkg_count: int            # paquetes consultados
    affected: list[PkgVulns]
    vuln_count: int
    error: str | None = None
    truncated_details: bool = False  # se acabó el presupuesto de detalles


# --- red ---------------------------------------------------------------------

def _post(url: str, payload: dict, timeout: float = 20.0) -> dict | None:
    try:
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            url, data=data,
            headers={"Content-Type": "application/json", "User-Agent": "warden"})
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 (url fijo https)
            return json.loads(r.read().decode("utf-8", "ignore"))
    except Exception:
        return None


def _get_json(url: str, timeout: float = 10.0) -> dict | None:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "warden"})
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310
            return json.loads(r.read().decode("utf-8", "ignore"))
    except Exception:
        return None


# --- enumeración de paquetes -------------------------------------------------

def _dpkg() -> list[tuple[str, str]]:
    r = _run(["dpkg-query", "-W", "-f=${Package} ${Version}\n"], timeout=20)
    if not r or r[0] != 0:
        return []
    out = []
    for line in r[1].splitlines():
        p = line.split(" ", 1)
        if len(p) == 2 and p[0] and p[1]:
            out.append((p[0], p[1]))
    return out


def _rpm() -> list[tuple[str, str]]:
    r = _run(["rpm", "-qa", "--qf", "%{NAME} %{VERSION}-%{RELEASE}\n"], timeout=20)
    if not r or r[0] != 0:
        return []
    return [(p[0], p[1]) for line in r[1].splitlines()
            if len((p := line.split(" ", 1))) == 2 and p[0] and p[1]]


def _pacman() -> list[tuple[str, str]]:
    r = _run(["pacman", "-Q"], timeout=20)
    if not r or r[0] != 0:
        return []
    return [(p[0], p[1]) for line in r[1].splitlines()
            if len((p := line.split(" ", 1))) == 2 and p[0] and p[1]]


def _collect_packages() -> tuple[str, list[tuple[str, str]]]:
    """(ecosystem OSV, [(nombre, versión)]). ('', []) si no hay gestor soportado."""
    if not is_linux():
        return "", []
    if shutil.which("dpkg-query"):
        eco = "Ubuntu" if (distro and distro.id() == "ubuntu") else "Debian"
        return eco, _dpkg()
    if shutil.which("rpm"):
        eco = {"fedora": "Fedora", "rocky": "Rocky Linux", "almalinux": "AlmaLinux",
               "rhel": "Red Hat", "opensuse-leap": "openSUSE"}.get(
                   distro.id() if distro else "", "Debian")
        return eco, _rpm()
    if shutil.which("pacman"):
        return "Arch Linux", _pacman()
    return "", []


# --- consulta OSV ------------------------------------------------------------

def _query(ecosystem: str, pkgs: list[tuple[str, str]]) -> dict[str, list[str]]:
    """nombre -> [vuln_id]. querybatch alinea results con queries por índice."""
    found: dict[str, list[str]] = {}
    for i in range(0, len(pkgs), _CHUNK):
        chunk = pkgs[i:i + _CHUNK]
        payload = {"queries": [
            {"version": v, "package": {"name": n, "ecosystem": ecosystem}} for n, v in chunk]}
        resp = _post(_BATCH, payload)
        if not resp:
            continue
        for (n, _v), res in zip(chunk, resp.get("results", [])):
            vulns = (res or {}).get("vulns") or []
            ids = [x["id"] for x in vulns if "id" in x]
            if ids:
                found.setdefault(n, []).extend(ids)
    return found


def _severity(d: dict) -> str:
    ds = d.get("database_specific") or {}
    if isinstance(ds.get("severity"), str) and ds["severity"]:
        return ds["severity"].upper()
    for a in d.get("affected") or []:
        eds = a.get("database_specific") or {}
        if eds.get("severity"):
            return str(eds["severity"]).upper()
    if d.get("severity"):
        return "CVSS"  # ponytail: vector presente; parsear a score base cuando importe
    return "—"


def _cve_alias(vid: str) -> str:
    # UBUNTU-CVE-2026-1234 / DEBIAN-CVE-... -> CVE-2026-1234; si no, el id tal cual.
    m = re.search(r"CVE-\d{4}-\d+", vid)
    return m.group(0) if m else vid


def _detail(vid: str) -> Vuln:
    d = _get_json(_VULN + vid)
    if not d:
        return Vuln(vid, [_cve_alias(vid)], "", "—")
    aliases = [a for a in (d.get("aliases") or []) if a.upper().startswith("CVE")] or [_cve_alias(vid)]
    summary = d.get("summary") or (d.get("details") or "")[:140].replace("\n", " ").strip()
    return Vuln(vid, aliases, summary, _severity(d))


def collect_cve(details: int = 0) -> CveReport:
    """Por defecto (details=0) solo el batch query: rápido, sin un GET por vuln.
    details>0 enriquece con resumen/severidad las primeras N vulns (lento)."""
    ecosystem, pkgs = _collect_packages()
    if not ecosystem:
        return CveReport("", 0, [], 0,
                         error="Sin gestor de paquetes soportado (dpkg/rpm/pacman en Linux).")
    if not pkgs:
        return CveReport(ecosystem, 0, [], 0, error="No se pudieron enumerar paquetes.")
    found = _query(ecosystem, pkgs)
    if not found:
        return CveReport(ecosystem, len(pkgs), [], 0)  # 0 vulns (o OSV no respondió)

    ver = dict(pkgs)
    budget, truncated = details, False
    affected: list[PkgVulns] = []
    for name in found:
        vulns = []
        for vid in dict.fromkeys(found[name]):  # dedup conservando orden
            if budget > 0:
                vulns.append(_detail(vid))
                budget -= 1
            else:
                vulns.append(Vuln(vid, [_cve_alias(vid)], "", "—"))
                truncated = details > 0  # se pidió detalle pero se agotó el presupuesto
        affected.append(PkgVulns(name, ver.get(name, "?"), vulns))
    affected.sort(key=lambda p: (-len(p.vulns), p.package))  # peores ofensores primero
    vuln_count = sum(len(p.vulns) for p in affected)
    return CveReport(ecosystem, len(pkgs), affected, vuln_count, truncated_details=truncated)


def _demo() -> None:
    # offline-safe: enum local no necesita red; query sí, toleramos que falle.
    eco, pkgs = _collect_packages()
    assert isinstance(pkgs, list)
    assert _severity({"database_specific": {"severity": "high"}}) == "HIGH"
    assert _severity({"severity": [{"type": "CVSS_V3", "score": "x"}]}) == "CVSS"
    assert _severity({}) == "—"
    assert _cve_alias("UBUNTU-CVE-2026-1234") == "CVE-2026-1234"
    assert _cve_alias("DSA-5000-1") == "DSA-5000-1"
    print(f"cve._demo ok (ecosystem={eco or 'n/a'}, {len(pkgs)} paquetes)")


if __name__ == "__main__":
    _demo()
