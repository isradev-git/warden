"""CLI typer. Front-end fino: pide datos a core, pinta con render."""
from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Optional

import typer

from warden import SCHEMA_VERSION, __version__
from warden import render
from warden.core import report as core_report
from warden.core import security
from warden.core import system
from warden.core import scripts as core_scripts
from warden.core import expose as core_expose
from warden.core import secrets as core_secrets
from warden.core import cve as core_cve
from warden.core import history as core_history

app = typer.Typer(add_completion=False, no_args_is_help=False,
                  help="WARDEN_ — auditor de host y panel de sistemas.  >IZ::")


@app.callback(invoke_without_command=True)
def _default(ctx: typer.Context):
    if ctx.invoked_subcommand is None:
        rep = core_report.build()
        _record_safe(rep)  # el dashboard auto-puebla el histórico
        render.print_summary(rep)


def _record_safe(rep: core_report.FullReport) -> None:
    try:
        core_history.record(rep)
    except Exception:
        pass  # un fallo de escritura nunca debe romper el dashboard


@app.command()
def health(
    watch: bool = typer.Option(False, "--watch", help="Refresco en vivo cada 2s (Ctrl-C para salir)."),
    json_out: bool = typer.Option(False, "--json", help="Salida JSON para máquina/CI."),
    md: bool = typer.Option(False, "--md", help="Salida Markdown."),
):
    """Diagnóstico del sistema en vivo."""
    _health(watch, json_out, md)


@app.command()
def audit(
    json_out: bool = typer.Option(False, "--json", help="Salida JSON para máquina/CI."),
    md: bool = typer.Option(False, "--md", help="Salida Markdown."),
    fail_on: str = typer.Option("warn", "--fail-on", help="Umbral de código !=0: warn|fail."),
    lynis: bool = typer.Option(False, "--lynis", help="Ejecuta también Lynis (lento, mejor con root)."),
):
    """Auditoría de seguridad + hardening score 0-100."""
    if json_out and md:
        raise typer.BadParameter("Usa --json o --md, no ambos.")
    if fail_on not in ("warn", "fail"):
        raise typer.BadParameter("--fail-on debe ser 'warn' o 'fail'.")
    rep = security.run_audit(lynis=lynis)
    if json_out:
        print(json.dumps(_audit_dict(rep), indent=2, default=str))
    elif md:
        print(render.audit_md(rep))
    else:
        render.print_audit(rep)
    raise typer.Exit(_exit_code(rep.worst, fail_on))


@app.command()
def report(
    json_out: bool = typer.Option(False, "--json", help="Salida JSON versionada para máquina/CI."),
    md: bool = typer.Option(False, "--md", help="Salida Markdown (vault/informe)."),
    lynis: bool = typer.Option(False, "--lynis", help="Fuerza un run fresco de Lynis (lento)."),
):
    """Informe combinado health + audit."""
    if json_out and md:
        raise typer.BadParameter("Usa --json o --md, no ambos.")
    rep = core_report.build(lynis=lynis)
    if json_out:
        print(json.dumps(core_report.to_dict(rep), indent=2, default=str))
    elif md:
        print(render.report_md(rep))
    else:
        render.print_summary(rep)


@app.command()
def script(
    name: str = typer.Argument(..., help="Script a generar: backup | cleanup | update."),
    src: Optional[str] = typer.Option(None, "--src", help="(backup) ruta origen."),
    dest: Optional[str] = typer.Option(None, "--dest", help="(backup) ruta destino."),
    out: Optional[str] = typer.Option(None, "-o", "--out", help="Escribe a fichero en vez de mostrar."),
):
    """Genera y muestra un script bash. NO lo ejecuta."""
    try:
        gen = core_scripts.generate(name, src=src, dest=dest)
    except ValueError as e:
        raise typer.BadParameter(str(e))
    if out:
        Path(out).write_text(gen.content, encoding="utf-8")
        typer.echo(f"Escrito en {out}  (revísalo antes de ejecutar: chmod +x {out} && ./{out})", err=True)
    else:
        render.print_script(gen)


@app.command()
def expose(json_out: bool = typer.Option(False, "--json", help="Salida JSON para máquina/CI.")):
    """OSINT de auto-exposición: IP pública, geoloc, reverse DNS, puertos públicos."""
    exp = core_expose.collect_exposure()
    if json_out:
        print(json.dumps(asdict(exp), indent=2, default=str))
    else:
        render.print_expose(exp)


@app.command(name="scan-secrets")
def scan_secrets(json_out: bool = typer.Option(False, "--json", help="Salida JSON para máquina/CI.")):
    """Busca secretos expuestos en env, history y ficheros sensibles."""
    sc = core_secrets.scan()
    if json_out:
        print(json.dumps(asdict(sc), indent=2, default=str))
    else:
        render.print_secrets(sc)
    raise typer.Exit(2 if sc.counts["fail"] else 1 if sc.counts["warn"] else 0)


@app.command()
def cve(
    json_out: bool = typer.Option(False, "--json", help="Salida JSON para máquina/CI."),
    details: int = typer.Option(0, "--details", help="Enriquece N vulns con resumen/severidad (lento)."),
):
    """CVEs conocidas de los paquetes instalados (vía OSV.dev)."""
    rep = core_cve.collect_cve(details=details)
    if json_out:
        print(json.dumps(asdict(rep), indent=2, default=str))
    else:
        render.print_cve(rep)
    raise typer.Exit(1 if rep.vuln_count else 0)  # warn: el match de versión no es exacto


@app.command()
def record():
    """Registra un snapshot (score + vitales) en el histórico. Para cron."""
    pt = core_history.record(core_report.build())
    typer.echo(f"Registrado · score {pt.score} ({pt.grade}) · {pt.ts}")


@app.command()
def history(
    json_out: bool = typer.Option(False, "--json", help="Salida JSON para máquina/CI."),
    limit: int = typer.Option(30, "--limit", help="Nº de registros recientes a mostrar."),
):
    """Tendencias del histórico (score y vitales en el tiempo)."""
    pts = core_history.load(limit=limit)
    if json_out:
        print(json.dumps({"warden_version": __version__, "schema_version": SCHEMA_VERSION,
                          "data": [asdict(p) for p in pts]}, indent=2, default=str))
    else:
        render.print_history(pts)


@app.command()
def info():
    """Información del sistema / SO."""
    render.print_info(system.collect_system_info())


def _snap_dict(snap: system.HealthSnapshot) -> dict:
    return {
        "warden_version": __version__,
        "schema_version": SCHEMA_VERSION,
        "data": asdict(snap),
    }


def _audit_dict(rep: security.AuditReport) -> dict:
    return {
        "warden_version": __version__,
        "schema_version": SCHEMA_VERSION,
        "data": asdict(rep),
    }


def _exit_code(worst: str, fail_on: str) -> int:
    sev = {"ok": 0, "warn": 1, "fail": 2}[worst]
    if fail_on == "fail" and sev == 1:  # los warn no rompen el build
        return 0
    return sev


def _health(watch: bool, json_out: bool, md: bool) -> None:
    if json_out and md:
        raise typer.BadParameter("Usa --json o --md, no ambos.")
    if watch:
        render.watch_health()
        return
    snap = system.collect_health()
    if json_out:
        print(json.dumps(_snap_dict(snap), indent=2, default=str))
    elif md:
        print(render.health_md(snap))
    else:
        render.print_health(snap)


if __name__ == "__main__":
    app()
