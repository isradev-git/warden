"""CLI typer. Front-end fino: pide datos a core, pinta con render."""
from __future__ import annotations

import json
from dataclasses import asdict

import typer

from warden import __version__
from warden import render
from warden.core import security
from warden.core import system

SCHEMA_VERSION = "1"

app = typer.Typer(add_completion=False, no_args_is_help=False,
                  help="WARDEN_ — auditor de host y panel de sistemas.  >IZ::")


@app.callback(invoke_without_command=True)
def _default(ctx: typer.Context):
    if ctx.invoked_subcommand is None:
        _health(watch=False, json_out=False, md=False)


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
