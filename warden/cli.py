"""CLI typer. Front-end fino: pide datos a core, pinta con render."""
from __future__ import annotations

import json
from dataclasses import asdict

import typer

from warden import __version__
from warden import render
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
def info():
    """Información del sistema / SO."""
    render.print_info(system.collect_system_info())


def _snap_dict(snap: system.HealthSnapshot) -> dict:
    return {
        "warden_version": __version__,
        "schema_version": SCHEMA_VERSION,
        "data": asdict(snap),
    }


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
