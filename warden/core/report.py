"""Informe combinado health + audit -> dataclass + dict JSON versionado.

core: sin rich/typer. La presentación (terminal/Markdown) vive en render.py.
"""
from __future__ import annotations

import datetime
from dataclasses import asdict, dataclass

from warden import SCHEMA_VERSION, __version__
from warden.core import security, system


@dataclass
class FullReport:
    health: system.HealthSnapshot
    audit: security.AuditReport
    generated_at: str  # ISO-8601 local


def build(lynis: bool = False) -> FullReport:
    return FullReport(
        health=system.collect_health(),
        audit=security.run_audit(lynis=lynis),
        generated_at=datetime.datetime.now().isoformat(timespec="seconds"),
    )


def to_dict(rep: FullReport) -> dict:
    return {
        "warden_version": __version__,
        "schema_version": SCHEMA_VERSION,
        "generated_at": rep.generated_at,
        "health": asdict(rep.health),
        "audit": asdict(rep.audit),
    }
