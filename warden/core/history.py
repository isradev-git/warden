"""Histórico de snapshots -> tendencias. Append-only JSONL en XDG_DATA_HOME.

core: sin rich/typer. record() añade una línea compacta por run; load() lee.
La presentación (sparklines, deltas) vive en render.py.
ponytail: guardamos un resumen numérico, no el health entero (sería enorme).
Líneas de un esquema viejo que ya no casen con HistoryPoint se ignoran al leer.
"""
from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass

from warden.core.report import FullReport


def _path() -> str:
    base = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")
    return os.path.join(base, "warden", "history.jsonl")


@dataclass
class HistoryPoint:
    ts: str
    score: int
    grade: str
    ok: int
    warn: int
    fail: int
    cpu: float | None
    ram: float | None
    swap: float | None
    disk: float | None  # peor disco


def _from_report(rep: FullReport) -> HistoryPoint:
    h, a = rep.health, rep.audit
    worst = max((d.percent for d in h.disks), default=None)
    return HistoryPoint(
        ts=rep.generated_at, score=a.score, grade=a.grade,
        ok=a.counts.get("ok", 0), warn=a.counts.get("warn", 0), fail=a.counts.get("fail", 0),
        cpu=h.cpu.percent, ram=h.mem.percent, swap=h.mem.swap_percent, disk=worst)


def record(rep: FullReport, path: str | None = None) -> HistoryPoint:
    p = path or _path()
    os.makedirs(os.path.dirname(p), exist_ok=True)
    pt = _from_report(rep)
    with open(p, "a", encoding="utf-8") as f:
        f.write(json.dumps(asdict(pt)) + "\n")
    return pt


def load(limit: int | None = None, path: str | None = None) -> list[HistoryPoint]:
    p = path or _path()
    out: list[HistoryPoint] = []
    try:
        with open(p, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(HistoryPoint(**json.loads(line)))
                except Exception:
                    continue  # línea corrupta / esquema viejo -> se ignora
    except FileNotFoundError:
        return []
    return out[-limit:] if limit else out


def _demo() -> None:
    import tempfile
    from warden.core import report as core_report
    p = os.path.join(tempfile.mkdtemp(), "h.jsonl")
    rep = core_report.build(lynis=False)
    pt = record(rep, path=p)
    assert pt.score == rep.audit.score
    pts = load(path=p)
    assert len(pts) == 1 and pts[0].ts == pt.ts
    with open(p, "a") as f:
        f.write("basura no-json\n")
    assert len(load(path=p)) == 1  # la corrupta se ignora
    print("history._demo ok")


if __name__ == "__main__":
    _demo()
