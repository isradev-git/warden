"""Self-check fase 0. Corre con `pytest` o `python tests/test_warden.py`."""
import json

from warden import render
from warden.cli import _snap_dict
from warden.core import system


def test_human_bytes():
    assert render.human_bytes(0) == "0 B"
    assert render.human_bytes(1024) == "1.0 KB"
    assert render.human_bytes(None) == "N/A"
    assert render.human_bytes(1536).startswith("1.5")


def test_human_duration():
    assert render.human_duration(None) == "N/A"
    assert render.human_duration(0) == "0s"
    assert render.human_duration(90061) == "1d 1h 1m 1s"


def test_pct_status():
    assert render.pct_status(None) == "na"
    assert render.pct_status(50) == "ok"
    assert render.pct_status(80) == "warn"
    assert render.pct_status(95) == "fail"


def test_pct_bar_no_overflow():
    # la barra nunca debe pasarse de 100% (filled <= width).
    bar = render.pct_bar(100, width=10)
    assert "█" * 10 in bar.plain


def test_collect_health_no_crash():
    snap = system.collect_health(cpu_interval=0.0)
    assert snap.system.os
    assert isinstance(snap.disks, list)
    assert isinstance(snap.procs, list)
    assert isinstance(snap.is_root, bool)


def test_snapshot_json_serializable():
    d = _snap_dict(system.collect_health(cpu_interval=0.0))
    json.dumps(d, default=str)  # no debe lanzar
    assert d["schema_version"] == "1"
    assert d["data"]["system"]["os"]


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok  {name}")
    print("PASS")
