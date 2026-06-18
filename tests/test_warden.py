"""Self-check fase 0. Corre con `pytest` o `python tests/test_warden.py`."""
import json

from dataclasses import asdict

from warden import render
from warden.cli import _audit_dict, _exit_code, _snap_dict
from warden.core import report as core_report
from warden.core import expose as core_expose
from warden.core import scripts as core_scripts
from warden.core import secrets as core_secrets
from warden.core import security, system


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


def test_score_grade():
    ok = security.CheckResult("a", "A", security.OK, weight=1)
    warn = security.CheckResult("b", "B", security.WARN, weight=1)
    fail = security.CheckResult("c", "C", security.FAIL, weight=1)
    na = security.CheckResult("d", "D", security.NA, weight=5)
    assert security._score([ok, ok])[0] == 100
    assert security._score([ok, fail])[0] == 50
    assert security._score([warn, na])[0] == 50  # na no cuenta
    assert security._score([na])[1] == 0  # nada aplicable
    assert security._grade(100) == "A" and security._grade(50) == "F"


def test_worst_and_exit_code():
    ok = security.CheckResult("a", "A", security.OK)
    warn = security.CheckResult("b", "B", security.WARN)
    fail = security.CheckResult("c", "C", security.FAIL)
    assert security._worst([ok, warn]) == "warn"
    assert security._worst([ok, warn, fail]) == "fail"
    assert _exit_code("warn", "warn") == 1
    assert _exit_code("warn", "fail") == 0  # warn no rompe build
    assert _exit_code("fail", "fail") == 2


def test_lynis_age_parser():
    txt = "report_datetime_end=2020-01-01 00:00:00\nhardening_index=70\n"
    age = security._lynis_report_age_days(txt)
    assert age is not None and age > 1000
    assert security._lynis_report_age_days("basura sin fecha") is None


def test_run_audit_no_crash():
    rep = security.run_audit(lynis=False)
    assert 0 <= rep.score <= 100
    assert rep.grade in ("A", "B", "C", "D", "F", "—")
    assert rep.worst in ("ok", "warn", "fail")
    assert rep.checks


def test_audit_json_serializable():
    d = _audit_dict(security.run_audit(lynis=False))
    json.dumps(d, default=str)  # no debe lanzar
    assert d["schema_version"] == "1"
    assert "checks" in d["data"]


def test_report_build_and_json():
    rep = core_report.build(lynis=False)
    d = core_report.to_dict(rep)
    json.dumps(d, default=str)  # no debe lanzar
    assert d["schema_version"] and d["generated_at"]
    assert "health" in d and "audit" in d
    assert rep.generated_at


def test_report_md():
    md = render.report_md(core_report.build(lynis=False))
    assert "Health" in md and "Audit" in md


def test_script_generate():
    for n in core_scripts.NAMES:
        g = core_scripts.generate(n)
        assert g.content.startswith("#!/usr/bin/env bash")
        assert "set -euo pipefail" in g.content
        assert g.filename == f"warden-{n}.sh"
    assert 'SRC="${1:-/data}"' in core_scripts.generate("backup", src="/data").content
    try:
        core_scripts.generate("nope")
        assert False, "debería lanzar"
    except ValueError:
        pass


def test_expose_shape_serializable():
    # sin red: forma correcta y JSON-serializable, sin pegar a internet en el test.
    exp = core_expose.Exposure(None, None, {}, core_expose._listening())
    json.dumps(asdict(exp), default=str)
    assert isinstance(exp.listening, list)


def test_secrets_scan():
    assert core_secrets._mask("abc") == "***"
    assert core_secrets._match_line("export AWS_KEY=AKIAIOSFODNN7EXAMPLE")[0] == "AWS access key"
    assert core_secrets._match_line("ls -la /tmp") is None
    sc = core_secrets.scan()
    assert set(sc.counts) == {"warn", "fail"}
    json.dumps(asdict(sc), default=str)  # no debe lanzar
    assert all(f.severity in ("warn", "fail") for f in sc.findings)


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"ok  {name}")
    print("PASS")
