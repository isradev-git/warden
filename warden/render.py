"""Render rich de los datos. Toda la presentación vive aquí; core no sabe de rich."""
from __future__ import annotations

import time

from rich.columns import Columns
from rich.console import Group
from rich.live import Live
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from warden.console import BG_PANEL, console
from warden.core import system
from warden.core import security
from warden.core import report as core_report
from warden.core import scripts as core_scripts
from warden.core import expose as core_expose
from warden.core import secrets as core_secrets
from warden.core import cve as core_cve
from warden.core import history as core_history

LEVEL_STYLE = {"ok": "warden.ok", "warn": "warden.warn", "fail": "warden.fail", "na": "warden.na"}
STATUS_DOT = {"ok": "●", "warn": "●", "fail": "●", "na": "○"}
GRADE_STYLE = {"A": "warden.ok", "B": "warden.ok", "C": "warden.warn",
               "D": "warden.warn", "F": "warden.fail", "—": "warden.na"}


def human_bytes(n) -> str:
    if n is None:
        return "N/A"
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if abs(n) < 1024 or unit == "PB":
            return f"{int(n)} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def human_duration(s) -> str:
    if s is None:
        return "N/A"
    s = int(s)
    d, s = divmod(s, 86400)
    h, s = divmod(s, 3600)
    m, s = divmod(s, 60)
    parts = []
    if d:
        parts.append(f"{d}d")
    if h:
        parts.append(f"{h}h")
    if m:
        parts.append(f"{m}m")
    parts.append(f"{s}s")
    return " ".join(parts)


def pct_status(p) -> str:
    if p is None:
        return "na"
    if p < 70:
        return "ok"
    if p < 90:
        return "warn"
    return "fail"


def _fmt_pct(p) -> str:
    return "N/A" if p is None else f"{p:.1f}%"


def pct_bar(percent, width: int = 22) -> Text:
    if percent is None:
        return Text("N/A", style="warden.na")
    lvl = LEVEL_STYLE[pct_status(percent)]
    filled = round(percent / 100 * width)
    t = Text()
    t.append("█" * filled, style=lvl)
    t.append("░" * (width - filled), style="warden.muted")
    t.append(f" {percent:5.1f}%", style=lvl)
    return t


def _panel(body, title):
    return Panel(body, title=Text(title, style="warden.header"), title_align="left",
                 border_style="warden.accent", style=BG_PANEL)


def _header(snap: system.HealthSnapshot) -> Panel:
    si = snap.system
    left = Text.assemble(
        ("WARDEN", "warden.brand"), ("_", "warden.accent2"),
        (f"  {si.hostname} · {si.distro or si.os} · up {human_duration(si.uptime)}", "warden.muted"),
    )
    badge = (Text(" ROOT ", style="bold #0d0d12 on #3dff94") if snap.is_root
             else Text(" SIN PRIVILEGIOS ", style="bold #0d0d12 on #ffcc3d"))
    g = Table.grid(expand=True)
    g.add_column(justify="left", ratio=1, no_wrap=True, overflow="ellipsis")  # subtítulo se recorta, no envuelve
    g.add_column(justify="right")
    g.add_row(left, badge)
    return Panel(g, border_style="warden.accent", style=BG_PANEL)


def _cpu_panel(c: system.CpuInfo) -> Panel:
    g = Table.grid(padding=(0, 1))
    g.add_column(style="warden.muted", justify="right")
    g.add_column()
    g.add_row("uso", pct_bar(c.percent))
    if c.load_avg:
        g.add_row("load", Text(f"{c.load_avg[0]:.2f}  {c.load_avg[1]:.2f}  {c.load_avg[2]:.2f}",
                               style="warden.value"))
    cores = f"{c.cores_physical}/{c.cores_logical}" if c.cores_logical else "N/A"
    g.add_row("cores", Text(f"{cores} fís/lóg", style="warden.value"))
    if c.freq_mhz:
        g.add_row("freq", Text(f"{c.freq_mhz:.0f} MHz", style="warden.value"))
    return _panel(g, "CPU")


def _mem_panel(m: system.MemInfo) -> Panel:
    g = Table.grid(padding=(0, 1))
    g.add_column(style="warden.muted", justify="right")
    g.add_column()
    g.add_row("ram", pct_bar(m.percent))
    g.add_row("", Text(f"{human_bytes(m.used)} / {human_bytes(m.total)}", style="warden.value"))
    g.add_row("swap", pct_bar(m.swap_percent))
    g.add_row("", Text(f"{human_bytes(m.swap_used)} / {human_bytes(m.swap_total)}", style="warden.value"))
    return _panel(g, "Memoria")


def _disks_table(disks: list[system.DiskInfo]) -> Panel:
    t = Table(expand=True, header_style="warden.header", border_style="warden.accent", box=None)
    t.add_column("Montaje", style="warden.value")
    t.add_column("FS", style="warden.muted")
    t.add_column("Tamaño", justify="right", style="warden.muted")
    t.add_column("Uso", ratio=1)
    if not disks:
        t.add_row("N/A", "", "", Text("sin discos legibles", style="warden.na"))
    for d in disks:
        t.add_row(d.mountpoint, d.fstype, human_bytes(d.total), pct_bar(d.percent))
    return _panel(t, "Discos")


def _net_panel(net: system.NetInfo) -> Panel:
    g = Table.grid(padding=(0, 1))
    g.add_column(style="warden.muted", justify="right")
    g.add_column(style="warden.value")
    g.add_row("↑ enviado", human_bytes(net.bytes_sent))
    g.add_row("↓ recibido", human_bytes(net.bytes_recv))
    up = [i for i in net.ifaces if i.isup and i.addresses]
    for i in up[:4]:
        g.add_row(i.name, ", ".join(i.addresses[:2]))
    return _panel(g, "Red")


def _temps_panel(temps: list[system.TempInfo]) -> Panel:
    if not temps:
        return _panel(Text("N/A — sin sensores legibles", style="warden.na"), "Temperaturas")
    g = Table.grid(padding=(0, 1))
    g.add_column(style="warden.muted")
    g.add_column(justify="right")
    for t in temps[:8]:
        lvl = "fail" if t.critical and t.current >= t.critical else (
            "warn" if t.high and t.current >= t.high else "ok")
        g.add_row(t.label, Text(f"{t.current:.0f}°C", style=LEVEL_STYLE[lvl]))
    return _panel(g, "Temperaturas")


def _procs_table(procs: list[system.ProcInfo]) -> Panel:
    t = Table(expand=True, header_style="warden.header", border_style="warden.accent", box=None)
    t.add_column("PID", justify="right", style="warden.muted")
    t.add_column("Proceso", style="warden.value")
    t.add_column("CPU%", justify="right")
    t.add_column("MEM%", justify="right")
    for p in procs:
        t.add_row(str(p.pid), p.name, f"{p.cpu:.1f}", f"{p.mem:.1f}")
    return _panel(t, "Top procesos")


def health_renderable(snap: system.HealthSnapshot) -> Group:
    return Group(
        _header(snap),
        Columns([_cpu_panel(snap.cpu), _mem_panel(snap.mem)], equal=True, expand=True),
        _disks_table(snap.disks),
        Columns([_net_panel(snap.net), _temps_panel(snap.temps)], equal=True, expand=True),
        _procs_table(snap.procs),
    )


def print_health(snap: system.HealthSnapshot) -> None:
    console.print(health_renderable(snap))


def watch_health() -> None:
    system.collect_cpu(None)  # primer muestreo para que cpu_percent tenga delta
    try:
        with Live(console=console, screen=True, auto_refresh=False) as live:
            while True:
                live.update(health_renderable(system.collect_health(cpu_interval=None)))
                live.refresh()
                time.sleep(2)
    except KeyboardInterrupt:
        pass


def score_bar(score, width: int = 28) -> Text:
    # score: alto = bueno (inverso a uso de recursos), por eso no reusa pct_bar.
    lvl = "ok" if score >= 80 else "warn" if score >= 60 else "fail"
    filled = round(score / 100 * width)
    t = Text()
    t.append("█" * filled, style=LEVEL_STYLE[lvl])
    t.append("░" * (width - filled), style="warden.muted")
    t.append(f" {score:3d}/100", style=LEVEL_STYLE[lvl])
    return t


def _counts_line(counts: dict) -> Text:
    t = Text()
    for i, (st, label) in enumerate((("ok", "ok"), ("warn", "warn"), ("fail", "fail"), ("na", "na"))):
        sep = "" if i == 0 else " "
        t.append(f"{sep}{STATUS_DOT[st]} {counts.get(st, 0)} {label}", style=LEVEL_STYLE[st])
    return t


def _score_panel(rep: security.AuditReport, bar_width: int = 28) -> Panel:
    gstyle = GRADE_STYLE.get(rep.grade, "warden.na")
    line1 = Text()
    line1.append(f" {rep.grade} ", style=f"bold reverse {gstyle}")
    line1.append("  ")
    line1.append_text(score_bar(rep.score, bar_width))
    rows = [line1, _counts_line(rep.counts)]
    if not rep.is_root:
        rows.append(Text("cobertura parcial — sin root", style="warden.muted"))
    title = "Hardening" + ("  · Lynis" if rep.lynis_used else "")
    return _panel(Group(*rows), title)


def _checks_table(checks: list[security.CheckResult]) -> Panel:
    t = Table(expand=True, header_style="warden.header", border_style="warden.accent", box=None)
    t.add_column("", width=1)
    t.add_column("Check", style="warden.value", no_wrap=True)
    t.add_column("Detalle", ratio=1, overflow="fold")
    for c in checks:
        dot = Text(STATUS_DOT[c.status], style=LEVEL_STYLE[c.status])
        detail = c.detail
        if c.recommendation and c.status in ("warn", "fail"):
            detail = f"{detail}  → {c.recommendation}"
        t.add_row(dot, c.name, Text(detail or "—", style="warden.muted"))
    return _panel(t, "Checks")


def audit_renderable(rep: security.AuditReport) -> Group:
    return Group(_score_panel(rep), _checks_table(rep.checks))


def print_audit(rep: security.AuditReport) -> None:
    console.print(audit_renderable(rep))


def audit_md(rep: security.AuditReport) -> str:
    L = [
        "# WARDEN_ — Audit", "",
        f"- **Hardening score:** {rep.score}/100 · **grade {rep.grade}**",
        f"- **Privilegios:** {'root' if rep.is_root else 'usuario (cobertura parcial)'}",
        f"- **Lynis:** {'sí' if rep.lynis_used else 'no'}",
        f"- **Resumen:** {rep.counts['ok']} ok · {rep.counts['warn']} warn · "
        f"{rep.counts['fail']} fail · {rep.counts['na']} n/a",
        "", "| | Check | Estado | Detalle | Recomendación |", "|---|---|---|---|---|",
    ]
    for c in rep.checks:
        L.append(f"| {STATUS_DOT[c.status]} | {c.name} | {c.status.upper()} | "
                 f"{c.detail or '—'} | {c.recommendation or '—'} |")
    return "\n".join(L)


def _vitals_panel(snap: system.HealthSnapshot) -> Panel:
    g = Table.grid(padding=(0, 1))
    g.add_column(style="warden.muted", justify="right")
    g.add_column(ratio=1)
    g.add_row("cpu", pct_bar(snap.cpu.percent, 16))
    g.add_row("ram", pct_bar(snap.mem.percent, 16))
    if snap.mem.swap_total:
        g.add_row("swap", pct_bar(snap.mem.swap_percent, 16))
    worst = max(snap.disks, key=lambda d: d.percent, default=None)
    if worst:
        g.add_row(f"disco {worst.mountpoint}", pct_bar(worst.percent, 16))
    if snap.cpu.load_avg:
        la = snap.cpu.load_avg
        g.add_row("load", Text(f"{la[0]:.2f}  {la[1]:.2f}  {la[2]:.2f}", style="warden.value"))
    return _panel(g, "Vitales")


def _issues_panel(audit: security.AuditReport) -> Panel:
    issues = [c for c in audit.checks if c.status in ("warn", "fail")]
    if not issues:
        return _panel(Text("Sin incidencias.", style="warden.ok"), "Incidencias")
    order = {"fail": 0, "warn": 1}
    t = Table.grid(padding=(0, 1))
    t.add_column(width=1)
    t.add_column(style="warden.value", no_wrap=True)
    t.add_column(ratio=1, overflow="fold")
    for c in sorted(issues, key=lambda c: order[c.status]):
        t.add_row(Text(STATUS_DOT[c.status], style=LEVEL_STYLE[c.status]), c.name,
                  Text(c.recommendation or c.detail, style="warden.muted"))
    return _panel(t, f"Incidencias ({len(issues)})")


def summary_renderable(rep: core_report.FullReport) -> Group:
    top = Table.grid(expand=True, padding=(0, 1))  # grid fuerza mitad y mitad; Columns no encajaba a 80 col
    top.add_column(ratio=1)
    top.add_column(ratio=1)
    top.add_row(_score_panel(rep.audit, bar_width=18), _vitals_panel(rep.health))
    return Group(_header(rep.health), top, _issues_panel(rep.audit))


def print_summary(rep: core_report.FullReport) -> None:
    console.print(summary_renderable(rep))


def report_md(rep: core_report.FullReport) -> str:
    return "\n".join([
        f"# WARDEN_ — Report · {rep.health.system.hostname}",
        f"_Generado: {rep.generated_at}_", "", "---", "",
        health_md(rep.health), "", "---", "", audit_md(rep.audit),
    ])


def print_script(gen: core_scripts.GeneratedScript) -> None:
    syn = Syntax(gen.content, "bash", theme="ansi_dark", background_color="#15090f",
                 word_wrap=True)
    console.print(_panel(syn, f"script · {gen.name}  →  {gen.filename}"))


def expose_renderable(exp: core_expose.Exposure) -> Group:
    g = Table.grid(padding=(0, 1))
    g.add_column(style="warden.muted", justify="right")
    g.add_column(style="warden.value", overflow="fold")
    g.add_row("IP pública", exp.public_ip or Text("N/A", style="warden.na"))
    g.add_row("Reverse DNS", exp.reverse_dns or "—")
    if exp.geo:
        loc = ", ".join(filter(None, (exp.geo.get("city"), exp.geo.get("regionName"),
                                      exp.geo.get("country"))))
        g.add_row("Ubicación", loc or "—")
        g.add_row("ISP", exp.geo.get("isp") or exp.geo.get("org") or "—")
    if exp.error:
        g.add_row("Aviso", Text(exp.error, style="warden.warn"))
    top = _panel(g, "Auto-exposición")

    if not exp.listening:
        ports = _panel(Text("Nada escuchando en 0.0.0.0/:: (o sin permiso).", style="warden.ok"),
                       "Puertos en interfaz pública")
    else:
        t = Table(expand=True, header_style="warden.header", box=None)
        t.add_column("Puerto", justify="right", style="warden.warn")
        t.add_column("Proceso", style="warden.value", ratio=1)
        for item in exp.listening:
            t.add_row(str(item["port"]), item["proc"] or "—")
        ports = _panel(Group(
            Text("Escuchando en todas las interfaces — exposición potencial, "
                 "no alcanzabilidad confirmada.", style="warden.muted"), t),
            f"Puertos en interfaz pública ({len(exp.listening)})")
    return Group(top, ports)


def print_expose(exp: core_expose.Exposure) -> None:
    console.print(expose_renderable(exp))


def secrets_renderable(scan: core_secrets.SecretScan) -> Panel:
    sub = (f"env: {scan.scanned['env_vars']} vars · "
           f"history: {scan.scanned['history_files']} · "
           f"ficheros sensibles: {scan.scanned['sensitive_files']}")
    if not scan.findings:
        return _panel(Group(Text("Sin secretos expuestos detectados.", style="warden.ok"),
                            Text(sub, style="warden.muted")), "Secret scan")
    sev = {"fail": 0, "warn": 1}
    t = Table(expand=True, header_style="warden.header", box=None)
    t.add_column("", width=1)
    t.add_column("Origen", style="warden.muted", no_wrap=True)
    t.add_column("Ubicación", style="warden.value", overflow="fold")
    t.add_column("Tipo", overflow="fold")
    t.add_column("Valor", style="warden.muted", no_wrap=True)
    for f in sorted(scan.findings, key=lambda f: sev[f.severity]):
        t.add_row(Text(STATUS_DOT[f.severity], style=LEVEL_STYLE[f.severity]),
                  f.source, f.location, f.kind, f.masked)
    title = f"Secret scan — {scan.counts['fail']} fail · {scan.counts['warn']} warn"
    return _panel(Group(t, Text(sub, style="warden.muted")), title)


def print_secrets(scan: core_secrets.SecretScan) -> None:
    console.print(secrets_renderable(scan))


_CVE_ROWS = 30  # tope de paquetes mostrados; --json da el listado completo


def cve_renderable(rep: core_cve.CveReport) -> Panel:
    if rep.error:
        return _panel(Text(rep.error, style="warden.warn"), "CVE · OSV.dev")
    sub = Text(f"ecosistema {rep.ecosystem} · {rep.pkg_count} paquetes · "
               f"{rep.vuln_count} vulns en {len(rep.affected)} paquetes  ·  "
               "según OSV.dev (el match de versión puede dar falsos positivos)",
               style="warden.muted")
    if not rep.affected:
        return _panel(Group(Text(f"Sin CVEs conocidas en {rep.pkg_count} paquetes.",
                                 style="warden.ok"), sub), "CVE · OSV.dev")
    t = Table(expand=True, header_style="warden.header", box=None, pad_edge=False)
    t.add_column("Paquete", style="warden.value", width=18, no_wrap=True, overflow="ellipsis")
    t.add_column("Versión", style="warden.muted", width=20, no_wrap=True, overflow="ellipsis")
    t.add_column("Vulns", justify="right", width=5, no_wrap=True)
    t.add_column("CVEs", ratio=1, no_wrap=True, overflow="ellipsis")
    for p in rep.affected[:_CVE_ROWS]:
        ids = [v.aliases[0] if v.aliases else v.id for v in p.vulns]
        sample = ", ".join(ids[:2]) + (f", +{len(ids) - 2}" if len(ids) > 2 else "")
        cstyle = "warden.fail" if len(p.vulns) >= 10 else "warden.warn"
        t.add_row(p.package, p.version, Text(str(len(p.vulns)), style=cstyle),
                  Text(sample, style="warden.accent2"))
    rows = [t]
    if len(rep.affected) > _CVE_ROWS:
        rows.append(Text(f"… +{len(rep.affected) - _CVE_ROWS} paquetes más  ·  "
                         "usa --json para el listado completo", style="warden.warn"))
    rows.append(sub)
    return _panel(Group(*rows), f"CVE · OSV.dev ({rep.vuln_count})")


def print_cve(rep: core_cve.CveReport) -> None:
    console.print(cve_renderable(rep))


_SPARK = "▁▂▃▄▅▆▇█"


def sparkline(values, lo: float = 0.0, hi: float = 100.0) -> str:
    out = []
    span = hi - lo
    for v in values:
        if v is None:
            out.append(" ")
            continue
        frac = 0.0 if span <= 0 else (v - lo) / span
        idx = min(len(_SPARK) - 1, max(0, round(frac * (len(_SPARK) - 1))))
        out.append(_SPARK[idx])
    return "".join(out)


def _short_ts(ts: str) -> str:
    # "2026-06-18T14:30:05" -> "06-18 14:30"
    return ts[5:16].replace("T", " ") if len(ts) >= 16 else ts


def _delta(cur, base, good_up: bool) -> Text:
    if cur is None or base is None:
        return Text("—", style="warden.muted")
    d = cur - base
    if round(d) == 0:
        return Text("·", style="warden.muted")  # sin cambio
    arrow = "↑" if d > 0 else "↓"
    good = (d > 0) == good_up
    return Text(f"{arrow}{abs(round(d))}", style="warden.ok" if good else "warden.fail")


def history_renderable(points: list[core_history.HistoryPoint]) -> Panel:
    if not points:
        return _panel(Text("Sin histórico todavía — corre `warden record` "
                           "(o ponlo en cron) para acumular tendencias.", style="warden.warn"),
                      "Histórico")
    first, last = points[0], points[-1]
    sub = Text(f"{len(points)} registros · {_short_ts(first.ts)} → {_short_ts(last.ts)}",
               style="warden.muted")
    if len(points) < 2:
        return _panel(Group(Text("Solo 1 registro; corre `warden record` más veces "
                                 "para ver tendencias.", style="warden.muted"), sub), "Histórico")

    g = Table.grid(padding=(0, 1))
    g.add_column(style="warden.muted", justify="right")
    g.add_column(no_wrap=True)            # sparkline
    g.add_column(justify="right")          # valor actual
    g.add_column(justify="right")          # delta vs primero
    metrics = [
        ("score", "score", "warden.value", True),
        ("cpu", "cpu", "warden.accent2", False),
        ("ram", "ram", "warden.accent2", False),
        ("disk", "disco", "warden.accent2", False),
    ]
    for attr, label, style, good_up in metrics:
        series = [getattr(p, attr) for p in points]
        cur = series[-1]
        g.add_row(label, Text(sparkline(series), style=style),
                  Text("—" if cur is None else f"{cur:.0f}", style=style),
                  _delta(cur, series[0], good_up))

    t = Table(expand=True, header_style="warden.header", box=None, pad_edge=False)
    t.add_column("Fecha", style="warden.muted", no_wrap=True)
    t.add_column("Score", justify="right")
    t.add_column("Grade", justify="center")
    for col in ("cpu", "ram", "swap", "disco"):
        t.add_column(col, justify="right", style="warden.muted")
    for p in points[-8:]:
        t.add_row(_short_ts(p.ts),
                  Text(str(p.score), style=LEVEL_STYLE["ok" if p.score >= 80 else "warn" if p.score >= 60 else "fail"]),
                  Text(p.grade, style=GRADE_STYLE.get(p.grade, "warden.na")),
                  *[("—" if v is None else f"{v:.0f}") for v in (p.cpu, p.ram, p.swap, p.disk)])
    return _panel(Group(g, Text(""), t, sub), f"Histórico ({len(points)})")


def print_history(points: list[core_history.HistoryPoint]) -> None:
    console.print(history_renderable(points))


def print_info(si: system.SystemInfo) -> None:
    g = Table.grid(padding=(0, 2))
    g.add_column(style="warden.muted", justify="right")
    g.add_column(style="warden.value")
    rows = [
        ("SO", si.os), ("Distro", si.distro or "—"), ("Kernel", si.kernel),
        ("Host", si.hostname), ("Arquitectura", si.arch), ("Python", si.python),
        ("Uptime", human_duration(si.uptime)),
    ]
    for k, v in rows:
        g.add_row(k, str(v))
    console.print(_panel(g, "Información del sistema"))


def health_md(snap: system.HealthSnapshot) -> str:
    si, c, m = snap.system, snap.cpu, snap.mem
    L = [
        f"# WARDEN_ — Health · {si.hostname}", "",
        f"- **SO:** {si.distro or si.os}",
        f"- **Kernel:** {si.kernel}",
        f"- **Uptime:** {human_duration(si.uptime)}",
        f"- **Privilegios:** {'root' if snap.is_root else 'usuario'}", "",
        "## CPU", "",
        f"- Uso: {_fmt_pct(c.percent)} · Cores: {c.cores_physical}/{c.cores_logical}"
        + (f" · Load: {c.load_avg[0]:.2f} {c.load_avg[1]:.2f} {c.load_avg[2]:.2f}" if c.load_avg else ""),
        "", "## Memoria", "",
        f"- RAM: {human_bytes(m.used)} / {human_bytes(m.total)} ({_fmt_pct(m.percent)})",
        f"- Swap: {human_bytes(m.swap_used)} / {human_bytes(m.swap_total)} ({_fmt_pct(m.swap_percent)})",
        "", "## Discos", "", "| Montaje | FS | Tamaño | Uso |", "|---|---|---|---|",
    ]
    for d in snap.disks:
        L.append(f"| {d.mountpoint} | {d.fstype} | {human_bytes(d.total)} | {_fmt_pct(d.percent)} |")
    L += ["", "## Top procesos", "", "| PID | Proceso | CPU% | MEM% |", "|---|---|---|---|"]
    for p in snap.procs:
        L.append(f"| {p.pid} | {p.name} | {p.cpu:.1f} | {p.mem:.1f} |")
    return "\n".join(L)
