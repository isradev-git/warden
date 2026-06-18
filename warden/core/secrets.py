"""Escaneo defensivo de fugas de secretos en el host local.

Busca patrones de tokens/claves en variables de entorno, history de shell y
ficheros sensibles legibles por otros. NUNCA imprime el secreto: solo ubicación,
tipo y un valor enmascarado. Heurístico de alta señal, no un gitleaks completo.
ponytail: pocas regex de alta señal + lista fija de ficheros; para cobertura
exhaustiva -> gitleaks/trufflehog.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass

from warden.core.security import FAIL, WARN, _mode, _read

# --- patrones de alta señal --------------------------------------------------
_PATTERNS = [
    ("AWS access key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("GitHub token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}")),
    ("Slack token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("Private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("Bearer token", re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]{20,}")),
    ("Asignación sospechosa", re.compile(
        r"(?i)(?:api[_-]?key|secret|token|passwd|password|credential)"
        r"['\"]?\s*[=:]\s*['\"]?([A-Za-z0-9/+_\-]{12,})")),
]
_ENV_KEY_RE = re.compile(r"(?i)(?:^|_)(key|token|secret|passwd|password|credential|api)")

_HISTORY = ["~/.bash_history", "~/.zsh_history", "~/.history",
            "~/.local/share/fish/fish_history"]
_SENSITIVE = ["~/.netrc", "~/.aws/credentials", "~/.git-credentials", "~/.pgpass",
              "~/.env", "~/.docker/config.json", "~/.npmrc", "~/.pypirc",
              "~/.ssh/id_rsa", "~/.ssh/id_ed25519", "~/.ssh/id_ecdsa", "~/.ssh/id_dsa"]


@dataclass
class Finding:
    source: str    # env | history | file
    location: str  # var / fichero:linea / ruta
    kind: str
    masked: str
    severity: str  # warn | fail


@dataclass
class SecretScan:
    findings: list[Finding]
    counts: dict   # {warn, fail}
    scanned: dict  # {env_vars, history_files, sensitive_files}


def _mask(s: str) -> str:
    s = s.strip().strip("'\"")
    if len(s) <= 6:
        return "***"
    return f"{s[:2]}…{s[-2:]} ({len(s)} car)"


def _match_line(line: str) -> tuple[str, str] | None:
    for kind, rx in _PATTERNS:
        m = rx.search(line)
        if m:
            val = m.group(m.lastindex) if m.lastindex else m.group(0)
            return kind, _mask(val)
    return None


def _scan_env() -> list[Finding]:
    out = []
    for k, v in os.environ.items():
        if v and len(v) >= 8 and _ENV_KEY_RE.search(k):
            out.append(Finding("env", k, "variable de entorno sospechosa", _mask(v), WARN))
    return out


def _scan_history() -> list[Finding]:
    out = []
    for raw in _HISTORY:
        txt = _read(os.path.expanduser(raw))
        if not txt:
            continue
        base = os.path.basename(raw)
        for i, line in enumerate(txt.splitlines(), 1):
            hit = _match_line(line)
            if hit:
                out.append(Finding("history", f"{base}:{i}", hit[0], hit[1], WARN))
    return out


def _scan_files() -> list[Finding]:
    out = []
    for raw in _SENSITIVE:
        path = os.path.expanduser(raw)
        if not os.path.exists(path):
            continue
        mode = _mode(path)
        if mode is not None and mode & 0o077:  # legible/escribible por grupo u otros
            out.append(Finding("file", path, f"permisos {oct(mode)} (accesible por otros)",
                               "—", FAIL))
    return out


def scan() -> SecretScan:
    findings = _scan_env() + _scan_history() + _scan_files()
    counts = {WARN: sum(f.severity == WARN for f in findings),
              FAIL: sum(f.severity == FAIL for f in findings)}
    scanned = {
        "env_vars": len(os.environ),
        "history_files": sum(os.path.exists(os.path.expanduser(p)) for p in _HISTORY),
        "sensitive_files": sum(os.path.exists(os.path.expanduser(p)) for p in _SENSITIVE),
    }
    return SecretScan(findings, counts, scanned)


def _demo() -> None:
    assert _mask("abcd") == "***"
    assert _mask("AKIAEXAMPLE1234567890") .startswith("AK")
    assert _match_line("export AWS_KEY=AKIAIOSFODNN7EXAMPLE")[0] == "AWS access key"
    assert _match_line("ls -la") is None
    sc = scan()
    assert set(sc.counts) == {WARN, FAIL}
    assert all(f.severity in (WARN, FAIL) for f in sc.findings)
    print(f"secrets._demo ok ({len(sc.findings)} findings)")


if __name__ == "__main__":
    _demo()
