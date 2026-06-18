"""Generación (solo) de scripts bash. WARDEN nunca los ejecuta ni programa.

Sin motor de plantillas: el cuerpo bash es una constante estática y solo se
inyecta una pequeña cabecera con variables. Así las llaves de bash (${VAR},
brace-expansion {a,b}) no chocan con ningún str.format / f-string.
ponytail: si los scripts crecen o se parametrizan de verdad -> Jinja2 + templates/.
"""
from __future__ import annotations

from dataclasses import dataclass

NAMES = ("backup", "cleanup", "update")


@dataclass
class GeneratedScript:
    name: str
    filename: str
    content: str


_BANNER = (
    "#!/usr/bin/env bash\n"
    "#\n"
    "# Generado por WARDEN_  ·  >IZ::\n"
    "# REVISA este script antes de ejecutarlo. WARDEN genera, NO ejecuta.\n"
    "#\n"
    "set -euo pipefail\n"
)

_BACKUP = """
# Backup de SRC a DEST: espejo con rsync (si está) + tarball comprimido fechado.
TS="$(date +%Y%m%d-%H%M%S)"
ARCHIVE="$DEST/backup-$TS.tar.gz"
mkdir -p "$DEST"
echo "Backup: $SRC -> $ARCHIVE"

if command -v rsync >/dev/null 2>&1; then
  rsync -aAX --delete "$SRC"/ "$DEST/mirror"/
  echo "Espejo rsync actualizado en $DEST/mirror"
fi

tar -czf "$ARCHIVE" -C "$(dirname "$SRC")" "$(basename "$SRC")"
echo "Archivo creado: $ARCHIVE"
"""

_CLEANUP = """
# Limpieza: paquetes huérfanos, cachés de paquetes, logs de journald y temporales.
echo "== Limpieza del sistema =="

if command -v apt-get >/dev/null 2>&1; then
  sudo apt-get -y autoremove --purge
  sudo apt-get -y autoclean
elif command -v dnf >/dev/null 2>&1; then
  sudo dnf -y autoremove
  sudo dnf clean all
elif command -v pacman >/dev/null 2>&1; then
  orphans="$(pacman -Qtdq || true)"
  [ -n "$orphans" ] && sudo pacman -Rns --noconfirm $orphans
  sudo pacman -Scc --noconfirm
fi

if command -v journalctl >/dev/null 2>&1; then
  sudo journalctl --vacuum-size=200M
fi

rm -rf "${HOME:?}/.cache/thumbnails/"* 2>/dev/null || true
find /tmp -maxdepth 1 -type f -atime +7 -delete 2>/dev/null || true
echo "Limpieza terminada."
"""

_UPDATE = """
# Actualización del sistema con el gestor de paquetes detectado en tiempo de ejecución.
echo "== Actualización del sistema =="

if command -v apt-get >/dev/null 2>&1; then
  sudo apt-get update && sudo apt-get -y upgrade
elif command -v dnf >/dev/null 2>&1; then
  sudo dnf -y upgrade
elif command -v pacman >/dev/null 2>&1; then
  sudo pacman -Syu --noconfirm
elif command -v zypper >/dev/null 2>&1; then
  sudo zypper -n update
else
  echo "Gestor de paquetes no reconocido." >&2
  exit 1
fi
echo "Sistema actualizado."
"""

_BODIES = {"backup": _BACKUP, "cleanup": _CLEANUP, "update": _UPDATE}


def generate(name: str, src: str | None = None, dest: str | None = None) -> GeneratedScript:
    if name not in NAMES:
        raise ValueError(f"Script desconocido: {name!r}. Opciones: {', '.join(NAMES)}.")
    header = ""
    if name == "backup":
        # ${1:-...} permite override en tiempo de ejecución sin reeditar el script.
        header = (f'\nSRC="${{1:-{src or "/ruta/origen"}}}"\n'
                  f'DEST="${{2:-{dest or "/ruta/destino"}}}"\n')
    content = _BANNER + header + _BODIES[name]
    return GeneratedScript(name, f"warden-{name}.sh", content)


def _demo() -> None:
    for n in NAMES:
        g = generate(n, src="/home/u", dest="/backup")
        assert g.content.startswith("#!/usr/bin/env bash")
        assert "set -euo pipefail" in g.content
        assert g.filename == f"warden-{n}.sh"
    assert 'SRC="${1:-/home/u}"' in generate("backup", "/home/u", "/backup").content
    try:
        generate("nope")
        assert False, "debería lanzar"
    except ValueError:
        pass
    print("scripts._demo ok")


if __name__ == "__main__":
    _demo()
