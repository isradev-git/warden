"""Consola rich + tema Glitchbane.

Paleta: magenta neón #ff3d94 (marca) + cian #3dffd1 (acento), estados en neón.
#ff3d941f (relleno translúcido) no lo soporta el terminal -> se aproxima con
fondos oscuros teñidos de magenta.
"""
from rich.console import Console
from rich.theme import Theme

GLITCHBANE = Theme(
    {
        "warden.brand": "bold #ff3d94",
        "warden.accent": "#ff3d94",
        "warden.accent2": "#3dffd1",
        "warden.header": "bold #ff3d94",
        "warden.value": "bold #3dffd1",
        "warden.muted": "#6b6b7b",
        "warden.ok": "#3dff94",
        "warden.warn": "#ffcc3d",
        "warden.fail": "#ff3d3d",
        "warden.na": "#6b6b7b",
    }
)

# Badges (fondo sólido): el terminal no hace alpha, usamos colores planos.
BG_PANEL = "on #15090f"

console = Console(theme=GLITCHBANE)
