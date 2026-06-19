# WARDEN_ — Plan técnico

> Auditor de host y panel de sistemas para terminal. Linux primero.

|  |  |
|---|---|
| **Proyecto** | `WARDEN_` |
| **Desarrollador** | Israel Zamora Tejero |
| **Organización** | `>IZ::` |
| **Fecha** | 18 de junio de 2026 |
| **Versión** | 0.2 (plan) |
| **Estado** | Planificación — pendiente de implementación |

---

## 0. Cambios v0.2 (decisiones de alcance)

Recorte deliberado para tener algo útil antes y mantener menos código:

- **Linux primero.** macOS/Windows degradan a `N/A`; soporte real → fase 4.
- **Herramienta personal.** Sin reporte HTML-cliente. Solo JSON + Markdown.
- **Scripts solo generan.** No ejecutan, no programan (cron/schtasks). Quita el 80 % del riesgo.
- **Audit envuelve Lynis** donde exista; checks propios solo para lo barato/portable.
- **Sin `config.py` por ahora.** Defaults en código; config TOML cuando algo de verdad varíe.

Todo lo recortado sigue vivo como opción en la **Fase 4**.

---

## 1. Objetivo

Herramienta de terminal **todo-en-uno para técnico de sistemas**, centrada en el **host Linux local**. CLI con subcomandos + `rich`. Núcleo de lógica **independiente del front-end**. Complementa a LuaNetSentinel (que cubre la red). Multiplataforma es objetivo futuro, no requisito v1.

---

## 2. Decisiones tomadas

- **Interacción:** CLI (`typer`) + `rich`. Cada función es un subcomando scriptable y cron-able (por el propio usuario).
- **Seguridad:** auditoría del host envolviendo **Lynis** + checks propios ligeros. Sin CVEs, sin red.
- **Privilegios:** detecta si es root; si no, avisa de qué checks quedan parciales y sigue con lo que puede. Sin elevación automática.
- **Scripts:** **genera y muestra** scripts bash (backup/cleanup/update). El usuario decide si los corre. WARDEN no ejecuta ni programa.
- **Reporting:** terminal + export JSON (máquina) + Markdown (vault/interno).

---

## 3. Supuestos

> Marcados como `[Supuesto]`: ajustables.

- **Nombre / codename:** `WARDEN_`. Comando `warden`. Renombrable.
- **Instalación:** paquete Python instalable con `pipx` (aislado, por-usuario), desde repo Git. `pyinstaller` para binario único → fase 4.
- **Python 3.11+.**
- **Configuración:** defaults en código. `~/.config/warden/config.toml` solo si/cuando haga falta.
- **Diagnóstico:** set completo (CPU, RAM, swap, temperaturas, discos, red, top procesos, uptime, info SO) — todo gratis vía `psutil` en Linux.

---

## 4. Arquitectura

```
warden/
  pyproject.toml
  warden/
    __main__.py          # python -m warden
    cli.py               # typer: subcomandos
    console.py           # Console rich + tema Glitchbane
    platform_utils.py    # detección SO, check root, ejecución segura de comandos
    core/
      system.py          # collectors psutil -> dataclasses
      security.py        # envuelve lynis + checks propios -> CheckResult (OK/WARN/FAIL/NA)
      scripts.py         # genera scripts bash (cuerpo estático + cabecera) -> texto (NO ejecuta)
      report.py          # dataclasses -> JSON / Markdown
    render.py            # render rich de los datos (tablas, dashboard)
    templates/           # *.sh.j2
```

**Regla de oro:** `core/` devuelve **datos estructurados** sin saber nada de `rich`/`typer`. Testeable, y deja la puerta abierta a una TUI Textual sin tocar lógica.

Notas de diseño:
- `platform_utils.py`, no `platform.py` (colisiona con el módulo stdlib `platform`).
- `render.py` es un fichero, no un paquete `render/`. Un solo sitio para tablas.
- Sin `config.py` hasta que un valor de verdad varíe por-usuario.

---

## 5. Superficie CLI

| Comando | Descripción |
|---|---|
| `warden` | Sin args = dashboard: resumen health + audit en una pantalla. |
| `warden health [--watch] [--json\|--md]` | Diagnóstico del sistema en vivo. |
| `warden audit [--json\|--md] [--fail-on warn\|fail]` | Auditoría de seguridad + hardening score 0-100. `--fail-on` la hace usable en CI. |
| `warden expose [--json]` | OSINT sobre el propio host: IP pública, geoloc, reverse DNS, puertos en iface pública. |
| `warden scan-secrets [--json]` | Busca tokens/keys en env, history y ficheros world-readable. |
| `warden script <backup\|cleanup\|update> [--src --dest] [-o FILE]` | **Genera y muestra** un script. `-o` lo escribe a fichero. No lo ejecuta. |
| `warden cve [--json] [--details N]` | CVEs conocidas de los paquetes instalados vía OSV.dev. |
| `warden record` | Registra un snapshot (score + vitales) en el histórico. Cron-able. |
| `warden history [--json] [--limit N]` | Tendencias del histórico (score y vitales en el tiempo). |
| `warden report [--md\|--json]` | Informe combinado health + audit. |
| `warden info` | Información del sistema / SO. |

**Códigos de salida** (para CI / cron del usuario): `0` todo OK · `1` hubo WARN · `2` hubo FAIL. `--fail-on` decide el umbral.

---

## 6. Pilares en detalle

### 6.1. Diagnóstico

`psutil` para CPU (global / por-core / freq / load), RAM + swap, discos (uso, descartando pseudo-fs), red (I/O + interfaces), top procesos por CPU/RAM, uptime, info SO. Temperaturas vía `psutil.sensors_temperatures()`.

Si un dato no existe (sin sensor, sin permiso) → `N/A`, nunca crash.

### 6.2. Seguridad

`security.py` produce una lista de `CheckResult` (estado `OK / WARN / FAIL / N-A` + recomendación), de dos fuentes:

1. **Lynis (híbrido):** Lynis está pensado para correr por cron y dejar su report en `/var/log/lynis-report.dat`. WARDEN **auto-parsea ese report si existe** (hardening index, warnings, suggestions → `CheckResult`, con antigüedad; report >30 d degrada un OK a WARN). Sin esperas. `--lynis` **fuerza un run fresco** (`lynis audit system --quiet`, 1-3 min, mejor con root) antes de parsear. Maduro, mantenido, evita falsos positivos propios.
2. **Checks propios ligeros** (siempre, no dependen de Lynis):
   - **Red / firewall:** puertos a la escucha y binds a `0.0.0.0`; estado de `ufw` / `firewalld`.
   - **SSH:** `PermitRootLogin`, `PasswordAuthentication`, puerto (parseo de `sshd_config`).
   - **Permisos:** ficheros sensibles (`passwd` / `shadow` / `sudoers`, `~/.ssh`), world-writable en `$PATH`, SUID/SGID inesperados.
   - **Usuarios / auth:** UID 0 duplicados, cuentas sin password.
   - **Actualizaciones de seguridad pendientes:** `apt` / `dnf`.
   - **Cifrado de disco:** LUKS presente.

Si Lynis no está → solo checks propios, y se indica en el report que la cobertura es parcial.

### 6.3. Scripts (solo generación)

Scripts bash con cuerpo estático + cabecera de variables inyectada (sin motor de plantillas: Jinja2 sería sobreingeniería para tres scripts, y las llaves de bash chocan con `str.format`; se reconsidera si crecen). Flujo: **generar → mostrar en pantalla** (resaltado). Con `-o` se escribe a fichero. **WARDEN no ejecuta ni programa nada** — el usuario revisa y corre lo que quiera. El `update`/`cleanup` detectan el gestor de paquetes en tiempo de ejecución (bash), no al generar.

Plantillas iniciales: `backup` (rsync/tar src→dest), `cleanup` (cachés, logs viejos, paquetes huérfanos), `update` (gestor de paquetes detectado).

### 6.4. Reporting

Un mismo dataset serializado a:
- **JSON** — máquina / automatización. Incluye `warden_version` y `schema_version` para estabilidad ante cambios.
- **Markdown** — vault / uso interno.

---

## 7. Casos límite y riesgos

Tras los recortes, el riesgo grande (ejecutar/programar) desaparece. Queda:

- Temperaturas inexistentes según hardware/permisos → degradación a `N/A`.
- `net_connections` puede lanzar `AccessDenied` sin root → capturar, marcar parcial.
- Sin root: varios checks quedan incompletos → reportarlo claro, no fingir cobertura total.
- Parsing de `lynis-report.dat` y de gestores de paquetes varía por distro → tolerar formato ausente/cambiado, degradar a `N/A`.
- Scripts generados tocan el sistema **cuando el usuario los corra** → cabecera de aviso + comentarios + `set -euo pipefail` en las plantillas.
- Auditoría: recomendaciones, no verdades absolutas (evitar falsos positivos agresivos).

---

## 8. Criterios de calidad

- No revienta: lo no aplicable → `N/A` claro, nunca traceback.
- Salida JSON estable y versionada, parseable para automatización / CI.
- Códigos de salida coherentes (`0/1/2`).
- Estado de privilegios siempre explícito en la salida.
- `core/` sin dependencia de `rich`/`typer` (testeable de forma aislada, con `psutil` mockeado).

---

## 9. Fases de implementación

| Fase | Contenido |
|---|---|
| **Fase 0** ✅ | Esqueleto del paquete + CLI base + tema Glitchbane + `health` / `info` (Linux) + detección de root + `--json`/`--md` + README + SVGs. *Hecho y verificado.* |
| **Fase 1** ✅ | `security.py`: checks propios ligeros + wrapper de Lynis (`--lynis`) + comando `audit` + códigos de salida `0/1/2` + `--fail-on` + **hardening score 0-100 + grade A-F**. *Hecho y verificado.* |
| **Fase 2** ✅ | `core/report.py` (combina health + audit) + comando `report` (JSON/MD versionado) + `warden` sin-args = dashboard de resumen (score + vitales + incidencias). *Hecho y verificado.* |
| **Fase 3** ✅ | `scripts.py`: generación de backup/cleanup/update (solo genera, no ejecuta). **OSINT:** `expose` (IP pública + geoloc + reverse DNS + puertos en iface pública) + `scan-secrets` (env, history, ficheros world-readable). *Hecho y verificado.* |
| **Fase 4** *(opcional, lo recortado)* | **CVE de paquetes (OSV.dev)** ✅ — `cve` enumera paquetes (dpkg/rpm/pacman) y los consulta en batch contra api.osv.dev. **Histórico/tendencias** ✅ — `record` añade un snapshot (JSONL en `XDG_DATA_HOME`), `history` muestra sparklines de score y vitales; el dashboard auto-registra. *Pendiente:* 2.º SO (macOS/Windows), ejecución/programación de scripts, binario `pyinstaller`, TUI Textual, config TOML. |

---

## 10. Stack

**Base:** `python>=3.11`, `psutil`, `rich`, `typer`, `distro`. OSINT vía `urllib` (stdlib). Scripts sin `jinja2` (cuerpo estático).

Nada más por ahora. `jinja2` (si los scripts se complican), `tomllib` (config), `wmi`/`pywin32` (Windows), `croniter` (cron) → solo cuando hagan falta.

---

<div align="center">

`>IZ::` · Israel Zamora Tejero · Glitchbane

</div>
