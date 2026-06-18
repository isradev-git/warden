"""OSINT de auto-exposición: qué ve internet de este host.

IP pública + geoloc + reverse DNS (vía servicios externos) + puertos a la
escucha en 0.0.0.0/::. Sin red -> campos None / listas vacías, nunca revienta.
ponytail: urllib (stdlib) + un endpoint free sin clave (ip-api.com); no hace un
port-scan externo real (intrusivo, lento) -> "escuchando en todas las ifaces"
es exposición *potencial*, no alcanzabilidad confirmada.
"""
from __future__ import annotations

import json
import socket
import urllib.request
from dataclasses import dataclass, field

import psutil


@dataclass
class Exposure:
    public_ip: str | None
    reverse_dns: str | None
    geo: dict  # {country, regionName, city, isp, org} o {}
    listening: list[dict] = field(default_factory=list)  # [{port, proc}] en 0.0.0.0/::
    error: str | None = None


def _get(url: str, timeout: float = 4.0) -> str | None:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "warden"})
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 (urls fijos http/https)
            return r.read().decode("utf-8", "ignore")
    except Exception:
        return None


def _public_ip() -> str | None:
    return (_get("https://api.ipify.org") or "").strip() or None


def _geo(ip: str) -> dict:
    raw = _get(f"http://ip-api.com/json/{ip}"
               "?fields=status,country,regionName,city,isp,org,query")
    if not raw:
        return {}
    try:
        d = json.loads(raw)
        return d if d.get("status") == "success" else {}
    except Exception:
        return {}


def _rdns(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def _pname(pid: int | None) -> str:
    if not pid:
        return ""
    try:
        return psutil.Process(pid).name()
    except Exception:
        return ""


def _listening() -> list[dict]:
    try:
        conns = psutil.net_connections(kind="inet")
    except Exception:
        return []  # sin root no se enumeran todos los sockets
    seen: dict[int, str] = {}
    for c in conns:
        if c.status == psutil.CONN_LISTEN and c.laddr and c.laddr.ip in ("0.0.0.0", "::"):
            seen.setdefault(c.laddr.port, _pname(c.pid))
    return [{"port": p, "proc": seen[p]} for p in sorted(seen)]


def collect_exposure() -> Exposure:
    ip = _public_ip()
    listening = _listening()
    if not ip:
        return Exposure(None, None, {}, listening, error="Sin IP pública (¿sin red?).")
    return Exposure(ip, _rdns(ip), _geo(ip), listening)


def _demo() -> None:
    # offline-safe: no asume red, solo que no revienta y la forma es correcta.
    exp = collect_exposure()
    assert isinstance(exp.listening, list)
    assert exp.geo == {} or isinstance(exp.geo, dict)
    print("expose._demo ok", "(con red)" if exp.public_ip else "(sin red)")


if __name__ == "__main__":
    _demo()
