"""
Modo batch (Fase 2).

Permite apuntar VeilScan a una CARPETA en vez de a archivos sueltos. Recorre el
directorio (opcionalmente de forma recursiva), junta todos los documentos de
formato soportado y los escanea en lote, entregando un resumen agregado:
cuantos archivos hay en cada nivel de riesgo y cuales son los sospechosos.

Es lo que separa una herramienta de juguete (un archivo a la vez) de una que se
puede enchufar a un flujo real (procesar cientos de documentos de una pasada).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from veilscan.core import scanner
from veilscan.core.models import ScanResult


def expand_paths(paths: list[str], recursive: bool = False) -> list[str]:
    """Convierte una mezcla de archivos y carpetas en una lista plana de archivos
    con formato soportado, sin duplicados y en orden estable."""
    supported = tuple(scanner.supported_extensions())
    found: list[str] = []
    seen: set[str] = set()

    def _add(fp: str) -> None:
        real = os.path.abspath(fp)
        if real not in seen and os.path.splitext(fp)[1].lower() in supported:
            seen.add(real)
            found.append(fp)

    for p in paths:
        if os.path.isdir(p):
            if recursive:
                for root, _dirs, files in os.walk(p):
                    for name in sorted(files):
                        _add(os.path.join(root, name))
            else:
                for name in sorted(os.listdir(p)):
                    full = os.path.join(p, name)
                    if os.path.isfile(full):
                        _add(full)
        else:
            # archivo explicito: se respeta aunque la extension no este soportada
            # (el scanner devolvera un error claro), salvo que venga de un glob vacio
            found.append(p) if os.path.abspath(p) not in seen else None
            seen.add(os.path.abspath(p))

    return found


@dataclass
class BatchSummary:
    total: int = 0
    by_label: dict = field(default_factory=dict)        # {"CRITICAL": n, ...}
    risky: list[tuple] = field(default_factory=list)    # [(path, label, score), ...]
    errors: list[tuple] = field(default_factory=list)   # [(path, error), ...]

    def to_dict(self) -> dict:
        return {
            "total": self.total,
            "by_label": self.by_label,
            "risky": [{"path": p, "label": l, "score": s} for p, l, s in self.risky],
            "errors": [{"path": p, "error": e} for p, e in self.errors],
        }


def summarize(results: list[ScanResult]) -> BatchSummary:
    s = BatchSummary(total=len(results))
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "CLEAN": 4}
    for r in results:
        if r.error:
            s.errors.append((r.path, r.error))
            s.by_label["ERROR"] = s.by_label.get("ERROR", 0) + 1
            continue
        label = r.risk_label
        s.by_label[label] = s.by_label.get(label, 0) + 1
        if label != "CLEAN":
            s.risky.append((r.path, label, r.risk_score))
    # ordena los riesgosos de mayor a menor gravedad
    s.risky.sort(key=lambda t: (order.get(t[1], 9), -t[2]))
    return s
