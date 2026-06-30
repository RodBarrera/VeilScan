"""
Sanitizador (Fase 1, basico).

En Fase 1 neutralizamos las superficies que se pueden limpiar de forma segura sin
re-renderizar el documento:
  - metadatos (/Info y XMP)
  - JavaScript embebido y OpenAction

La neutralizacion profunda (eliminar runs ocultos, texto casi blanco, capas OCG,
caracteres Unicode invisibles, etc.) se aborda en Fase 2, donde se reescribe el
contenido. Aqui devolvemos una copia "mas limpia" y reportamos que se hizo.
"""

from __future__ import annotations

import pikepdf


def sanitize_pdf(in_path: str, out_path: str) -> list[str]:
    """Devuelve la lista de acciones aplicadas."""
    actions: list[str] = []
    pdf = pikepdf.open(in_path)

    # Metadatos /Info
    try:
        if pdf.docinfo is not None and len(pdf.docinfo) > 0:
            for key in list(pdf.docinfo.keys()):
                del pdf.docinfo[key]
            actions.append("Metadatos /Info eliminados")
    except Exception:
        pass

    # Metadatos XMP
    try:
        with pdf.open_metadata() as xmp:
            keys = list(xmp.keys())
            for k in keys:
                del xmp[k]
        if keys:
            actions.append(f"{len(keys)} campos XMP eliminados")
    except Exception:
        pass

    # JavaScript / OpenAction
    try:
        root = pdf.Root
        if "/OpenAction" in root:
            del root.OpenAction
            actions.append("OpenAction eliminado")
        names = root.get("/Names", None)
        if names is not None and "/JavaScript" in names:
            del names.JavaScript
            actions.append("Names/JavaScript eliminado")
    except Exception:
        pass

    pdf.save(out_path)
    pdf.close()
    if not actions:
        actions.append("Sin cambios aplicables (no se encontraron superficies limpiables en Fase 1)")
    return actions
