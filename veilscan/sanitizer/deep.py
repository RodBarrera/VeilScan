"""
Sanitizacion profunda de PDF (Fase 2).

La sanitizacion Fase 1 (`veilscan.sanitizer.pdf_sanitizer.sanitize_pdf`) es
segura pero superficial: borra metadatos y JavaScript sin tocar el CONTENIDO
visual de la pagina. No alcanza si el ataque esta en el propio texto: un run
casi blanco, una capa OCG apagada, o unicode invisible mezclado dentro de un
parrafo visible siguen ahi despues de la Fase 1 -- un LLM que reciba el PDF
"limpio" segun Fase 1 sigue leyendo la inyeccion igual.

`sanitize_pdf_deep()` hace 4 cosas, en este orden:

  1. Fase 1 (metadatos + JavaScript) -- se reutiliza tal cual, via pikepdf.
  2. Capas OCG ocultas -- no basta con que esten "apagadas" (siguen ahi para
     quien reactive la capa o para cualquier parser que ignore el flag de
     visibilidad). Se borra el bloque `/OC BDC ... EMC` del content stream de
     cada pagina para cada capa listada en /OCProperties/D/OFF, usando la API
     de content-stream de pikepdf (parse_content_stream/unparse_content_stream)
     en vez de manipular bytes crudos con regex, que es fragil ante streams
     con formato irregular.
  3. Runs de texto ocultos -- casi blanco, fuente diminuta, fuera de pagina, y
     texto en modo de render invisible (operador `3 Tr`, atribuido por span
     via el campo `alpha` que expone PyMuPDF -- ver
     `veilscan/extractors/pdf.py`). Se redactan con PyMuPDF: se borra el
     dibujo original en esa zona de la pagina, no solo se tapa visualmente.
     El texto realmente invisible (alpha=0) se redacta SIN caja de color
     encima (`fill=None`): como nunca se pinto nada, pintar con el color
     interno del span podria dejar una marca donde antes no habia ninguna.
  4. Unicode invisible DENTRO de texto por lo demas visible (zero-width, tag
     block, controles bidireccionales) -- el run se redacta y se reinserta ya
     normalizado, en la misma posicion/tamano/color, para no alterar como se
     ve la pagina a simple vista.

Al final se reescribe el PDF completo (`clean=True, garbage=4`): borrar
referencias no basta, hay que reconstruir el archivo para que los objetos ya
sin referencias no sigan viviendo en el archivo de salida.

Nota sobre el paso 3: en el caso raro de que el operador `3 Tr` este presente
en el stream pero ningun span se haya podido atribuir por alpha (fuente no
estandar, texto vacio, etc.), se agrega un aviso a las acciones devueltas en
vez de fallar en silencio -- igual que hace el extractor en ese mismo caso.
"""

from __future__ import annotations

import os
import re
import tempfile

import fitz  # PyMuPDF
import pikepdf

from veilscan.detectors import unicode_layer
from veilscan.sanitizer.pdf_sanitizer import sanitize_pdf as _sanitize_pdf_phase1

NEAR_WHITE_THRESHOLD = 230
TINY_FONT_PT = 2.0
OFF_PAGE_MARGIN = 2.0


def sanitize_pdf_deep(in_path: str, out_path: str) -> list[str]:
    """Aplica la sanitizacion profunda de 4 pasos y devuelve las acciones tomadas."""
    actions: list[str] = []

    with tempfile.TemporaryDirectory() as tmp:
        stage1 = os.path.join(tmp, "stage1.pdf")

        # Pasos 1 y 2: todo lo que se resuelve a nivel de estructura (pikepdf).
        actions.extend(_sanitize_pdf_phase1(in_path, stage1))
        actions.extend(_strip_hidden_ocg_layers(stage1))

        # Pasos 3 y 4: redaccion de runs ocultos + normalizacion Unicode +
        # reescritura final (PyMuPDF), directo sobre out_path.
        actions.extend(_redact_and_rewrite(stage1, out_path))

    if not actions:
        actions.append("Sin cambios aplicables (no se encontraron superficies limpiables).")
    return actions


# ---------------------------------------------------------------------- #
# Paso 2: eliminar capas OCG ocultas (contenido + definicion)
# ---------------------------------------------------------------------- #
def _strip_hidden_ocg_layers(path: str) -> list[str]:
    """Borra, pagina por pagina, los bloques `/OC BDC ... EMC` que referencian
    una capa listada en /OCProperties/D/OFF. Sobrescribe `path` in-place."""
    actions: list[str] = []
    try:
        pdf = pikepdf.open(path, allow_overwriting_input=True)
    except Exception:
        return actions

    try:
        root = pdf.Root
        if "/OCProperties" not in root:
            pdf.close()
            return actions
        d = root.OCProperties.get("/D", {})
        off = list(d.get("/OFF", []))
        if not off:
            pdf.close()
            return actions

        hidden_ids = {ocg.objgen for ocg in off}
        pages_touched = 0

        for page in pdf.pages:
            resources = page.get("/Resources", None)
            if resources is None or "/Properties" not in resources:
                continue
            props = resources.Properties
            hidden_keys = {
                str(key) for key, val in props.items()
                if hasattr(val, "objgen") and val.objgen in hidden_ids
            }
            if not hidden_keys:
                continue

            try:
                instructions = pikepdf.parse_content_stream(page)
            except Exception:
                continue

            kept = []
            depth = 0  # profundidad de bloques BDC ocultos anidados a saltar
            removed_any = False
            for instr in instructions:
                op = str(instr.operator)
                if op == "BDC" and len(instr.operands) >= 2 \
                        and str(instr.operands[0]) == "/OC" \
                        and str(instr.operands[1]) in hidden_keys:
                    depth += 1
                    removed_any = True
                    continue
                if depth > 0:
                    if op == "BDC":
                        depth += 1  # bloque anidado dentro del que ya saltamos
                    elif op == "EMC":
                        depth -= 1
                    continue  # se descarta todo lo que esta dentro del bloque oculto
                kept.append(instr)

            if not removed_any:
                continue

            new_bytes = pikepdf.unparse_content_stream(kept)
            page.Contents = pdf.make_stream(new_bytes)
            pages_touched += 1

        if pages_touched:
            # Ya no queda contenido que referencie estas capas: se eliminan
            # tambien de la definicion (/OFF, /Order, /OCGs) para que el
            # visor ni siquiera las liste como una capa "apagada" existente.
            _remove_ocg_definitions(root, off)
            pdf.save(path)
            actions.append(
                f"{len(off)} capa(s) OCG oculta(s) eliminadas (contenido en "
                f"{pages_touched} pagina(s) + definicion de la capa)")
    except Exception:
        pass
    finally:
        pdf.close()

    return actions


def _remove_ocg_definitions(root, off_ocgs) -> None:
    """Quita las OCG ya vaciadas de /OCProperties: /OFF, /Order y /OCGs."""
    try:
        off_ids = {ocg.objgen for ocg in off_ocgs}
        ocprops = root.OCProperties
        d = ocprops.get("/D", {})
        if "/OFF" in d:
            d.OFF = pikepdf.Array([o for o in d.OFF if o.objgen not in off_ids])
        if "/Order" in d:
            d.Order = pikepdf.Array([o for o in d.Order if getattr(o, "objgen", None) not in off_ids])
        if "/OCGs" in ocprops:
            ocprops.OCGs = pikepdf.Array([o for o in ocprops.OCGs if o.objgen not in off_ids])
    except Exception:
        pass


# ---------------------------------------------------------------------- #
# Pasos 3 y 4: redaccion de runs ocultos + normalizacion Unicode + reescritura
# ---------------------------------------------------------------------- #
def _redact_and_rewrite(in_path: str, out_path: str) -> list[str]:
    actions: list[str] = []
    doc = fitz.open(in_path)

    hidden_redactions = 0
    unicode_redactions = 0
    unattributed_pages = 0

    for page in doc:
        rect = page.rect
        raw = page.get_text("rawdict")
        pending_reinsert = []  # (point, text, size, color) a reinsertar tras aplicar redacciones
        attributed_invisible_render = False

        for block in raw.get("blocks", []):
            for line in block.get("lines", []):
                for span in line.get("spans", []):
                    text = "".join(c.get("c", "") for c in span.get("chars", []))
                    if not text.strip():
                        continue
                    size = float(span.get("size", 0.0))
                    color_int = int(span.get("color", 0))
                    alpha = int(span.get("alpha", 255))
                    bbox = fitz.Rect(span.get("bbox", (0, 0, 0, 0)))
                    color_rgb = tuple(c / 255 for c in _int_to_rgb(color_int))

                    if alpha == 0:
                        # Texto realmente invisible (nunca se pinto nada en pantalla):
                        # fill=None borra el contenido sin dibujar una caja de color
                        # encima. Usar el color propio del span aqui seria un error --
                        # como nunca se renderizo, ese valor puede ser cualquier cosa
                        # (p.ej. negro) y dejaria una marca visible donde antes no
                        # habia ninguna.
                        page.add_redact_annot(bbox, fill=None)
                        hidden_redactions += 1
                        attributed_invisible_render = True
                        continue
                    if _is_near_white(color_int) or (size and size < TINY_FONT_PT) or _is_off_page(bbox, rect):
                        page.add_redact_annot(bbox, fill=color_rgb)
                        hidden_redactions += 1
                        continue

                    normalized = unicode_layer.normalize(text)
                    if normalized != text and normalized.strip():
                        page.add_redact_annot(bbox, fill=(1, 1, 1))
                        pending_reinsert.append((bbox, normalized, size, color_rgb))
                        unicode_redactions += 1

        # Red de seguridad: si '3 Tr' esta en el stream de la pagina pero no se
        # atribuyo ningun span por alpha, no se puede redactar con precision.
        if not attributed_invisible_render:
            try:
                raw_content = page.read_contents().decode("latin-1", errors="ignore")
                if re.search(r"(^|\s)3\s+Tr(\s|$)", raw_content):
                    unattributed_pages += 1
            except Exception:
                pass

        if page.first_annot is not None:
            page.apply_redactions()

        for bbox, normalized, size, color_rgb in pending_reinsert:
            try:
                page.insert_text(
                    (bbox.x0, bbox.y1 - 1.5),  # linea base aprox. igual que el run original
                    normalized, fontsize=size or 10, fontname="helv", color=color_rgb,
                )
            except Exception:
                pass  # si la reinsercion falla, el texto queda redactado (vacio) por seguridad

    if hidden_redactions:
        actions.append(f"{hidden_redactions} run(s) de texto oculto (casi blanco / fuente "
                        "diminuta / fuera de pagina / modo de render invisible) eliminados del contenido")
    if unicode_redactions:
        actions.append(f"{unicode_redactions} run(s) con Unicode invisible (zero-width / "
                        "bidi / tag block) reescritos ya normalizados")
    if unattributed_pages:
        actions.append(
            f"AVISO: {unattributed_pages} pagina(s) tienen el operador '3 Tr' en el stream "
            "pero no se pudo atribuir a un span especifico (caso raro) -- revisar a mano.")

    # Reescritura final: no basta con guardar, hay que limpiar objetos huerfanos
    # que quedaron sin referencias tras las redacciones y el paso OCG.
    doc.save(out_path, garbage=4, deflate=True, clean=True)
    doc.close()
    return actions


def _int_to_rgb(color: int) -> tuple[int, int, int]:
    return (color >> 16) & 0xFF, (color >> 8) & 0xFF, color & 0xFF


def _is_near_white(color: int) -> bool:
    r, g, b = _int_to_rgb(color)
    return r >= NEAR_WHITE_THRESHOLD and g >= NEAR_WHITE_THRESHOLD and b >= NEAR_WHITE_THRESHOLD


def _is_off_page(bbox: "fitz.Rect", rect: "fitz.Rect") -> bool:
    return (
        bbox.x1 < rect.x0 - OFF_PAGE_MARGIN
        or bbox.x0 > rect.x1 + OFF_PAGE_MARGIN
        or bbox.y1 < rect.y0 - OFF_PAGE_MARGIN
        or bbox.y0 > rect.y1 + OFF_PAGE_MARGIN
        or bbox.x0 < -OFF_PAGE_MARGIN
        or bbox.y0 < -OFF_PAGE_MARGIN
    )
