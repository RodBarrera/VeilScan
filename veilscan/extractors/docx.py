"""
Extractor de DOCX (Fase 1).

Decision de diseno clave: NO usamos python-docx para la deteccion. Las librerias
de alto nivel ignoran justamente el contenido oculto (texto con w:vanish, runs en
blanco, etc.). Vamos directo al XML del paquete OOXML (el .docx es un ZIP).

Superficies cubiertas:
  - Texto con w:vanish (oculto)                 -> VANISH
  - Texto en color casi blanco (w:color)        -> NEAR_WHITE
  - Fuente diminuta (w:sz, en medios puntos)     -> TINY_FONT
  - Comentarios (comments.xml)                   -> COMMENT
  - Metadatos (core/app/custom .xml)             -> METADATA
  - Texto alternativo de imagenes (descr=)       -> ALT_TEXT
  - Encabezados / pies de pagina (visibles)      -> location header/footer
"""

from __future__ import annotations

import zipfile

from lxml import etree

from veilscan.core.models import HideReason, TextSpan
from veilscan.extractors.base import BaseExtractor, ExtractionResult

W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
NS = {
    "w": W,
    "wp": "http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing",
    "a": "http://schemas.openxmlformats.org/drawingml/2006/main",
    "dc": "http://purl.org/dc/elements/1.1/",
    "cp": "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
}

TINY_HALF_POINTS = 4  # w:sz esta en medios puntos -> 4 = 2pt
NEAR_WHITE_THRESHOLD = 230


def _hex_is_near_white(val: str) -> bool:
    val = val.strip().lstrip("#").upper()
    if len(val) != 6:
        return False
    try:
        r, g, b = int(val[0:2], 16), int(val[2:4], 16), int(val[4:6], 16)
    except ValueError:
        return False
    return r >= NEAR_WHITE_THRESHOLD and g >= NEAR_WHITE_THRESHOLD and b >= NEAR_WHITE_THRESHOLD


class DocxExtractor(BaseExtractor):
    extensions = (".docx",)

    def extract(self, path: str) -> ExtractionResult:
        result = ExtractionResult()
        with zipfile.ZipFile(path) as z:
            names = set(z.namelist())

            if "word/document.xml" in names:
                self._parse_body(z.read("word/document.xml"), "document body", result)

            # Encabezados y pies (visibles pero faciles de pasar por alto)
            for name in sorted(names):
                if name.startswith("word/header") and name.endswith(".xml"):
                    self._parse_body(z.read(name), "header", result, force_visible=True)
                elif name.startswith("word/footer") and name.endswith(".xml"):
                    self._parse_body(z.read(name), "footer", result, force_visible=True)

            if "word/comments.xml" in names:
                self._parse_comments(z.read("word/comments.xml"), result)

            self._parse_metadata(z, names, result)

        return result

    # ------------------------------------------------------------------ #
    def _parse_body(self, xml: bytes, location: str, result: ExtractionResult,
                    force_visible: bool = False) -> None:
        root = etree.fromstring(xml)

        # Texto alternativo de imagenes (atributo descr en docPr)
        for docpr in root.iter(f"{{{NS['wp']}}}docPr"):
            descr = docpr.get("descr")
            if descr and descr.strip():
                result.spans.append(
                    TextSpan(text=descr, visible=False,
                             location=f"{location} (image alt-text)",
                             reason=HideReason.ALT_TEXT)
                )

        # Cada run <w:r> con sus propiedades <w:rPr>
        for run in root.iter(f"{{{W}}}r"):
            text = "".join(t.text or "" for t in run.iter(f"{{{W}}}t"))
            if not text.strip():
                continue

            reason = None
            font_size = None
            color_hex = None
            rpr = run.find(f"{{{W}}}rPr")
            if rpr is not None and not force_visible:
                # w:vanish -> texto oculto
                if rpr.find(f"{{{W}}}vanish") is not None:
                    reason = HideReason.VANISH
                # w:color
                color_el = rpr.find(f"{{{W}}}color")
                if color_el is not None:
                    val = color_el.get(f"{{{W}}}val", "")
                    color_hex = f"#{val.upper()}" if val and val != "auto" else None
                    if reason is None and _hex_is_near_white(val):
                        reason = HideReason.NEAR_WHITE
                # w:sz (medios puntos)
                sz_el = rpr.find(f"{{{W}}}sz")
                if sz_el is not None:
                    try:
                        half = int(sz_el.get(f"{{{W}}}val", "0"))
                        font_size = half / 2.0
                        if reason is None and 0 < half < TINY_HALF_POINTS:
                            reason = HideReason.TINY_FONT
                    except ValueError:
                        pass

            result.spans.append(
                TextSpan(
                    text=text,
                    visible=reason is None,
                    location=location,
                    reason=reason,
                    font_size=font_size,
                    color=color_hex,
                )
            )

    def _parse_comments(self, xml: bytes, result: ExtractionResult) -> None:
        root = etree.fromstring(xml)
        for comment in root.iter(f"{{{W}}}comment"):
            text = "".join(t.text or "" for t in comment.iter(f"{{{W}}}t"))
            if text.strip():
                author = comment.get(f"{{{W}}}author", "?")
                result.spans.append(
                    TextSpan(text=text, visible=False,
                             location=f"comments.xml (author: {author})",
                             reason=HideReason.COMMENT)
                )

    def _parse_metadata(self, z: zipfile.ZipFile, names: set, result: ExtractionResult) -> None:
        meta = {}
        for part in ("docProps/core.xml", "docProps/app.xml", "docProps/custom.xml"):
            if part not in names:
                continue
            try:
                root = etree.fromstring(z.read(part))
            except Exception:
                continue
            for el in root.iter():
                tag = etree.QName(el).localname
                if el.text and el.text.strip():
                    meta[tag] = el.text.strip()
                    result.spans.append(
                        TextSpan(text=el.text.strip(), visible=False,
                                 location=f"metadata:{part}:{tag}",
                                 reason=HideReason.METADATA)
                    )
        result.metadata = meta
