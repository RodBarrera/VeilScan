"""
Extractor de PDF (Fase 1).

Estrategia: analisis ESTRUCTURAL. No tratamos de adivinar si el texto oculto es
malicioso por su contenido (eso lo hacen los detectores). Aqui detectamos *como*
se oculta el texto, que es agnostico al idioma y casi no genera falsos positivos.

Superficies cubiertas:
  - Texto casi blanco (mismo color del fondo)         -> NEAR_WHITE
  - Fuente diminuta (< 2pt)                            -> TINY_FONT
  - Texto fuera del area visible de la pagina          -> OFF_PAGE
  - Modo de render invisible (operador `3 Tr`)         -> INVISIBLE_RENDER (texto atribuido por span)
  - Capas OCG ocultas por defecto                      -> hallazgo estructural
  - JavaScript embebido / OpenAction                   -> hallazgo estructural
  - Metadatos (/Info + XMP)                             -> spans METADATA
  - Anotaciones / comentarios                          -> spans COMMENT

Libs: PyMuPDF (fitz) para spans y geometria; pikepdf para la estructura interna.
"""

from __future__ import annotations

import re

import fitz  # PyMuPDF
import pikepdf

from veilscan.core.models import (
    Finding,
    HideReason,
    Severity,
    Technique,
    TextSpan,
)
from veilscan.extractors.base import BaseExtractor, ExtractionResult

# Umbrales (ajustables). Color: 0.9 * 255 ~= 230 en cada canal.
NEAR_WHITE_THRESHOLD = 230
TINY_FONT_PT = 2.0
OFF_PAGE_MARGIN = 2.0  # puntos de tolerancia fuera del rect de la pagina


def _int_to_rgb(color: int) -> tuple[int, int, int]:
    return (color >> 16) & 0xFF, (color >> 8) & 0xFF, color & 0xFF


def _is_near_white(color: int) -> bool:
    r, g, b = _int_to_rgb(color)
    return r >= NEAR_WHITE_THRESHOLD and g >= NEAR_WHITE_THRESHOLD and b >= NEAR_WHITE_THRESHOLD


class PdfExtractor(BaseExtractor):
    extensions = (".pdf",)

    def extract(self, path: str) -> ExtractionResult:
        result = ExtractionResult()
        self._extract_spans(path, result)
        self._extract_structure(path, result)
        return result

    # ------------------------------------------------------------------ #
    # Spans de texto + geometria (PyMuPDF)
    # ------------------------------------------------------------------ #
    def _extract_spans(self, path: str, result: ExtractionResult) -> None:
        doc = fitz.open(path)
        for page_index, page in enumerate(doc):
            page_no = page_index + 1
            rect = page.rect
            raw = page.get_text("rawdict")
            attributed_invisible_render = False

            for block in raw.get("blocks", []):
                for line in block.get("lines", []):
                    for span in line.get("spans", []):
                        text = "".join(c.get("c", "") for c in span.get("chars", []))
                        if not text.strip():
                            continue
                        size = float(span.get("size", 0.0))
                        color = int(span.get("color", 0))
                        alpha = int(span.get("alpha", 255))
                        bbox = span.get("bbox", (0, 0, 0, 0))
                        r, g, b = _int_to_rgb(color)
                        color_hex = f"#{r:02X}{g:02X}{b:02X}"

                        # alpha=0 es la huella que deja MuPDF cuando el texto se
                        # dibuja con modo de render invisible (operador `3 Tr` o
                        # `7 Tr`): no pinta nada, pero el texto SI se extrae. A
                        # diferencia de casi-blanco o fuente diminuta, este texto
                        # suele tener color y tamano completamente normales -- por
                        # eso antes se colaba como "visible" y solo se reportaba
                        # que el operador existia en la pagina, sin decir que texto
                        # era. Revisando alpha por span en vez de solo el operador
                        # a nivel de pagina, se atribuye el texto exacto.
                        reason = None
                        if alpha == 0:
                            reason = HideReason.INVISIBLE_RENDER
                            attributed_invisible_render = True
                        elif _is_near_white(color):
                            reason = HideReason.NEAR_WHITE
                        elif size and size < TINY_FONT_PT:
                            reason = HideReason.TINY_FONT
                        elif self._is_off_page(bbox, rect):
                            reason = HideReason.OFF_PAGE

                        result.spans.append(
                            TextSpan(
                                text=text,
                                visible=reason is None,
                                location=f"page {page_no}",
                                reason=reason,
                                font_size=size,
                                color=color_hex,
                            )
                        )

            # Red de seguridad: si el operador '3 Tr' aparece en el stream pero
            # ningun span del page.get_text() se pudo atribuir por alpha==0 (caso
            # raro: fuente no estandar, texto vacio, etc.), lo dejamos como aviso
            # generico en vez de quedar en silencio.
            if not attributed_invisible_render:
                self._scan_invisible_render(page, page_no, result)

            # Anotaciones / comentarios
            for annot in page.annots() or []:
                info = annot.info or {}
                content = (info.get("content") or "").strip()
                if content:
                    result.spans.append(
                        TextSpan(
                            text=content,
                            visible=False,
                            location=f"page {page_no} (annotation)",
                            reason=HideReason.COMMENT,
                        )
                    )
        doc.close()

    @staticmethod
    def _is_off_page(bbox, rect) -> bool:
        x0, y0, x1, y1 = bbox
        return (
            x1 < rect.x0 - OFF_PAGE_MARGIN
            or x0 > rect.x1 + OFF_PAGE_MARGIN
            or y1 < rect.y0 - OFF_PAGE_MARGIN
            or y0 > rect.y1 + OFF_PAGE_MARGIN
            or x0 < -OFF_PAGE_MARGIN
            or y0 < -OFF_PAGE_MARGIN
        )

    def _scan_invisible_render(self, page, page_no: int, result: ExtractionResult) -> None:
        """Fallback: el operador `3 Tr` esta en el stream pero ningun span se
        pudo atribuir por alpha (ver `_extract_spans`). Se reporta igual, sin
        texto exacto, para no perder la senal por completo."""
        try:
            content = page.read_contents().decode("latin-1", errors="ignore")
        except Exception:
            return
        # `3 Tr` activa el modo de render invisible. Permitimos espacios variables.
        if re.search(r"(^|\s)3\s+Tr(\s|$)", content):
            result.structural_findings.append(
                Finding(
                    technique=Technique.HIDDEN_TEXT,
                    severity=Severity.HIGH,
                    title="Texto en modo de render invisible (3 Tr), sin atribuir",
                    location=f"page {page_no}",
                    evidence="Operador '3 Tr' presente en el content stream, "
                             "pero no se pudo asociar a un span especifico.",
                    detail=(
                        "La pagina usa el modo de render de texto 3 (invisible). El texto "
                        "no se dibuja en pantalla pero un parser o LLM si lo lee. No se pudo "
                        "extraer el texto exacto en este caso (revisar manualmente)."
                    ),
                    hidden=True,
                )
            )

    # ------------------------------------------------------------------ #
    # Estructura interna (pikepdf): OCG, JavaScript, metadatos
    # ------------------------------------------------------------------ #
    def _extract_structure(self, path: str, result: ExtractionResult) -> None:
        try:
            pdf = pikepdf.open(path)
        except Exception as exc:  # pragma: no cover
            result.structural_findings.append(
                Finding(
                    technique=Technique.ACTIVE_CONTENT,
                    severity=Severity.LOW,
                    title="No se pudo abrir estructura interna",
                    location="document",
                    evidence=str(exc),
                )
            )
            return

        self._check_metadata(pdf, result)
        self._check_ocg(pdf, result)
        self._check_javascript(pdf, result)
        pdf.close()

    def _check_metadata(self, pdf, result: ExtractionResult) -> None:
        meta = {}
        try:
            docinfo = pdf.docinfo or {}
            for key, value in docinfo.items():
                k = str(key).lstrip("/")
                v = str(value)
                meta[k] = v
                if v.strip():
                    result.spans.append(
                        TextSpan(
                            text=v,
                            visible=False,
                            location=f"metadata:/Info/{k}",
                            reason=HideReason.METADATA,
                        )
                    )
        except Exception:
            pass
        try:
            with pdf.open_metadata() as xmp:
                for key, value in xmp.items():
                    meta[f"xmp:{key}"] = str(value)
                    if str(value).strip():
                        result.spans.append(
                            TextSpan(
                                text=str(value),
                                visible=False,
                                location=f"metadata:/XMP/{key}",
                                reason=HideReason.METADATA,
                            )
                        )
        except Exception:
            pass
        result.metadata = meta

    def _check_ocg(self, pdf, result: ExtractionResult) -> None:
        """Capas OCG (Optional Content Groups) apagadas por defecto."""
        try:
            root = pdf.Root
            if "/OCProperties" not in root:
                return
            ocprops = root.OCProperties
            d = ocprops.get("/D", {})
            off = d.get("/OFF", [])
            if len(off) > 0:
                result.structural_findings.append(
                    Finding(
                        technique=Technique.HIDDEN_TEXT,
                        severity=Severity.MEDIUM,
                        title=f"{len(off)} capa(s) OCG oculta(s) por defecto",
                        location="document (/OCProperties)",
                        evidence=f"{len(off)} capas en el array /OFF",
                        detail=(
                            "El PDF define capas de contenido opcional que arrancan "
                            "ocultas. El texto en esas capas no se muestra pero si se extrae."
                        ),
                        hidden=True,
                    )
                )
        except Exception:
            pass

    def _check_javascript(self, pdf, result: ExtractionResult) -> None:
        """Detecta JavaScript embebido y acciones automaticas (OpenAction)."""
        found = []
        try:
            root = pdf.Root
            names = root.get("/Names", {})
            if "/JavaScript" in names:
                found.append("/Names/JavaScript")
            if "/OpenAction" in root:
                oa = root.OpenAction
                if isinstance(oa, pikepdf.Dictionary) and oa.get("/S") == pikepdf.Name("/JavaScript"):
                    found.append("/OpenAction (JavaScript)")
        except Exception:
            pass
        if found:
            result.structural_findings.append(
                Finding(
                    technique=Technique.ACTIVE_CONTENT,
                    severity=Severity.HIGH,
                    title="JavaScript embebido en el PDF",
                    location="document",
                    evidence=", ".join(found),
                    detail=(
                        "El documento contiene JavaScript. Aunque no es inyeccion de "
                        "prompt en si, es contenido activo que amplia la superficie de ataque."
                    ),
                    hidden=True,
                )
            )
