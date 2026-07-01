"""
Orquestador central.

Flujo:
  1. Elige el extractor segun la extension del archivo.
  2. Extrae spans + metadatos + hallazgos estructurales.
  3. Pasa el texto por las capas de deteccion:
       - divergencia (vista humana vs IA)
       - patrones semanticos (por span, escalando si el span es oculto)
       - capa Unicode (zero-width, bidi, tag block, homoglifos)
  4. Consolida todo en un ScanResult con risk score.
"""

from __future__ import annotations

import os

from veilscan.core import magic
from veilscan.core.models import Finding, ScanResult, Severity, Technique
from veilscan.detectors import divergence, patterns, unicode_layer
from veilscan.extractors.base import BaseExtractor
from veilscan.extractors.docx import DocxExtractor
from veilscan.extractors.pdf import PdfExtractor
from veilscan.extractors.pptx import PptxExtractor
from veilscan.extractors.xlsx import XlsxExtractor

# Registro de extractores. Anadir un formato = registrar su extractor aqui.
_EXTRACTORS: list[BaseExtractor] = [
    PdfExtractor(),
    DocxExtractor(),
    XlsxExtractor(),
    PptxExtractor(),
]

# Mismo registro, pero indexado por "familia" (pdf/docx/xlsx/pptx) en vez de
# por extension. Lo usa la validacion de magic number para elegir el
# extractor correcto segun el CONTENIDO real del archivo, no segun su nombre.
_EXTRACTOR_BY_KIND: dict[str, BaseExtractor] = {
    ex.extensions[0].lstrip("."): ex for ex in _EXTRACTORS
}


def _pick_extractor(path: str) -> BaseExtractor | None:
    ext = os.path.splitext(path)[1].lower()
    for ex in _EXTRACTORS:
        if ext in ex.extensions:
            return ex
    return None


def supported_extensions() -> list[str]:
    out = []
    for ex in _EXTRACTORS:
        out.extend(ex.extensions)
    return out


def scan_file(path: str, use_llm: bool = False, llm_model: str | None = None) -> ScanResult:
    ext = os.path.splitext(path)[1].lower()
    extractor = _pick_extractor(path)
    result = ScanResult(path=path, file_type=ext.lstrip("."))

    if extractor is None:
        result.error = f"Formato no soportado: {ext}. Soportados: {', '.join(supported_extensions())}"
        return result

    if not os.path.isfile(path):
        result.error = "El archivo no existe."
        return result

    # 0) magic number: la extension del nombre de archivo es solo una etiqueta;
    #    esto verifica que el CONTENIDO real coincida con lo que dice el nombre.
    mcheck = magic.check(path, ext)
    spoof_finding: Finding | None = None
    if not mcheck.matches:
        spoof_finding = Finding(
            technique=Technique.EXTENSION_SPOOFING,
            severity=Severity.CRITICAL,
            title="La extension declarada no coincide con el contenido real del archivo",
            location="file",
            evidence=f"nombre: *{mcheck.declared_ext}  |  firma binaria real: {mcheck.real_kind or 'desconocida'}",
            detail=mcheck.detail,
        )
        # Si el contenido real es un formato que SI sabemos procesar, seguimos
        # el escaneo con el extractor correcto (mas robusto que rendirse), pero
        # el hallazgo CRITICAL queda igual: el intento de disfraz es la senal.
        if mcheck.real_kind in _EXTRACTOR_BY_KIND:
            extractor = _EXTRACTOR_BY_KIND[mcheck.real_kind]
        else:
            # firma desconocida o zip sin subtipo Office: no hay como extraer con seguridad
            result.error = mcheck.detail
            result.add(spoof_finding)
            return result

    try:
        extraction = extractor.extract(path)
    except Exception as exc:  # extraccion robusta: un PDF roto no debe tumbar el scan
        result.error = f"Error al extraer: {exc}"
        if spoof_finding is not None:
            result.add(spoof_finding)
        return result

    result.metadata = extraction.metadata

    if spoof_finding is not None:
        result.add(spoof_finding)

    # 1) hallazgos estructurales del extractor
    for f in extraction.structural_findings:
        result.add(f)

    # 2) divergencia vista-humano vs vista-IA
    for f in divergence.scan(extraction):
        result.add(f)

    # 3) patrones semanticos por span (normalizando antes para evadir trucos Unicode)
    for span in extraction.spans:
        normalized = unicode_layer.normalize(span.text)
        for f in patterns.scan(normalized, hidden=not span.visible, where=span.location):
            result.add(f)

    # 4) capa Unicode a nivel de documento
    for f in unicode_layer.scan(extraction.all_text, where="document"):
        result.add(f)

    # estadisticas
    result.visible_chars = sum(len(s.text) for s in extraction.spans if s.visible)
    result.hidden_chars = sum(len(s.text) for s in extraction.spans if not s.visible)

    _dedupe(result)

    # 5) (opcional) juez LLM: solo si se pidio y hay texto oculto que explicar
    if use_llm and extraction.hidden_text.strip():
        from veilscan.detectors import llm_judge
        llm_judge.assess_result(result, extraction.hidden_text, model=llm_model)

    return result


def _dedupe(result: ScanResult) -> None:
    seen = set()
    unique: list[Finding] = []
    for f in result.findings:
        key = (f.technique, f.title, f.evidence_preview(80))
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)
    result.findings = unique
