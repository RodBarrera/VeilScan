"""
Detector de divergencia de extraccion.

Esta es la idea central de VeilScan. En vez de juzgar el contenido, medimos la
BRECHA entre dos vistas del mismo documento:

  - vista humana : solo el texto que se renderiza visiblemente
  - vista IA      : TODO lo que un parser o LLM puede llegar a leer

Cuando esa brecha es grande, alguien metio texto que ve la maquina pero no la
persona. Es agnostico al idioma y al contenido. Aqui emitimos un hallazgo
"cabecera" que resume la brecha; el detalle por-span lo aportan los otros detectores.
"""

from __future__ import annotations

from veilscan.core.models import Finding, HideReason, Severity, Technique
from veilscan.extractors.base import ExtractionResult

# Motivos de ocultamiento que NO contamos como divergencia "sospechosa" por si solos
# (los metadatos casi siempre existen; se analizan por patrones aparte).
_LOW_SIGNAL = {HideReason.METADATA}


def scan(extraction: ExtractionResult) -> list[Finding]:
    hidden_spans = [
        s for s in extraction.spans
        if not s.visible and s.reason not in _LOW_SIGNAL and s.text.strip()
    ]
    if not hidden_spans:
        return []

    hidden_chars = sum(len(s.text) for s in hidden_spans)
    visible_chars = max(1, sum(len(s.text) for s in extraction.spans if s.visible))
    ratio = hidden_chars / visible_chars

    # Gravedad por volumen de texto oculto y proporcion respecto a lo visible.
    if hidden_chars >= 200 or ratio >= 0.25:
        sev = Severity.HIGH
    elif hidden_chars >= 40:
        sev = Severity.MEDIUM
    else:
        sev = Severity.LOW

    reasons = {}
    for s in hidden_spans:
        key = s.reason.value if s.reason else "unknown"
        reasons[key] = reasons.get(key, 0) + 1
    reason_summary = ", ".join(f"{k} (x{v})" for k, v in sorted(reasons.items()))

    sample = " | ".join(s.preview for s in hidden_spans[:3])

    return [
        Finding(
            technique=Technique.HIDDEN_TEXT,
            severity=sev,
            title="Divergencia entre vista humana y vista IA",
            location="document",
            evidence=f"{hidden_chars} chars ocultos vs {visible_chars} visibles "
                     f"({ratio:.0%}). Via: {reason_summary}. Muestra: {sample}",
            detail=(
                "Hay texto que un parser/LLM lee pero que un humano no ve al abrir el "
                "documento. Esa brecha es el indicador principal de inyeccion oculta."
            ),
            hidden=True,
        )
    ]
