"""
Detector de capa Unicode.

El analisis estructural ve *como* se oculta el texto a nivel de formato. Esta capa
ve los trucos a nivel de *caracter*, que el render estructural no detecta:

  - Caracteres de ancho cero (ZWSP, ZWNJ, ZWJ, BOM, word joiner)
  - Controles bidireccionales (override LTR/RTL)
  - Bloque de etiquetas Unicode U+E0000-E007F ("ASCII smuggling": texto totalmente
    invisible que un LLM si interpreta). Lo DECODIFICAMOS para mostrar que decia.
  - Homoglifos / mezcla de scripts dentro de una misma palabra

Funciona sobre cualquier texto ya extraido, sin importar el formato de origen.
"""

from __future__ import annotations

import unicodedata

from veilscan.core.models import Finding, Severity, Technique

try:
    from confusable_homoglyphs import confusables
    _HAS_CONFUSABLES = True
except Exception:  # pragma: no cover
    _HAS_CONFUSABLES = False

ZERO_WIDTH = {
    "\u200b": "ZERO WIDTH SPACE",
    "\u200c": "ZERO WIDTH NON-JOINER",
    "\u200d": "ZERO WIDTH JOINER",
    "\u2060": "WORD JOINER",
    "\ufeff": "ZERO WIDTH NO-BREAK SPACE (BOM)",
}
BIDI_CONTROLS = {
    "\u202a": "LEFT-TO-RIGHT EMBEDDING",
    "\u202b": "RIGHT-TO-LEFT EMBEDDING",
    "\u202c": "POP DIRECTIONAL FORMATTING",
    "\u202d": "LEFT-TO-RIGHT OVERRIDE",
    "\u202e": "RIGHT-TO-LEFT OVERRIDE",
    "\u2066": "LEFT-TO-RIGHT ISOLATE",
    "\u2067": "RIGHT-TO-LEFT ISOLATE",
    "\u2068": "FIRST STRONG ISOLATE",
    "\u2069": "POP DIRECTIONAL ISOLATE",
}


def _decode_tag_block(text: str) -> str:
    """Convierte el bloque de etiquetas (U+E0000+) de vuelta a ASCII legible."""
    out = []
    for ch in text:
        cp = ord(ch)
        if 0xE0020 <= cp <= 0xE007E:
            out.append(chr(cp - 0xE0000))
    return "".join(out)


def scan(text: str, where: str = "document") -> list[Finding]:
    findings: list[Finding] = []
    if not text:
        return findings

    # --- Caracteres de ancho cero ---
    zw_hits = {name: text.count(ch) for ch, name in ZERO_WIDTH.items() if ch in text}
    if zw_hits:
        total = sum(zw_hits.values())
        detail = ", ".join(f"{n}x {name}" for name, n in zw_hits.items())
        findings.append(
            Finding(
                technique=Technique.UNICODE_SMUGGLING,
                severity=Severity.MEDIUM,
                title=f"{total} caracter(es) de ancho cero",
                location=where,
                evidence=detail,
                detail="Caracteres invisibles intercalados; pueden ocultar o partir instrucciones.",
                hidden=True,
            )
        )

    # --- Controles bidireccionales ---
    bidi_hits = {name: text.count(ch) for ch, name in BIDI_CONTROLS.items() if ch in text}
    if bidi_hits:
        detail = ", ".join(f"{n}x {name}" for name, n in bidi_hits.items())
        findings.append(
            Finding(
                technique=Technique.BIDI_OVERRIDE,
                severity=Severity.MEDIUM,
                title="Controles bidireccionales presentes",
                location=where,
                evidence=detail,
                detail="Overrides de direccion que pueden reordenar texto visualmente y enganar al lector.",
                hidden=True,
            )
        )

    # --- Bloque de etiquetas (ASCII smuggling) ---
    decoded = _decode_tag_block(text)
    if decoded:
        findings.append(
            Finding(
                technique=Technique.UNICODE_SMUGGLING,
                severity=Severity.CRITICAL,
                title="Texto oculto via bloque de etiquetas Unicode",
                location=where,
                evidence=f"Mensaje decodificado: {decoded!r}",
                detail=(
                    "El texto contiene caracteres del bloque U+E0000 (tag block), totalmente "
                    "invisibles para un humano pero interpretables por un LLM. Se decodifico "
                    "el contenido oculto."
                ),
                hidden=True,
            )
        )

    # --- Homoglifos / mezcla de scripts por palabra ---
    if _HAS_CONFUSABLES:
        flagged = []
        for word in set(text.split()):
            w = word.strip(".,;:!?()[]{}\"'")
            if len(w) < 2 or w.isascii():
                continue
            try:
                if confusables.is_mixed_script(w):
                    flagged.append(w)
            except Exception:
                continue
            if len(flagged) >= 5:
                break
        if flagged:
            findings.append(
                Finding(
                    technique=Technique.HOMOGLYPH,
                    severity=Severity.LOW,
                    title="Palabras con mezcla de scripts (posibles homoglifos)",
                    location=where,
                    evidence=", ".join(flagged),
                    detail="Una misma palabra combina caracteres de distintos alfabetos; tecnica clasica de suplantacion.",
                    hidden=True,
                )
            )

    return findings


def normalize(text: str) -> str:
    """Quita caracteres invisibles y normaliza, para que el detector de patrones
    no se evada por culpa de un zero-width insertado en medio de una palabra."""
    cleaned = []
    for ch in text:
        cp = ord(ch)
        if ch in ZERO_WIDTH or ch in BIDI_CONTROLS:
            continue
        if 0xE0000 <= cp <= 0xE007F:  # tag block
            if 0xE0020 <= cp <= 0xE007E:
                cleaned.append(chr(cp - 0xE0000))
            continue
        cleaned.append(ch)
    return unicodedata.normalize("NFKC", "".join(cleaned))
