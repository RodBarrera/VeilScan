"""
Detector de patrones semanticos.

Capa SECUNDARIA. La leccion de las herramientas existentes es clara: un clasificador
de texto puro falla y genera falsos positivos. Por eso el peso fuerte lo lleva el
analisis estructural. Aqui solo buscamos frases tipicas de inyeccion, y subimos la
gravedad cuando el texto que las contiene venia de un span OCULTO (la combinacion
"oculto + instruccion imperativa" es la senal de alta confianza).

Patrones bilingues (ingles + espanol), por la realidad del mercado LATAM.
"""

from __future__ import annotations

import re

from veilscan.core.models import Finding, Severity, Technique

# (regex, tecnica, gravedad_base, titulo)
_PATTERNS: list[tuple[re.Pattern, Technique, Severity, str]] = [
    (re.compile(r"ignore (all |the )?(previous|above|prior|earlier) (instructions|prompts?|context)", re.I),
     Technique.INSTRUCTION_OVERRIDE, Severity.HIGH, "Override de instrucciones (EN)"),
    (re.compile(r"(disregard|forget) (all |the |everything )?(previous|above|prior)", re.I),
     Technique.INSTRUCTION_OVERRIDE, Severity.HIGH, "Descartar instrucciones previas (EN)"),
    (re.compile(r"(ignora|olvida|descarta)( (las|todas las|tus))? (instrucciones|indicaciones)( (previas|anteriores))?", re.I),
     Technique.INSTRUCTION_OVERRIDE, Severity.HIGH, "Override de instrucciones (ES)"),
    (re.compile(r"\b(system|assistant|developer)\s*:", re.I),
     Technique.ROLE_MANIPULATION, Severity.MEDIUM, "Inyeccion de rol (system/assistant)"),
    (re.compile(r"you are (now |an? )?(a |an )?(helpful |different )?(AI|assistant|model|chatbot)", re.I),
     Technique.ROLE_MANIPULATION, Severity.MEDIUM, "Manipulacion de rol (EN)"),
    (re.compile(r"(eres|actua como|comportate como|haz de) (ahora )?(un|una|el|la)?\s*(IA|asistente|modelo)", re.I),
     Technique.ROLE_MANIPULATION, Severity.MEDIUM, "Manipulacion de rol (ES)"),
    (re.compile(r"if you (are|'re) (an? )?(AI|language model|assistant)", re.I),
     Technique.ROLE_MANIPULATION, Severity.MEDIUM, "Targeting de identidad IA (EN)"),
    (re.compile(r"si (eres|fueras) (una? )?(IA|modelo de lenguaje|asistente)", re.I),
     Technique.ROLE_MANIPULATION, Severity.MEDIUM, "Targeting de identidad IA (ES)"),
    (re.compile(r"(as|being) an? (AI |large )?language model", re.I),
     Technique.ROLE_MANIPULATION, Severity.LOW, "Referencia a modelo de lenguaje"),
    (re.compile(r"(send|forward|email|exfiltrate|leak|post)\s+(this|the|all|an?)\b.{0,30}\b(to|email|address|url|http)", re.I),
     Technique.TOOL_ABUSE, Severity.HIGH, "Intento de exfiltracion / accion (EN)"),
    (re.compile(r"(envia|reenvia|manda|filtra)\b.{0,40}\b(correo|email|a la direccion|http|url)", re.I),
     Technique.TOOL_ABUSE, Severity.HIGH, "Intento de exfiltracion / accion (ES)"),
    (re.compile(r"(only (output|respond|reply|say)|respond only with|output only)", re.I),
     Technique.INSTRUCTION_OVERRIDE, Severity.MEDIUM, "Forzado de salida (EN)"),
    (re.compile(r"(responde|contesta|di) (solo|unicamente|solamente)\b", re.I),
     Technique.INSTRUCTION_OVERRIDE, Severity.MEDIUM, "Forzado de salida (ES)"),
    (re.compile(r"(give|provide|write) (a |an )?(positive|glowing|excellent|top|perfect) (review|rating|score|recommendation)", re.I),
     Technique.INSTRUCTION_OVERRIDE, Severity.MEDIUM, "Manipulacion de evaluacion (EN)"),
    (re.compile(r"(recomienda|aprueba|califica|evalua)\b.{0,30}\b(positiv|excelente|favorable|contrata)", re.I),
     Technique.INSTRUCTION_OVERRIDE, Severity.MEDIUM, "Manipulacion de evaluacion (ES)"),
]


def scan(text: str, hidden: bool = False, where: str = "document") -> list[Finding]:
    """Busca patrones de inyeccion. Si `hidden` es True, sube la gravedad un escalon."""
    findings: list[Finding] = []
    if not text or not text.strip():
        return findings

    for regex, technique, base_sev, title in _PATTERNS:
        m = regex.search(text)
        if not m:
            continue
        sev = _escalate(base_sev) if hidden else base_sev
        # extrae un fragmento de contexto alrededor del match
        start = max(0, m.start() - 30)
        end = min(len(text), m.end() + 30)
        context = text[start:end]
        findings.append(
            Finding(
                technique=technique,
                severity=sev,
                title=title + (" [en texto oculto]" if hidden else ""),
                location=where,
                evidence=context,
                detail=(
                    "Frase tipica de inyeccion de prompt detectada"
                    + (" dentro de contenido oculto (alta confianza)." if hidden
                       else " en contenido visible (revisar contexto).")
                ),
                hidden=hidden,
            )
        )
    return findings


_ESCALATION = {
    Severity.LOW: Severity.MEDIUM,
    Severity.MEDIUM: Severity.HIGH,
    Severity.HIGH: Severity.CRITICAL,
    Severity.CRITICAL: Severity.CRITICAL,
    Severity.INFO: Severity.LOW,
}


def _escalate(sev: Severity) -> Severity:
    return _ESCALATION[sev]
