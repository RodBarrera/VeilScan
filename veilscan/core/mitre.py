"""
Crosswalk VEIL-TXXX -> MITRE ATT&CK (Enterprise).

Por que un modulo aparte y no meterlo directo en models.py
------------------------------------------------------------
La taxonomia VEIL es NUESTRA: la inventamos para describir con precision
tecnicas de inyeccion de prompt en documentos (algo que ATT&CK Enterprise,
pensado para intrusion tradicional en redes/endpoints, no cubria cuando fue
disenado). MITRE ATT&CK es el lenguaje ESTANDAR que cualquier analista SOC,
herramienta SIEM o reporte de threat intel ya reconoce.

Este modulo no reemplaza la taxonomia VEIL, la traduce: cada VEIL-TXXX apunta
a una o mas tecnicas oficiales de ATT&CK, con su tactica (la fase del ataque:
Defense Evasion, Execution, etc.) y un nivel de confianza en el mapeo.

Sobre la honestidad del mapeo
------------------------------
ATT&CK Enterprise se diseno para malware, C2 y movimiento lateral en
infraestructura IT clasica; no tiene categoria nativa para "inyeccion de
prompt contra un LLM". Por eso cada entrada trae un campo `confidence`:

  - "direct"    : la tecnica de ATT&CK describe el mismo comportamiento,
                  casi sin traduccion (ej: esconder texto = Hide Artifacts).
  - "analogous" : no existe una tecnica ATT&CK para "manipular a un modelo
                  de lenguaje", asi que mapeamos al concepto mas cercano en
                  espiritu (ej: tratar al LLM como un interprete de
                  comandos). Se marca explicitamente para no inflar
                  precision que no existe.

Nota para quien siga el roadmap: MITRE si tiene un framework hermano pensado
para esto -> ATLAS (Adversarial Threat Landscape for AI Systems), con
tecnicas como AML.T0051 (LLM Prompt Injection). Queda fuera de esta fase
para no mezclar dos taxonomias externas a la vez, pero es el siguiente
salto natural si se quiere aun mas precision.
"""

from __future__ import annotations

from dataclasses import dataclass

from veilscan.core.models import Technique


@dataclass(frozen=True)
class MitreTechnique:
    """Una tecnica oficial de MITRE ATT&CK, tal como aparece en su matriz."""

    id: str            # p.ej. "T1027" o "T1036.002" (con sub-tecnica)
    name: str           # nombre oficial en ingles (asi la indexa MITRE)
    tactic: str         # fase del ataque, p.ej. "Defense Evasion"
    confidence: str      # "direct" | "analogous"
    note: str = ""       # por que se eligio, sobre todo si es "analogous"

    @property
    def url(self) -> str:
        # Las sub-tecnicas usan guion en la URL en vez de punto: T1036.002 -> T1036/002
        base = self.id.split(".")[0]
        if "." in self.id:
            sub = self.id.split(".")[1]
            return f"https://attack.mitre.org/techniques/{base}/{sub}/"
        return f"https://attack.mitre.org/techniques/{base}/"


# Crosswalk principal: cada Technique VEIL -> lista de MitreTechnique.
# El orden importa: la primera es la mas representativa (la que se muestra
# en reportes compactos como la tabla de terminal).
_CROSSWALK: dict[Technique, list[MitreTechnique]] = {
    Technique.HIDDEN_TEXT: [
        MitreTechnique(
            "T1564", "Hide Artifacts", "Defense Evasion", "direct",
            "El objetivo exacto de VEIL-T001: esconder contenido de la vista humana."),
        MitreTechnique(
            "T1027", "Obfuscated Files or Information", "Defense Evasion", "direct",
            "El contenido oculto tambien ofusca la intencion real del documento."),
    ],
    Technique.UNICODE_SMUGGLING: [
        MitreTechnique(
            "T1027.003", "Obfuscated Files or Information: Steganography",
            "Defense Evasion", "direct",
            "Codificar instrucciones en puntos de codigo invisibles (zero-width, "
            "tag block) es esteganografia sobre texto plano."),
    ],
    Technique.BIDI_OVERRIDE: [
        MitreTechnique(
            "T1036.002", "Masquerading: Right-to-Left Override",
            "Defense Evasion", "direct",
            "Sub-tecnica oficial de ATT&CK, corresponde 1:1 con el caracter U+202E."),
    ],
    Technique.HOMOGLYPH: [
        MitreTechnique(
            "T1036", "Masquerading", "Defense Evasion", "direct",
            "ATT&CK no tiene sub-tecnica especifica para homoglifos; "
            "Masquerading (hacer pasar algo por lo que no es) es el padre correcto."),
    ],
    Technique.INSTRUCTION_OVERRIDE: [
        MitreTechnique(
            "T1059", "Command and Scripting Interpreter", "Execution", "analogous",
            "ATT&CK no cubre 'instrucciones a un LLM'; el analogo mas cercano es "
            "tratar al modelo como un interprete al que se le inyectan comandos."),
    ],
    Technique.ROLE_MANIPULATION: [
        MitreTechnique(
            "T1548", "Abuse Elevation Control Mechanism",
            "Privilege Escalation", "analogous",
            "Hacerse pasar por 'system' o 'assistant' busca que el modelo le "
            "otorgue al texto un nivel de confianza/autoridad que no le corresponde."),
    ],
    Technique.TOOL_ABUSE: [
        MitreTechnique(
            "T1106", "Native API", "Execution", "analogous",
            "Inducir al agente a invocar una herramienta/accion no solicitada "
            "abusa de una interfaz legitima, igual que abusar de una API nativa."),
    ],
    Technique.ACTIVE_CONTENT: [
        MitreTechnique(
            "T1059.007", "Command and Scripting Interpreter: JavaScript",
            "Execution", "direct",
            "JavaScript embebido y ejecutable dentro del propio PDF."),
    ],
    Technique.METADATA_INJECTION: [
        MitreTechnique(
            "T1027", "Obfuscated Files or Information", "Defense Evasion", "direct",
            "Los metadatos son un canal que casi nadie inspecciona: "
            "esconder ahi el payload es ofuscacion por ubicacion."),
    ],
}


def get_mitre(technique: Technique) -> list[MitreTechnique]:
    """Devuelve las tecnicas ATT&CK asociadas a una tecnica VEIL (puede ser vacia)."""
    return _CROSSWALK.get(technique, [])


def primary_mitre(technique: Technique) -> MitreTechnique | None:
    """La tecnica ATT&CK mas representativa (la primera de la lista), o None."""
    mapped = get_mitre(technique)
    return mapped[0] if mapped else None


def full_crosswalk() -> list[tuple[Technique, list[MitreTechnique]]]:
    """Todo el crosswalk, en el orden declarado (util para 'veilscan mitre')."""
    return list(_CROSSWALK.items())
