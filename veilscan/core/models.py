"""
Modelos de datos centrales de VeilScan.

Toda la herramienta gira en torno a tres objetos:

  - TextSpan        : una porcion de texto extraida de un documento, marcada
                      como visible u oculta (con el motivo del ocultamiento).
  - Finding         : una deteccion concreta (que se encontro, donde, gravedad).
  - ScanResult      : el resultado completo del analisis de un archivo.

El diseno separa deliberadamente la EXTRACCION (sacar todo el texto, visible y
oculto) de la DETECCION (decidir si algo es sospechoso). Asi cada capa se puede
probar y extender por separado.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    """Gravedad de un hallazgo. El valor numerico alimenta el risk score."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def weight(self) -> int:
        return {
            Severity.CRITICAL: 40,
            Severity.HIGH: 25,
            Severity.MEDIUM: 10,
            Severity.LOW: 3,
            Severity.INFO: 0,
        }[self]


class HideReason(str, Enum):
    """Por que un fragmento de texto se considera 'no visible' para un humano."""

    INVISIBLE_RENDER = "invisible_render_mode"   # PDF: modo de render 3 (texto invisible)
    NEAR_WHITE = "near_white_color"              # texto del mismo color que el fondo
    TINY_FONT = "tiny_font"                      # fuente < umbral (p.ej. < 2pt)
    OFF_PAGE = "off_page"                        # fuera del area visible de la pagina/slide
    HIDDEN_LAYER = "hidden_ocg_layer"            # PDF: capa OCG con visibilidad OFF
    VANISH = "vanish_flag"                       # DOCX: atributo w:vanish
    METADATA = "metadata"                        # metadatos (titulo, autor, XMP, etc.)
    COMMENT = "comment"                          # comentarios / anotaciones
    HEADER_FOOTER = "header_footer"              # encabezados y pies de pagina
    ALT_TEXT = "alt_text"                        # texto alternativo de imagenes
    NOTES = "speaker_notes"                      # notas del orador (PPTX)
    HIDDEN_SHEET = "hidden_sheet"                # XLSX: hoja oculta / veryHidden
    HIDDEN_ROWCOL = "hidden_row_or_col"          # XLSX: fila o columna oculta
    HIDDEN_FORMAT = "hidden_number_format"       # XLSX: formato ';;;' (celda en blanco)
    DEFINED_NAME = "defined_name"                # XLSX: nombre definido


# Taxonomia propia de tecnicas, con guino a MITRE ATT&CK donde aplica.
# (T1027 = Obfuscated Files or Information; T1566 = Phishing.)
class Technique(str, Enum):
    HIDDEN_TEXT = "VEIL-T001: Texto oculto a la vista humana"
    UNICODE_SMUGGLING = "VEIL-T002: Contrabando Unicode (zero-width / tag block)"
    BIDI_OVERRIDE = "VEIL-T003: Override bidireccional"
    HOMOGLYPH = "VEIL-T004: Homoglifos / caracteres confundibles"
    INSTRUCTION_OVERRIDE = "VEIL-T005: Intento de override de instrucciones"
    ROLE_MANIPULATION = "VEIL-T006: Manipulacion de rol del sistema/asistente"
    TOOL_ABUSE = "VEIL-T007: Invocacion de herramientas / accion no solicitada"
    ACTIVE_CONTENT = "VEIL-T008: Contenido activo (JavaScript embebido)"
    METADATA_INJECTION = "VEIL-T009: Inyeccion via metadatos"


@dataclass
class TextSpan:
    """Un fragmento de texto extraido del documento."""

    text: str
    visible: bool
    location: str = ""                  # p.ej. "page 2", "header", "comments.xml"
    reason: Optional[HideReason] = None  # solo cuando visible == False
    font_size: Optional[float] = None
    color: Optional[str] = None          # representacion legible, p.ej. "#FFFFFF"

    @property
    def preview(self) -> str:
        flat = " ".join(self.text.split())
        return flat[:120] + ("..." if len(flat) > 120 else "")


@dataclass
class Finding:
    """Una deteccion individual."""

    technique: Technique
    severity: Severity
    title: str
    location: str
    evidence: str                       # fragmento legible que prueba el hallazgo
    detail: str = ""                    # explicacion en lenguaje natural
    hidden: bool = False                # True si el texto venia de un span oculto

    def evidence_preview(self, limit: int = 160) -> str:
        flat = " ".join(self.evidence.split())
        return flat[:limit] + ("..." if len(flat) > limit else "")

    @property
    def mitre(self) -> list:
        """Tecnicas MITRE ATT&CK asociadas a este hallazgo (ver core/mitre.py).

        Import local para evitar import circular: mitre.py importa Technique
        desde este mismo archivo.
        """
        from veilscan.core.mitre import get_mitre

        return get_mitre(self.technique)


@dataclass
class LlmAssessment:
    """Veredicto en lenguaje natural del 'juez LLM' sobre el texto oculto."""

    available: bool                      # False si no se pudo consultar (sin key, sin red, etc.)
    verdict: str = ""                    # malicious | suspicious | benign
    summary: str = ""                    # explicacion en lenguaje natural
    intent: str = ""                     # etiqueta corta del objetivo del ataque
    recommendation: str = ""             # accion sugerida
    model: str = ""                      # modelo usado
    error: str = ""                      # motivo si available == False

    def to_dict(self) -> dict:
        return {
            "available": self.available,
            "verdict": self.verdict,
            "summary": self.summary,
            "intent": self.intent,
            "recommendation": self.recommendation,
            "model": self.model,
            "error": self.error,
        }


@dataclass
class ScanResult:
    """Resultado completo del analisis de un archivo."""

    path: str
    file_type: str
    findings: list[Finding] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
    error: Optional[str] = None

    # estadisticas de extraccion (utiles para el reporte y la divergencia)
    visible_chars: int = 0
    hidden_chars: int = 0

    # veredicto opcional del juez LLM (None si no se solicito)
    llm: Optional[LlmAssessment] = None

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    @property
    def risk_score(self) -> int:
        """Suma ponderada de gravedades, saturada a 100."""
        return min(100, sum(f.severity.weight for f in self.findings))

    @property
    def risk_label(self) -> str:
        s = self.risk_score
        if s >= 70:
            return "CRITICAL"
        if s >= 40:
            return "HIGH"
        if s >= 15:
            return "MEDIUM"
        if s > 0:
            return "LOW"
        return "CLEAN"

    @property
    def is_clean(self) -> bool:
        return not self.findings and self.error is None

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "file_type": self.file_type,
            "risk_score": self.risk_score,
            "risk_label": self.risk_label,
            "error": self.error,
            "stats": {
                "visible_chars": self.visible_chars,
                "hidden_chars": self.hidden_chars,
            },
            "metadata": self.metadata,
            "llm": self.llm.to_dict() if self.llm else None,
            "findings": [
                {
                    "technique": f.technique.value,
                    "severity": f.severity.value,
                    "title": f.title,
                    "location": f.location,
                    "hidden": f.hidden,
                    "evidence": f.evidence_preview(400),
                    "detail": f.detail,
                    "mitre_attack": [
                        {
                            "id": m.id,
                            "name": m.name,
                            "tactic": m.tactic,
                            "confidence": m.confidence,
                            "url": m.url,
                        }
                        for m in f.mitre
                    ],
                }
                for f in self.findings
            ],
        }
