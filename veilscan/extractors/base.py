"""
Interfaz base para los extractores de formato.

Un extractor recibe la ruta de un archivo y devuelve un ExtractionResult con:
  - todos los TextSpan (visibles y ocultos)
  - los metadatos del documento
  - hallazgos estructurales propios del formato (capas OCG, JS embebido, etc.)

La regla de oro del proyecto: el extractor NO decide si algo es malicioso por su
contenido; solo expone TODO lo que un parser ingenuo (o un LLM) podria llegar a
leer, marcando que es visible y que no. La capa de deteccion semantica vive
aparte, en veilscan/detectors/.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from veilscan.core.models import Finding, TextSpan


@dataclass
class ExtractionResult:
    spans: list[TextSpan] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
    structural_findings: list[Finding] = field(default_factory=list)

    @property
    def visible_text(self) -> str:
        return "\n".join(s.text for s in self.spans if s.visible)

    @property
    def hidden_text(self) -> str:
        return "\n".join(s.text for s in self.spans if not s.visible)

    @property
    def all_text(self) -> str:
        return "\n".join(s.text for s in self.spans)


class BaseExtractor(ABC):
    """Clase base. Cada formato hereda y registra sus extensiones soportadas."""

    #: extensiones (en minuscula, con punto) que maneja este extractor
    extensions: tuple[str, ...] = ()

    @abstractmethod
    def extract(self, path: str) -> ExtractionResult:
        """Extrae spans, metadatos y hallazgos estructurales del archivo."""
        raise NotImplementedError
