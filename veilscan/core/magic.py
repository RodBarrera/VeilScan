"""
Validacion de magic number: detecta spoofing de extension.

La extension de un archivo (.pdf, .docx, ...) es solo una etiqueta de texto en
el nombre; el sistema operativo -y cualquier pipeline automatizado que decida
que hacer con un archivo "por su extension"- confia en ella ciegamente. El
contenido real de un archivo, en cambio, arranca con una firma binaria fija
(el "magic number") que no cambia si uno simplemente renombra el archivo.

Comparar ambos detecta el truco clasico de mandar "informe.pdf" cuando en
realidad es un ejecutable, o "cv.docx" cuando en realidad es una plantilla
Excel con macros: el nombre miente, el contenido no.

Los 4 formatos que soporta VeilScan tienen firmas distintas:

  - PDF                : arranca literal con los bytes "%PDF-".
  - DOCX / XLSX / PPTX : los tres son, por debajo, un archivo ZIP (firma
                         "PK\\x03\\x04"), porque el formato Office Open XML
                         es en realidad un .zip con una estructura de
                         carpetas fija. Para saber CUAL de los tres es en
                         realidad, hay que mirar el indice interno del zip:
                         si existe una carpeta "word/" es un Word, "xl/" es
                         un Excel, "ppt/" es un PowerPoint.

Por eso la deteccion tiene dos niveles: primero el magic number identifica la
"familia" (PDF vs ZIP vs algo desconocido), y despues -solo para el caso
ZIP- se mira el indice interno para saber la subfamilia exacta.

Este modulo NO decide que hacer con un mismatch (eso es responsabilidad del
scanner: sigue extrayendo con el extractor correcto para el contenido real,
y ademas deja un Finding CRITICAL). Aqui solo se compara y se informa.
"""

from __future__ import annotations

import zipfile
from dataclasses import dataclass

_PDF_MAGIC = b"%PDF-"
_ZIP_MAGIC = b"PK\x03\x04"
# variantes de ZIP menos comunes pero validas (archivo vacio / multi-volumen)
_ZIP_MAGIC_ALT = (b"PK\x05\x06", b"PK\x07\x08")

# Extension declarada (con punto, en minuscula) -> "familia" que deberia tener
_EXPECTED_KIND = {
    ".pdf": "pdf",
    ".docx": "docx",
    ".xlsx": "xlsx",
    ".xlsm": "xlsx",
    ".pptx": "pptx",
}

# Carpeta interna del zip que identifica cada subformato Office Open XML
_OOXML_MARKERS = {
    "word/": "docx",
    "xl/": "xlsx",
    "ppt/": "pptx",
}


@dataclass
class MagicCheck:
    """Resultado de comparar la extension declarada contra el contenido real."""

    declared_ext: str            # ".pdf", tal cual llego en el nombre de archivo
    declared_kind: str | None    # "pdf"/"docx"/"xlsx"/"pptx", o None si la extension no es soportada
    real_kind: str | None        # lo que dice el contenido real ("zip" = generico, sin subtipo Office)
    matches: bool                # True si coinciden (o si no hay como verificar)
    detail: str = ""             # explicacion legible


def sniff_real_kind(path: str) -> str | None:
    """Determina la familia real del archivo mirando su contenido, no su nombre.

    Devuelve "pdf", "docx", "xlsx", "pptx", "zip" (zip valido pero sin marcas
    de Office Open XML) o None (firma totalmente desconocida: ejecutable,
    imagen, texto plano, archivo corrupto, etc.).
    """
    try:
        with open(path, "rb") as fh:
            head = fh.read(8)
    except OSError:
        return None

    if head.startswith(_PDF_MAGIC):
        return "pdf"

    if head.startswith(_ZIP_MAGIC) or head.startswith(_ZIP_MAGIC_ALT):
        return _sniff_ooxml_subtype(path)

    return None


def _sniff_ooxml_subtype(path: str) -> str:
    """El archivo ya se sabe que es un ZIP. Mira el indice interno para saber cual Office es."""
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
    except (zipfile.BadZipFile, OSError):
        return "zip"

    for prefix, kind in _OOXML_MARKERS.items():
        if any(n.startswith(prefix) for n in names):
            return kind
    return "zip"  # zip generico (o de otra suite ofimatica): sin carpetas reconocibles


def check(path: str, declared_ext: str) -> MagicCheck:
    """Compara la extension declarada contra el contenido real del archivo."""
    declared_ext = declared_ext.lower()
    declared_kind = _EXPECTED_KIND.get(declared_ext)
    real_kind = sniff_real_kind(path)

    if declared_kind is None:
        return MagicCheck(declared_ext, None, real_kind, True,
                           "Extension no reconocida por VeilScan; no aplica verificacion.")

    if real_kind is None:
        return MagicCheck(
            declared_ext, declared_kind, None, False,
            f"El archivo declara ser .{declared_ext.lstrip('.')} pero su firma binaria no "
            "corresponde a PDF ni a un ZIP/OOXML: podria ser otro tipo de archivo "
            "(ejecutable, imagen, texto) disfrazado con esta extension.")

    matches = real_kind == declared_kind
    if matches:
        detail = f"La firma binaria confirma que el contenido es {declared_kind}."
    elif real_kind == "zip":
        detail = (f"El archivo declara ser .{declared_ext.lstrip('.')}, y es un ZIP valido, "
                   "pero no tiene la estructura interna de ningun formato Office Open XML "
                   "reconocido (falta word/, xl/ o ppt/).")
    else:
        detail = (f"El archivo se llama .{declared_ext.lstrip('.')} pero su contenido real "
                   f"es '{real_kind}': la extension no coincide con la firma binaria.")
    return MagicCheck(declared_ext, declared_kind, real_kind, matches, detail)
