# Arquitectura de VeilScan

## Principio rector

> El extractor expone **todo** lo que un parser/LLM podría leer, marcando qué es
> visible y qué no. Los detectores deciden qué es sospechoso. Estas dos
> responsabilidades nunca se mezclan.

Esto importa porque la lección de las herramientas existentes es que un clasificador
de texto puro falla y genera ruido. El peso fuerte lo lleva el análisis **estructural**
(detectar *cómo* se oculta el texto), que es agnóstico al idioma. La capa semántica
(qué dice el texto) es secundaria y solo sube la confianza.

## Pipeline

```
archivo
  │
  ▼
┌─────────────┐   spans (visible/oculto) + metadatos + hallazgos estructurales
│  EXTRACTOR  │ ───────────────────────────────────────────────────────────┐
└─────────────┘   (pdf.py / docx.py)                                        │
                                                                            ▼
                                                              ┌──────────────────────┐
                                                              │      DETECTORES       │
                                                              │  · divergencia        │
                                                              │  · patrones (EN/ES)   │
                                                              │  · capa unicode       │
                                                              └──────────┬───────────┘
                                                                         │ findings
                                                                         ▼
                                                              ┌──────────────────────┐
                                                              │   SCORING (models)    │
                                                              │  suma ponderada → 100 │
                                                              └──────────┬───────────┘
                                                                         │ ScanResult
                                                                         ▼
                                                              ┌──────────────────────┐
                                                              │  REPORTE (rich/html)  │
                                                              └──────────────────────┘
```

## Componentes

### `core/models.py`
Define `Severity` (con peso numérico), `HideReason`, `Technique`, `TextSpan`,
`Finding` y `ScanResult`. El `risk_score` es la suma ponderada de severidades,
saturada a 100. CRITICAL=40, HIGH=25, MEDIUM=10, LOW=3.

### `extractors/`
Cada extractor hereda de `BaseExtractor` y declara sus extensiones. Devuelve un
`ExtractionResult` con `spans`, `metadata` y `structural_findings`. Para agregar un
formato nuevo (XLSX, PPTX en Fase 2): crear el módulo, heredar `BaseExtractor`,
registrarlo en `core/scanner.py`. Nada más cambia.

- **`pdf.py`** — PyMuPDF para spans y geometría (color, tamaño, bbox vs página),
  pikepdf para estructura interna (OCG, JavaScript, metadatos `/Info` + XMP).
- **`docx.py`** — `zipfile` + `lxml` sobre el OOXML crudo. Intencionalmente NO usa
  `python-docx`, porque las librerías de alto nivel ignoran el contenido oculto.

### `detectors/`
- **`divergence.py`** — calcula la brecha entre caracteres visibles y ocultos. Es la
  señal principal y agnóstica al idioma.
- **`patterns.py`** — regex bilingües de frases de inyección. Si el texto venía de un
  span oculto, **escala** la severidad un nivel (oculto + imperativo = alta confianza).
- **`unicode_layer.py`** — zero-width, controles bidi, bloque de etiquetas (que
  **decodifica** a ASCII para mostrar el mensaje contrabandeado) y homoglifos.
  Expone `normalize()`, que el scanner aplica antes de pasar texto a `patterns` para
  que un zero-width insertado no permita evadir la detección.

### `core/scanner.py`
Orquesta todo. Elige el extractor, corre las capas de detección, calcula stats,
deduplica hallazgos y devuelve el `ScanResult`.

### `sanitizer/`
Fase 1: limpieza segura sin re-render (metadatos + JavaScript en PDF). Fase 2:
neutralización profunda con reescritura de contenido.

### `reporting/`
`terminal.py` (rich), `html.py` (jinja2) y `pdf.py` (reportlab, evidencia adjuntable).

## Decisiones de diseño

- **Robustez ante archivos rotos:** un PDF/DOCX malformado nunca tumba el scan; el
  error se captura y se reporta en `ScanResult.error`.
- **Códigos de salida para CI:** `--fail-on LEVEL` permite usar VeilScan como gate en
  pipelines (`exit 1` si el riesgo alcanza el umbral).
- **Umbrales ajustables:** los límites (color casi-blanco, fuente diminuta, margen
  off-page) están como constantes al inicio de cada extractor.

## Extender a Fase 2

El punto de entrada para casi todo es el registro de extractores en `scanner.py`:

```python
_EXTRACTORS: list[BaseExtractor] = [
    PdfExtractor(), DocxExtractor(), XlsxExtractor(), PptxExtractor(),
]
# Fase 2.x: añadir validación de magic-number, capa juez LLM, etc.
```

La capa "juez LLM" (`detectors/llm_judge.py`) es opcional y se activa con `--llm`.
Recibe el texto oculto y le pide a un modelo de Anthropic que lo clasifique y
explique. Punto crítico de seguridad: el texto analizado es hostil por definición,
así que se encapsula entre marcadores dentro del mensaje de usuario (nunca en el
system prompt) y el system prompt ordena analizarlo sin obedecerlo. Degrada con
elegancia si falta el paquete `anthropic` o la `ANTHROPIC_API_KEY`.
