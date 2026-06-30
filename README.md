# VeilScan

**Detector de inyección de prompt oculta en documentos.**

VeilScan analiza documentos (PDF, DOCX, XLSX, PPTX) en busca de instrucciones ocultas dirigidas
a sistemas de IA: texto invisible, fuentes diminutas, contenido fuera de página,
capas ocultas, metadatos envenenados y contrabando de caracteres Unicode. Es una
herramienta **defensiva** pensada para colocarse *antes* de que un LLM o pipeline RAG
ingiera documentos no confiables (CVs, facturas, reportes de terceros).

> El riesgo ya no es solo "este PDF tiene una macro". Es "este documento trae
> instrucciones que un humano no ve, pero que el asistente de IA que lo procesa sí
> obedece". VeilScan mide esa brecha.

---

## Por qué es distinto

La mayoría de scanners de este tipo son **PDF-only** y se quedan en detección.
VeilScan apunta a tres cosas que casi ninguno combina:

1. **Multi-formato atacando el XML crudo.** En DOCX no usamos `python-docx` (que se
   salta lo oculto): vamos directo al OOXML del paquete ZIP.
2. **Detección por divergencia.** En vez de juzgar el contenido, medimos la brecha
   entre la *vista humana* (lo renderizado) y la *vista IA* (todo lo parseable). Es
   agnóstico al idioma y casi sin falsos positivos.
3. **Sanitización, no solo alerta.** Genera una copia más limpia del documento.

---

## Estado de componentes

Leyenda: ✅ Listo · 🚧 En progreso · ⬜ Pendiente

| Componente | Descripción | Fase | Estado |
|---|---|:---:|:---:|
| Modelo de datos | `Finding`, `TextSpan`, `ScanResult`, risk score ponderado | 1 | ✅ |
| CLI (`typer`) | `scan` / `sanitize` / `formats`, flags `--json` `--html` `--fail-on` | 1 | ✅ |
| Extractor **PDF** | texto casi blanco, fuente diminuta, off-page, `3 Tr`, OCG, JS, metadatos | 1 | ✅ |
| Extractor **DOCX** | `w:vanish`, color blanco, `w:sz`, comentarios, metadatos, alt-text | 1 | ✅ |
| Detector de divergencia | brecha vista-humano vs vista-IA | 1 | ✅ |
| Detector de patrones | frases de inyección bilingües (EN + ES), escala si el texto es oculto | 1 | ✅ |
| Detector Unicode | zero-width, bidi, tag block (decodificado), homoglifos | 1 | ✅ |
| Reporte terminal (`rich`) | tabla con severidad, técnica, ubicación, evidencia | 1 | ✅ |
| Reporte HTML (`jinja2`) | reporte autocontenido para adjuntar/portafolio | 1 | ✅ |
| Reporte PDF (`reportlab`) | reporte profesional adjuntable (evidencia/auditoría) | 2 | ✅ |
| Sanitizador PDF | elimina metadatos `/Info`, XMP, JavaScript / OpenAction | 1 | ✅ |
| Tests + fixtures | `pytest` + generador de documentos maliciosos de prueba | 1 | ✅ |
| Extractor **XLSX** | hojas `veryHidden`, filas/cols ocultas, fuente blanca, formato `;;;`, comentarios, metadatos | 2 | ✅ |
| Extractor **PPTX** | shapes fuera del slide, slides ocultos, notas del orador, fuente diminuta/blanca, alt-text | 2 | ✅ |
| Sanitización profunda | eliminar runs ocultos, capas OCG, normalizar Unicode, reescritura | 2 | ⬜ |
| Validación magic-number / MIME | detectar spoofing de extensión antes de parsear | 2 | ⬜ |
| Capa "juez LLM" (opcional) | usa la API de Anthropic para explicar qué dice el texto oculto, construida defensivamente | 2 | ✅ |
| Atribución de `3 Tr` | mini-parser de content stream para extraer el texto invisible exacto | 2 | ⬜ |
| Mapeo formal a MITRE ATT&CK | etiquetar cada hallazgo con su técnica oficial | 2 | ⬜ |
| Modo batch recursivo | escanea carpetas enteras y emite un resumen agregado | 2 | ✅ |
| GitHub Action | gate de CI listo para usar en pipelines | 2 | ⬜ |

Marca las casillas de la columna **Estado** a medida que completes la Fase 2.

---

## Instalación (Kali / Debian)

```bash
git clone <tu-repo>/veilscan.git
cd veilscan
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

> En Kali con Python gestionado por el sistema, si instalas fuera de un venv usa
> `pip install -e . --break-system-packages`.

---

## Uso

```bash
# escanear un documento
veilscan scan documento.pdf

# varios archivos, solo mostrar los que tengan hallazgos
veilscan scan *.docx -q

# escanear una CARPETA entera de forma recursiva (modo batch)
veilscan scan ./documentos/ -r

# en lote, ver tambien la tabla completa de cada archivo
veilscan scan ./documentos/ -r --details

# en lote, generar un PDF por documento (nombrado segun el archivo de origen)
veilscan scan ./documentos/ -r --pdf ./reportes/

# salida JSON (para integrar con otras tools)
veilscan scan cv.pdf --json

# generar reporte HTML
veilscan scan untrusted.pdf --html reporte.html

# generar reporte PDF (adjuntable como evidencia)
veilscan scan untrusted.pdf --pdf reporte.pdf

# usar como gate en CI: exit code != 0 si el riesgo llega a HIGH
veilscan scan untrusted.pdf --fail-on HIGH

# limpiar un PDF (metadatos + JS)
veilscan sanitize sucio.pdf --out limpio.pdf
```

### Juez LLM (opcional)

Con `--llm`, VeilScan le pide a un modelo de Anthropic que explique en lenguaje
natural qué intenta hacer el texto oculto y por qué es peligroso. Requiere el
paquete `anthropic` y la variable `ANTHROPIC_API_KEY`:

```bash
pip install -e ".[llm]"           # instala 'anthropic' y 'python-dotenv'
export ANTHROPIC_API_KEY=sk-...
veilscan scan untrusted.pdf --llm
veilscan scan cv.pdf --llm --llm-model claude-haiku-4-5 --pdf reporte.pdf
```

En vez de exportar la variable, puedes dejar la clave en un archivo `.env` en la
raíz del proyecto (ya está en `.gitignore`, así que nunca se sube). VeilScan lo
carga solo al usar `--llm`:

```bash
echo 'ANTHROPIC_API_KEY=sk-ant-...' > .env
veilscan scan untrusted.pdf --llm     # la clave se carga sola desde .env
```

> **Diseño defensivo (importante).** El texto que analiza el juez es, por
> definición, un intento de inyección. Para que esa inyección no secuestre la
> propia llamada, el texto sospechoso **nunca** va en el system prompt ni como
> instrucción: viaja encapsulado entre marcadores dentro del mensaje de usuario,
> marcado como dato no confiable, y el system prompt ordena analizarlo, no
> obedecerlo. Si falta el paquete o la API key, el juez degrada con elegancia y el
> resto del análisis sigue funcionando.

### Generar documentos de prueba

```bash
python -m tests.generate_fixtures
veilscan scan tests/fixtures/injected.pdf
veilscan scan tests/fixtures/injected.docx
```

### Ejecutar los tests

```bash
python -m pytest -q
```

---

## Taxonomía de técnicas

VeilScan usa una taxonomía propia (con guiño a MITRE ATT&CK donde aplica):

| Código | Técnica |
|---|---|
| VEIL-T001 | Texto oculto a la vista humana |
| VEIL-T002 | Contrabando Unicode (zero-width / tag block) |
| VEIL-T003 | Override bidireccional |
| VEIL-T004 | Homoglifos / caracteres confundibles |
| VEIL-T005 | Intento de override de instrucciones |
| VEIL-T006 | Manipulación de rol del sistema/asistente |
| VEIL-T007 | Invocación de herramientas / acción no solicitada |
| VEIL-T008 | Contenido activo (JavaScript embebido) |
| VEIL-T009 | Inyección vía metadatos |

---

## Arquitectura

Pipeline en cuatro etapas: **extracción → detección → scoring → reporte**. El detalle
está en [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

```
veilscan/
├── core/          modelos de datos + orquestador (scanner)
├── extractors/    un módulo por formato (pdf, docx) — sacan TODO el texto
├── detectors/     divergencia, patrones, capa unicode — deciden qué es sospechoso
├── sanitizer/     limpieza de superficies (Fase 1: metadatos + JS)
└── reporting/     salida en terminal (rich) y HTML (jinja2)
```

---

## Aviso

Herramienta para uso **autorizado, defensivo y educativo**. Los fixtures incluidos
usan payloads inofensivos con fines de prueba. No la uses sobre documentos sin
autorización.

Licencia MIT.

---

**Autor:** Jorge Barrera Espinoza — Ingeniero en Ciberseguridad
