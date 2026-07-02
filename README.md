# VeilScan

[![Tests](https://github.com/RodBarrera/VeilScan/actions/workflows/tests.yml/badge.svg)](https://github.com/RodBarrera/VeilScan/actions/workflows/tests.yml)

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

## Capturas

Reporte HTML (autocontenido, pensado para adjuntar o subir a un ticket):

![Reporte HTML de VeilScan](docs/img/reporte_html.png)

Reporte PDF (evidencia/auditoría, con tabla de hallazgos y mapeo a MITRE ATT&CK):

![Reporte PDF de VeilScan](docs/img/reporte_pdf.png)

---

## Estado de componentes

Leyenda: ✅ Listo · 🚧 En progreso · ⬜ Pendiente

| Componente | Descripción | Fase | Estado |
|---|---|:---:|:---:|
| Modelo de datos | `Finding`, `TextSpan`, `ScanResult`, risk score ponderado | 1 | ✅ |
| CLI (`typer`) | `scan` / `sanitize` / `formats` / `mitre`, flags `--json` `--html` `--fail-on` | 1 | ✅ |
| Extractor **PDF** | texto casi blanco, fuente diminuta, off-page, `3 Tr`, OCG, JS, metadatos | 1 | ✅ |
| Extractor **DOCX** | `w:vanish`, color blanco, `w:sz`, comentarios, metadatos, alt-text | 1 | ✅ |
| Detector de divergencia | brecha vista-humano vs vista-IA | 1 | ✅ |
| Detector de patrones | frases de inyección bilingües (EN + ES), escala si el texto es oculto | 1 | ✅ |
| Detector Unicode | zero-width, bidi, tag block (decodificado), homoglifos | 1 | ✅ |
| Reporte terminal (`rich`) | tabla con severidad, técnica, ubicación, evidencia | 1 | ✅ |
| Reporte HTML (`jinja2`) | reporte autocontenido para adjuntar/portafolio | 1 | ✅ |
| Reporte PDF (`reportlab`) | reporte profesional adjuntable (evidencia/auditoría) | 2 | ✅ |
| Reporte de lote consolidado | un solo PDF con portada ejecutiva + un capítulo por archivo (`--pdf archivo.pdf` en modo lote) | 2 | ✅ |
| Sanitizador PDF | elimina metadatos `/Info`, XMP, JavaScript / OpenAction | 1 | ✅ |
| Tests + fixtures | `pytest` + generador de documentos maliciosos de prueba | 1 | ✅ |
| Extractor **XLSX** | hojas `veryHidden`, filas/cols ocultas, fuente blanca, formato `;;;`, comentarios, metadatos | 2 | ✅ |
| Extractor **PPTX** | shapes fuera del slide, slides ocultos, notas del orador, fuente diminuta/blanca, alt-text | 2 | ✅ |
| Sanitización profunda | eliminar runs ocultos, capas OCG, normalizar Unicode, reescritura (`veilscan sanitize --deep`) | 2 | ✅ |
| Validación magic-number / MIME | detectar spoofing de extensión antes de parsear (`veilscan/core/magic.py`) | 2 | ✅ |
| Capa "juez LLM" (opcional) | usa la API de Anthropic para explicar qué dice el texto oculto, construida defensivamente | 2 | ✅ |
| Atribución de `3 Tr` | extraer el texto invisible exacto por span, via el campo `alpha` de PyMuPDF | 2 | ✅ |
| Mapeo formal a MITRE ATT&CK | etiquetar cada hallazgo con su técnica oficial (crosswalk `veilscan/core/mitre.py`) | 2 | ✅ |
| Modo batch recursivo | escanea carpetas enteras y emite un resumen agregado | 2 | ✅ |
| GitHub Action | gate de CI listo para usar en pipelines (`.github/workflows/tests.yml`) | 2 | ✅ |

Fase 2 completa: todos los ítems del roadmap original están implementados.

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

# en lote, un solo PDF consolidado (portada + un capitulo por archivo)
veilscan scan ./documentos/ -r --pdf reporte_lote.pdf

# en lote, un PDF POR documento en vez de uno consolidado (apuntar a una carpeta)
veilscan scan ./documentos/ -r --pdf ./reportes/

# salida JSON (para integrar con otras tools)
veilscan scan cv.pdf --json

# generar reporte HTML
veilscan scan untrusted.pdf --html reporte.html

# generar reporte PDF (adjuntable como evidencia)
veilscan scan untrusted.pdf --pdf reporte.pdf

# usar como gate en CI: exit code != 0 si el riesgo llega a HIGH
veilscan scan untrusted.pdf --fail-on HIGH

# limpiar un PDF (Fase 1: metadatos + JS)
veilscan sanitize sucio.pdf --out limpio.pdf

# limpiar un PDF a fondo (Fase 2: + runs ocultos, capas OCG, Unicode invisible)
veilscan sanitize sucio.pdf --out limpio.pdf --deep

# ver el crosswalk completo VEIL-TXXX -> MITRE ATT&CK
veilscan mitre
```

### Sanitización profunda (`--deep`)

`sanitize` sin `--deep` (Fase 1) solo borra metadatos y JavaScript: seguro,
pero no toca el contenido de la página, así que un run de texto casi blanco o
una capa OCG apagada siguen ahí — un LLM que reciba ese PDF "limpio" sigue
leyendo la inyección igual. `--deep` (ver
[`veilscan/sanitizer/deep.py`](veilscan/sanitizer/deep.py)) va más allá y
reescribe el contenido en 4 pasos:

1. Fase 1 (metadatos + JavaScript).
2. Borra el contenido de las capas OCG ocultas y la definición de la capa
   misma (no solo la deja "apagada").
3. Redacta los runs de texto detectados como ocultos por heurística (casi
   blanco, fuente diminuta, fuera de página): se borra el dibujo real, no se
   tapa.
4. Los runs con Unicode invisible mezclado en texto por lo demás visible
   (zero-width, tag block, bidi override) se redactan y se reinsertan ya
   normalizados, en la misma posición y estilo.

Al final reescribe el PDF completo (no basta con borrar referencias; hay que
reconstruir el archivo para que los objetos ya sin uso no sigan viviendo
adentro). El resultado, vuelto a escanear con VeilScan, sale limpio:

```bash
veilscan sanitize cv_con_inyeccion.pdf --out cv_limpio.pdf --deep
veilscan scan cv_limpio.pdf
# -> CLEAN
```

Esto incluye el texto en modo de render invisible (operador `3 Tr`): antes se
confirmaba solo a nivel de página ("el operador está presente"); ahora se
atribuye por span exacto — ver la siguiente sección — así que `--deep`
también lo redacta. Solo en el caso raro de que el operador aparezca en el
stream sin que ningún span se pueda atribuir (fuente no estándar, texto
vacío) `--deep` lo advierte al final de la lista de acciones para revisión manual.

### Atribución de `3 Tr` (texto en modo de render invisible)

El operador `3 Tr` le dice al visor "no dibujes este texto en pantalla" —
pero un parser o un LLM lo sigue leyendo igual. El problema es que ese texto
suele tener color y tamaño de fuente completamente normales, así que las
otras heurísticas (casi blanco, fuente diminuta) no lo detectan por sí solas.

La solución no fue escribir un parser de content-stream propio: PyMuPDF ya
calcula, para cada fragmento de texto, un `alpha` (opacidad) efectivo —
`0` cuando el modo de render no pinta nada (`3 Tr` o `7 Tr`), `255` en
cualquier otro caso. Revisando ese campo por *span* (no solo si el operador
aparece en algún lugar de la página), VeilScan sabe exactamente **qué texto**
corresponde a cada aparición, lo marca oculto (`HideReason.INVISIBLE_RENDER`)
y lo deja fluir por el resto del pipeline: divergencia, patrones semánticos y
`--deep`, igual que cualquier otro texto oculto.

```bash
veilscan scan documento_con_3tr.pdf
# -> VEIL-T001 con "Via: invisible_render_mode" y el texto exacto en la evidencia,
#    en vez de un aviso generico de "el operador esta presente".
```

### Validación de magic-number (spoofing de extensión)

Antes de elegir cómo parsear un archivo, `scan` compara la extensión del
nombre contra la firma binaria real del contenido (ver
[`veilscan/core/magic.py`](veilscan/core/magic.py)). Esto detecta el truco de
renombrar un archivo para pasar filtros o engañar a un pipeline automatizado
— por ejemplo, un `.docx` con una macro renombrado a `informe.pdf`:

```bash
mv sospechoso.docx informe.pdf
veilscan scan informe.pdf
# -> VEIL-T010 (CRITICAL): la extension declarada no coincide con la firma binaria
#    y VeilScan sigue analizando el contenido real (docx), no el nombre.
```

Si la firma no coincide pero el contenido real es uno de los 4 formatos
soportados, VeilScan **sigue extrayendo con el extractor correcto** (más útil
que rendirse) y además deja el hallazgo `VEIL-T010` como evidencia del
disfraz. Si la firma no corresponde a nada reconocible (un ejecutable, una
imagen, un archivo corrupto), el escaneo se detiene con un error explícito en
vez de arriesgarse a parsear basura.

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
| VEIL-T010 | Spoofing de extensión (firma binaria no coincide) |

### Crosswalk a MITRE ATT&CK

Cada técnica VEIL se mapea a una o más técnicas oficiales de [MITRE ATT&CK
Enterprise](https://attack.mitre.org/), visible en la salida de terminal, HTML,
PDF y JSON, y consultable de forma completa con:

```bash
veilscan mitre
```

ATT&CK Enterprise se diseñó para intrusión en redes/endpoints, no para ataques
dirigidos a modelos de lenguaje, así que algunos mapeos son **directos** (p.ej.
`VEIL-T003` → `T1036.002 Right-to-Left Override`, una sub-técnica que coincide
exactamente) y otros son **análogos** — la técnica más cercana en espíritu,
marcada con `~` (p.ej. `VEIL-T005` → `T1059 Command and Scripting Interpreter`,
tratando al LLM como el intérprete al que se le inyectan comandos). El detalle
completo, con la justificación de cada mapeo, está en
[`veilscan/core/mitre.py`](veilscan/core/mitre.py).

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
