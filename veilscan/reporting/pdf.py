"""
Reporte en PDF con reportlab (Fase 2).

Genera reportes profesionales y autocontenidos, pensados como evidencia
adjuntable: un encabezado con el veredicto de riesgo, las estadisticas de
extraccion y una tabla de hallazgos ordenados por gravedad. Maneja paginacion
automatica.

Dos formas de generarlo:
  - render(result, out_path)                 -> un PDF, un archivo.
  - render_batch(results, summary, out_path) -> un solo PDF para TODO un lote:
    portada con el resumen agregado (cuantos archivos por nivel de riesgo,
    cuales son los mas riesgosos) y despues, un capitulo por archivo (salto de
    pagina + el mismo detalle que generaria render() para ese archivo solo).

    Por que importa: escanear una carpeta con --pdf antes generaba UN PDF POR
    ARCHIVO. Para una auditoria de "reviso esta carpeta de 40 CVs", eso son 40
    archivos sueltos que hay que adjuntar o comprimir a mano. Un solo PDF
    consolidado es lo que de verdad se adjunta a un correo o se sube a un
    ticket: una portada ejecutiva + el detalle de cada archivo, en orden,
    dentro del mismo documento.

Nota: reportlab NO incluye glifos para sub/superindices Unicode; por eso todo el
texto usa caracteres ASCII normales.
"""

from __future__ import annotations

import datetime as _dt
import os

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from veilscan.core.models import ScanResult, Severity

# Paleta por gravedad (tema claro, apto para imprimir/adjuntar)
_SEV_COLOR = {
    Severity.CRITICAL: colors.HexColor("#b00020"),
    Severity.HIGH: colors.HexColor("#d32f2f"),
    Severity.MEDIUM: colors.HexColor("#f9a825"),
    Severity.LOW: colors.HexColor("#0288d1"),
    Severity.INFO: colors.HexColor("#777777"),
}
_RISK_COLOR = {
    "CRITICAL": colors.HexColor("#b00020"),
    "HIGH": colors.HexColor("#d32f2f"),
    "MEDIUM": colors.HexColor("#f9a825"),
    "LOW": colors.HexColor("#0288d1"),
    "CLEAN": colors.HexColor("#2e7d32"),
    "ERROR": colors.HexColor("#777777"),
}
_PAGE_CONTENT_WIDTH = 178 * mm  # A4 (210mm) menos 16mm de margen a cada lado


def _styles():
    ss = getSampleStyleSheet()
    ss.add(ParagraphStyle("VTitle", parent=ss["Title"], fontSize=18, spaceAfter=2, alignment=TA_LEFT))
    ss.add(ParagraphStyle("VFileTitle", parent=ss["Title"], fontSize=13, spaceAfter=1, alignment=TA_LEFT))
    ss.add(ParagraphStyle("VSub", parent=ss["Normal"], fontSize=9, textColor=colors.HexColor("#666666")))
    ss.add(ParagraphStyle("VCell", parent=ss["Normal"], fontSize=8, leading=10))
    ss.add(ParagraphStyle("VCellBold", parent=ss["Normal"], fontSize=8, leading=10, fontName="Helvetica-Bold"))
    ss.add(ParagraphStyle("VEvidence", parent=ss["Normal"], fontSize=7.5, leading=9,
                          textColor=colors.HexColor("#444444"), fontName="Courier"))
    return ss


def render(result: ScanResult, out_path: str) -> str:
    """Escribe el reporte PDF de UN archivo y devuelve la ruta."""
    ss = _styles()
    doc = SimpleDocTemplate(
        out_path, pagesize=A4,
        leftMargin=16 * mm, rightMargin=16 * mm,
        topMargin=16 * mm, bottomMargin=16 * mm,
        title=f"VeilScan - {os.path.basename(result.path)}",
        author="VeilScan",
    )
    story = [
        Paragraph("VeilScan &mdash; Reporte de inyeccion oculta", ss["VTitle"]),
        Paragraph("Generado: " + _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ss["VSub"]),
        Spacer(1, 10),
    ]
    story.extend(_result_story(result, ss, show_filename_heading=False))
    story.append(_footer(ss))
    doc.build(story)
    return out_path


def render_batch(results: list[ScanResult], summary, out_path: str) -> str:
    """Escribe UN solo reporte PDF consolidado para un lote de archivos.

    `summary` es el `BatchSummary` de `veilscan.core.batch.summarize()`.
    """
    ss = _styles()
    doc = SimpleDocTemplate(
        out_path, pagesize=A4,
        leftMargin=16 * mm, rightMargin=16 * mm,
        topMargin=16 * mm, bottomMargin=16 * mm,
        title="VeilScan - Reporte de lote",
        author="VeilScan",
    )
    story = []

    # --- Portada: resumen ejecutivo del lote completo ---
    story.append(Paragraph("VeilScan &mdash; Reporte consolidado de lote", ss["VTitle"]))
    story.append(Paragraph("Generado: " + _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ss["VSub"]))
    story.append(Paragraph(f"Archivos escaneados: {summary.total}", ss["VSub"]))
    story.append(Spacer(1, 12))
    story.extend(_batch_summary_block(summary, ss))
    story.append(Spacer(1, 6))
    story.append(_footer(ss))

    # --- Un capitulo por archivo, con salto de pagina, en orden de escaneo ---
    for result in results:
        story.append(PageBreak())
        story.extend(_result_story(result, ss, show_filename_heading=True))

    doc.build(story)
    return out_path


def _batch_summary_block(summary, ss) -> list:
    """Tabla de conteos por nivel + tabla de archivos riesgosos + errores, para la portada del lote."""
    elems = []
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "CLEAN", "ERROR"]

    # conteo por nivel de riesgo
    present = [lbl for lbl in order if summary.by_label.get(lbl, 0)]
    rows = [[Paragraph(h, ss["VCellBold"]) for h in ("Nivel", "Archivos")]]
    for label in present:
        rows.append([Paragraph(label, ss["VCellBold"]), Paragraph(str(summary.by_label[label]), ss["VCell"])])
    count_tbl = Table(rows, colWidths=[45 * mm, 30 * mm])
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2430")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cccccc")),
        ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]
    for i, label in enumerate(present, 1):
        style.append(("TEXTCOLOR", (0, i), (0, i), _RISK_COLOR.get(label, colors.black)))
    count_tbl.setStyle(TableStyle(style))
    elems.append(count_tbl)
    elems.append(Spacer(1, 14))

    # archivos con riesgo, ordenados de mas a menos grave (ya vienen asi en summary.risky)
    if summary.risky:
        elems.append(Paragraph("Archivos con riesgo", ss["VCellBold"]))
        elems.append(Spacer(1, 4))
        rrows = [[Paragraph(h, ss["VCellBold"]) for h in ("Riesgo", "Score", "Archivo")]]
        for path, label, score in summary.risky:
            rrows.append([
                Paragraph(label, ss["VCellBold"]),
                Paragraph(f"{score}/100", ss["VCell"]),
                Paragraph(_esc(path), ss["VCell"]),
            ])
        rtable = Table(rrows, colWidths=[22 * mm, 18 * mm, _PAGE_CONTENT_WIDTH - 40 * mm], repeatRows=1)
        rstyle = [
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cccccc")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2430")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]
        for i, (_path, label, _score) in enumerate(summary.risky, 1):
            rstyle.append(("TEXTCOLOR", (0, i), (0, i), _RISK_COLOR.get(label, colors.black)))
        rtable.setStyle(TableStyle(rstyle))
        elems.append(rtable)
        elems.append(Spacer(1, 14))
    else:
        elems.append(Paragraph("Ningun archivo presento hallazgos. Lote limpio.", ss["VCellBold"]))
        elems.append(Spacer(1, 14))

    # errores de extraccion, si hubo
    if summary.errors:
        elems.append(Paragraph("Errores", ss["VCellBold"]))
        elems.append(Spacer(1, 4))
        erows = [[Paragraph(h, ss["VCellBold"]) for h in ("Archivo", "Motivo")]]
        for path, err in summary.errors:
            erows.append([Paragraph(_esc(path), ss["VCell"]), Paragraph(_esc(err), ss["VCell"])])
        etable = Table(erows, colWidths=[70 * mm, _PAGE_CONTENT_WIDTH - 70 * mm], repeatRows=1)
        etable.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cccccc")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        elems.append(etable)

    return elems


def _result_story(result: ScanResult, ss, show_filename_heading: bool) -> list:
    """Construye los flowables del detalle de UN archivo: banner de riesgo,
    estadisticas, bloque del juez LLM y tabla de hallazgos.

    Es el "capitulo" que tanto `render()` (un archivo, un PDF) como
    `render_batch()` (muchos archivos, un PDF) reutilizan sin duplicar logica:
    asi el detalle de un archivo se ve identico este solo o dentro de un lote.

    `show_filename_heading` controla si se imprime el nombre del archivo como
    titulo de seccion: en `render()` el titulo del documento ya lo dice, pero
    en `render_batch()` cada capitulo necesita su propio encabezado.
    """
    story = []

    if show_filename_heading:
        story.append(Paragraph(_esc(os.path.basename(result.path)), ss["VFileTitle"]))
        story.append(Spacer(1, 2))
    story.append(Paragraph(_esc(result.path), ss["VSub"]))
    story.append(Spacer(1, 8))

    if result.error:
        story.append(_banner(f"ERROR: {_esc(result.error)}", colors.HexColor("#b00020"), ss))
        return story

    label = result.risk_label
    banner_text = f"RIESGO: {label}  &mdash;  {result.risk_score}/100"
    story.append(_banner(banner_text, _RISK_COLOR.get(label, colors.grey), ss))
    story.append(Spacer(1, 6))

    stats = (f"Tipo: {result.file_type}   |   "
             f"Texto visible: {result.visible_chars} chars   |   "
             f"Texto oculto: {result.hidden_chars} chars   |   "
             f"Hallazgos: {len(result.findings)}")
    story.append(Paragraph(stats, ss["VSub"]))
    story.append(Spacer(1, 12))

    if result.llm is not None:
        story.extend(_llm_block(result.llm, ss))

    if result.is_clean:
        story.append(Paragraph("Sin hallazgos. Documento limpio.", ss["VCellBold"]))
        story.append(Spacer(1, 6))
        return story

    # --- Tabla de hallazgos ---
    header = [Paragraph(h, ss["VCellBold"]) for h in
              ("#", "Sev", "Tecnica", "ATT&CK", "Ubicacion", "Hallazgo / Evidencia")]
    rows = [header]
    sev_cells = []  # para colorear la columna Sev por fila

    for i, f in enumerate(sorted(result.findings, key=lambda x: -x.severity.weight), 1):
        sev_para = Paragraph(f.severity.value, ss["VCellBold"])
        sev_cells.append((i, _SEV_COLOR[f.severity]))
        cell = Paragraph(
            f"<b>{_esc(f.title)}</b><br/><font face='Courier' size='7.5'>{_esc(f.evidence_preview(280))}</font>",
            ss["VCell"])
        mitre_list = f.mitre
        if mitre_list:
            m = mitre_list[0]
            mark = "" if m.confidence == "direct" else "~"
            mitre_text = f"<font face='Courier'>{_esc(m.id)}{mark}</font>"
        else:
            mitre_text = "-"
        rows.append([
            Paragraph(str(i), ss["VCell"]),
            sev_para,
            Paragraph(_esc(f.technique.value.split(':')[0]), ss["VCell"]),
            Paragraph(mitre_text, ss["VCell"]),
            Paragraph(_esc(f.location), ss["VCell"]),
            cell,
        ])

    table = Table(rows, colWidths=[7 * mm, 14 * mm, 22 * mm, 16 * mm, 25 * mm, 94 * mm], repeatRows=1)
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2430")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cccccc")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f6f8")]),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]
    # color del texto de la columna Sev segun gravedad
    for row_idx, color in sev_cells:
        style.append(("TEXTCOLOR", (1, row_idx), (1, row_idx), color))
    table.setStyle(TableStyle(style))
    story.append(table)
    story.append(Spacer(1, 4))
    story.append(Paragraph(
        "ATT&amp;CK: id sin marca = correspondencia directa &middot; id con ~ = mapeo analogo "
        "(sin equivalente exacto en ATT&amp;CK Enterprise)", ss["VSub"]))
    story.append(Spacer(1, 6))
    return story


def _llm_block(a, ss) -> list:
    """Construye el bloque visual del veredicto del juez LLM."""
    elems = []
    if not a.available:
        elems.append(Paragraph(f"<b>Juez LLM</b> &mdash; no disponible: {_esc(a.error)}", ss["VSub"]))
        elems.append(Spacer(1, 10))
        return elems

    verdict_color = {
        "malicious": colors.HexColor("#b00020"),
        "suspicious": colors.HexColor("#f9a825"),
        "benign": colors.HexColor("#2e7d32"),
    }.get(a.verdict, colors.grey)

    head = Paragraph(
        f"<font color='white'><b>JUEZ LLM &mdash; Veredicto: {_esc(a.verdict.upper())}</b></font>"
        f"<font color='#dddddd' size='8'>   ({_esc(a.model)})</font>",
        ss["Normal"])
    inner = []
    if a.intent:
        inner.append(Paragraph(f"<b>Objetivo:</b> {_esc(a.intent)}", ss["VCell"]))
    if a.summary:
        inner.append(Paragraph(_esc(a.summary), ss["VCell"]))
    if a.recommendation:
        inner.append(Paragraph(f"<b>Recomendacion:</b> {_esc(a.recommendation)}", ss["VCell"]))

    head_tbl = Table([[head]], colWidths=[_PAGE_CONTENT_WIDTH])
    head_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), verdict_color),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    elems.append(head_tbl)
    if inner:
        body_tbl = Table([[inner]], colWidths=[_PAGE_CONTENT_WIDTH])
        body_tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f3f0fa")),
            ("BOX", (0, 0), (-1, -1), 0.5, verdict_color),
            ("LEFTPADDING", (0, 0), (-1, -1), 8), ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        elems.append(body_tbl)
    elems.append(Spacer(1, 12))
    return elems


def _banner(text: str, color, ss) -> Table:
    p = Paragraph(f"<font color='white'><b>{text}</b></font>", ss["Normal"])
    t = Table([[p]], colWidths=[_PAGE_CONTENT_WIDTH])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), color),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    return t


def _footer(ss) -> Paragraph:
    return Paragraph(
        "Generado por VeilScan. Herramienta defensiva para uso autorizado. "
        "&nbsp;&middot;&nbsp; Autor: Jorge Barrera Espinoza",
        ss["VSub"])


def _esc(text: str) -> str:
    """Escapa caracteres que reportlab interpreta como markup."""
    return (str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))
