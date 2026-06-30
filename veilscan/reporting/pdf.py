"""
Reporte en PDF con reportlab (Fase 2).

Genera un PDF profesional y autocontenido, pensado como evidencia adjuntable: un
encabezado con el veredicto de riesgo, las estadisticas de extraccion y una tabla
de hallazgos ordenados por gravedad. Maneja paginacion automatica.

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
}


def _styles():
    ss = getSampleStyleSheet()
    ss.add(ParagraphStyle("VTitle", parent=ss["Title"], fontSize=18, spaceAfter=2, alignment=TA_LEFT))
    ss.add(ParagraphStyle("VSub", parent=ss["Normal"], fontSize=9, textColor=colors.HexColor("#666666")))
    ss.add(ParagraphStyle("VCell", parent=ss["Normal"], fontSize=8, leading=10))
    ss.add(ParagraphStyle("VCellBold", parent=ss["Normal"], fontSize=8, leading=10, fontName="Helvetica-Bold"))
    ss.add(ParagraphStyle("VEvidence", parent=ss["Normal"], fontSize=7.5, leading=9,
                          textColor=colors.HexColor("#444444"), fontName="Courier"))
    return ss


def render(result: ScanResult, out_path: str) -> str:
    """Escribe el reporte PDF y devuelve la ruta."""
    ss = _styles()
    doc = SimpleDocTemplate(
        out_path, pagesize=A4,
        leftMargin=16 * mm, rightMargin=16 * mm,
        topMargin=16 * mm, bottomMargin=16 * mm,
        title=f"VeilScan - {os.path.basename(result.path)}",
        author="VeilScan",
    )
    story = []

    # --- Encabezado ---
    story.append(Paragraph("VeilScan &mdash; Reporte de inyeccion oculta", ss["VTitle"]))
    story.append(Paragraph(_esc(result.path), ss["VSub"]))
    story.append(Paragraph(
        "Generado: " + _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ss["VSub"]))
    story.append(Spacer(1, 8))

    # --- Caso error ---
    if result.error:
        story.append(_banner(f"ERROR: {_esc(result.error)}", colors.HexColor("#b00020"), ss))
        doc.build(story)
        return out_path

    # --- Banner de riesgo ---
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

    # --- Bloque del juez LLM (si se solicito) ---
    if result.llm is not None:
        story.extend(_llm_block(result.llm, ss))

    # --- Caso limpio ---
    if result.is_clean:
        story.append(Paragraph("Sin hallazgos. Documento limpio.", ss["VCellBold"]))
        story.append(Spacer(1, 6))
        story.append(_footer(ss))
        doc.build(story)
        return out_path

    # --- Tabla de hallazgos ---
    header = [Paragraph(h, ss["VCellBold"]) for h in
              ("#", "Sev", "Tecnica", "Ubicacion", "Hallazgo / Evidencia")]
    rows = [header]
    sev_cells = []  # para colorear la columna Sev por fila

    for i, f in enumerate(sorted(result.findings, key=lambda x: -x.severity.weight), 1):
        sev_para = Paragraph(f.severity.value, ss["VCellBold"])
        sev_cells.append((i, _SEV_COLOR[f.severity]))
        cell = Paragraph(
            f"<b>{_esc(f.title)}</b><br/><font face='Courier' size='7.5'>{_esc(f.evidence_preview(280))}</font>",
            ss["VCell"])
        rows.append([
            Paragraph(str(i), ss["VCell"]),
            sev_para,
            Paragraph(_esc(f.technique.value.split(':')[0]), ss["VCell"]),
            Paragraph(_esc(f.location), ss["VCell"]),
            cell,
        ])

    table = Table(rows, colWidths=[8 * mm, 16 * mm, 24 * mm, 30 * mm, 100 * mm], repeatRows=1)
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
    story.append(Spacer(1, 10))
    story.append(_footer(ss))

    doc.build(story)
    return out_path


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

    head_tbl = Table([[head]], colWidths=[168 * mm])
    head_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), verdict_color),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    elems.append(head_tbl)
    if inner:
        body_tbl = Table([[inner]], colWidths=[168 * mm])
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
    t = Table([[p]], colWidths=[168 * mm])
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
