"""Reporte en terminal con rich."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from veilscan.core.models import ScanResult, Severity

_SEV_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}
_RISK_STYLE = {
    "CRITICAL": "bold white on red",
    "HIGH": "bold red",
    "MEDIUM": "bold yellow",
    "LOW": "cyan",
    "CLEAN": "bold green",
}


def render_summary(summary, console: Console | None = None) -> None:
    """Resumen agregado de un escaneo en lote."""
    console = console or Console()

    head = Text()
    head.append(f"Escaneados: {summary.total} archivo(s)\n", style="bold")
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "CLEAN", "ERROR"]
    for label in order:
        n = summary.by_label.get(label, 0)
        if n:
            head.append("  " + label.ljust(9), style=_RISK_STYLE.get(label, "white"))
            head.append(f": {n}\n")
    console.print(Panel(head, title="VeilScan — Resumen de lote", border_style="cyan"))

    if summary.risky:
        table = Table(show_lines=False, expand=True, title="Archivos con riesgo")
        table.add_column("Riesgo", width=10)
        table.add_column("Score", justify="right", width=7)
        table.add_column("Archivo", overflow="fold")
        for path, label, score in summary.risky:
            table.add_row(Text(label, style=_RISK_STYLE.get(label, "white")), f"{score}/100", path)
        console.print(table)

    if summary.errors:
        etable = Table(show_lines=False, expand=True, title="Errores")
        etable.add_column("Archivo", width=40, overflow="fold")
        etable.add_column("Motivo", overflow="fold")
        for path, err in summary.errors:
            etable.add_row(path, err)
        console.print(etable)

    if not summary.risky and not summary.errors:
        console.print("[green]Ningun archivo presento hallazgos. Lote limpio.[/green]")
    console.print()


def render(result: ScanResult, console: Console | None = None) -> None:
    console = console or Console()

    if result.error:
        console.print(Panel(f"[red]{result.error}[/red]", title=result.path, border_style="red"))
        return

    label = result.risk_label
    header = Text()
    header.append(f"{result.path}\n", style="bold")
    header.append("Risk: ")
    header.append(f"{label} ({result.risk_score}/100)", style=_RISK_STYLE.get(label, "white"))
    header.append(f"   visible: {result.visible_chars} chars   oculto: {result.hidden_chars} chars")
    console.print(Panel(header, title="VeilScan", border_style=_RISK_STYLE.get(label, "white")))

    if result.is_clean:
        console.print("[green]Sin hallazgos. Documento limpio.[/green]\n")
        _render_llm(result, console)
        return

    table = Table(show_lines=True, expand=True)
    table.add_column("#", justify="right", width=3)
    table.add_column("Sev", width=9)
    table.add_column("Tecnica", width=22)
    table.add_column("ATT&CK", width=12)
    table.add_column("Ubicacion", width=20)
    table.add_column("Evidencia", overflow="fold")

    for i, f in enumerate(sorted(result.findings, key=lambda x: -x.severity.weight), 1):
        sev = Text(f.severity.value, style=_SEV_STYLE[f.severity])
        tech = f.technique.value.split(":")[0]  # solo el codigo VEIL-TXXX
        mitre = f.mitre
        if mitre:
            m = mitre[0]
            mark = "" if m.confidence == "direct" else "~"
            attck = Text(f"{m.id}{mark}")
        else:
            attck = Text("-", style="dim")
        table.add_row(str(i), sev, tech, attck, f.location, f"{f.title}\n[dim]{f.evidence_preview(180)}[/dim]")

    console.print(table)
    console.print("[dim]ATT&CK: id sin marca = correspondencia directa · id con ~ = mapeo analogo "
                  "(sin equivalente exacto en ATT&CK Enterprise, ver docs)[/dim]")
    console.print()
    _render_llm(result, console)


_VERDICT_STYLE = {
    "malicious": "bold white on red",
    "suspicious": "bold yellow",
    "benign": "bold green",
}


def _render_llm(result, console) -> None:
    if result.llm is None:
        return
    a = result.llm
    if not a.available:
        console.print(f"[dim]Juez LLM no disponible: {a.error}[/dim]\n")
        return
    body = Text()
    body.append("Veredicto: ")
    body.append(f"{a.verdict.upper()}\n", style=_VERDICT_STYLE.get(a.verdict, "bold"))
    if a.intent:
        body.append("Objetivo: ", style="bold")
        body.append(f"{a.intent}\n")
    if a.summary:
        body.append("\n" + a.summary + "\n")
    if a.recommendation:
        body.append("\nRecomendacion: ", style="bold")
        body.append(a.recommendation)
    console.print(Panel(body, title=f"Juez LLM ({a.model})", border_style="magenta"))
    console.print()
