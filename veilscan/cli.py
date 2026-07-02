"""
CLI de VeilScan.

Ejemplos:
    veilscan scan documento.pdf
    veilscan scan *.docx --json
    veilscan scan cv.pdf --html reporte.html
    veilscan scan ./carpeta/ -r --pdf reporte_lote.pdf   # 1 PDF consolidado para todo el lote
    veilscan scan untrusted.pdf --fail-on HIGH    # exit!=0 para pipelines CI
"""

from __future__ import annotations

import json as _json
import sys

import typer
from rich.console import Console

from veilscan.core import scanner
from veilscan.core.models import Severity
from veilscan.reporting import html as html_report
from veilscan.reporting import terminal as terminal_report

app = typer.Typer(add_completion=False, help="VeilScan — detector de inyeccion de prompt oculta en documentos.")
console = Console()

_LEVELS = {"LOW": 3, "MEDIUM": 15, "HIGH": 40, "CRITICAL": 70}


@app.command()
def scan(
    paths: list[str] = typer.Argument(..., help="Archivos o carpetas a analizar (.pdf, .docx, .xlsx, .pptx)."),
    recursive: bool = typer.Option(False, "--recursive", "-r", help="Recorre subcarpetas al pasar un directorio."),
    details: bool = typer.Option(False, "--details", help="En lote, muestra tambien la tabla completa de cada archivo."),
    json_out: bool = typer.Option(False, "--json", help="Salida en JSON en vez de tabla."),
    html_out: str = typer.Option(None, "--html", help="Escribe un reporte HTML en la ruta dada."),
    pdf_out: str = typer.Option(None, "--pdf", help="Ruta .pdf -> un reporte consolidado del lote. Ruta de carpeta -> un PDF por archivo."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Solo muestra archivos con hallazgos."),
    use_llm: bool = typer.Option(False, "--llm", help="Activa el juez LLM (explica el texto oculto). Requiere ANTHROPIC_API_KEY."),
    llm_model: str = typer.Option(None, "--llm-model", help="Modelo a usar para el juez (default: claude-haiku-4-5)."),
    fail_on: str = typer.Option(None, "--fail-on", help="Nivel minimo que provoca exit code !=0 (LOW/MEDIUM/HIGH/CRITICAL)."),
):
    """Analiza documentos (o carpetas enteras) en busca de inyeccion de prompt oculta."""
    from veilscan.core import batch

    # ¿se paso al menos una carpeta? -> modo lote
    is_batch = any(__import__("os").path.isdir(p) for p in paths)
    files = batch.expand_paths(paths, recursive=recursive)

    if not files:
        console.print("[yellow]No se encontraron archivos de formato soportado.[/yellow]")
        raise typer.Exit(0)

    results = [scanner.scan_file(p, use_llm=use_llm, llm_model=llm_model) for p in files]

    if json_out:
        out = {"summary": batch.summarize(results).to_dict(),
               "results": [r.to_dict() for r in results]}
        console.print_json(_json.dumps(out))
    else:
        # en lote, por defecto NO imprimimos 200 tablas: solo el resumen
        # (a menos que se pida --details o haya un solo archivo)
        show_detail = details or (not is_batch and len(results) <= 3)
        if show_detail:
            for r in results:
                if quiet and r.is_clean:
                    continue
                terminal_report.render(r, console)
        if is_batch or len(results) > 1:
            terminal_report.render_summary(batch.summarize(results), console)

    if html_out:
        body = "\n<hr>\n".join(html_report.render(r) for r in results)
        with open(html_out, "w", encoding="utf-8") as fh:
            fh.write(body)
        console.print(f"[green]Reporte HTML escrito en {html_out}[/green]")

    if pdf_out:
        from veilscan.reporting import pdf as pdf_report
        import os as _os

        if len(results) == 1:
            pdf_report.render(results[0], pdf_out)
            console.print(f"[green]Reporte PDF escrito en {pdf_out}[/green]")
        elif _os.path.isdir(pdf_out) or not pdf_out.lower().endswith(".pdf"):
            # --pdf apunta a una CARPETA: un PDF por archivo, nombrado segun el
            # documento de origen (util para adjuntar/archivar cada uno por separado).
            outdir = pdf_out
            _os.makedirs(outdir, exist_ok=True)
            for r in results:
                base = _os.path.basename(r.path)
                # se incluye la extension original en el nombre de salida: sin esto,
                # "benign.pdf" y "benign.docx" en la misma carpeta generarian el
                # mismo archivo de salida y uno pisaria al otro.
                stem = base.replace(".", "_")
                path_i = _os.path.join(outdir, f"{stem}_veilscan.pdf")
                pdf_report.render(r, path_i)
            console.print(f"[green]{len(results)} reportes PDF escritos en {outdir}/[/green]")
        else:
            # --pdf apunta a un ARCHIVO .pdf concreto: un unico reporte
            # consolidado (portada con el resumen del lote + un capitulo por
            # archivo), pensado para adjuntar como UN documento de evidencia.
            pdf_report.render_batch(results, batch.summarize(results), pdf_out)
            console.print(f"[green]Reporte PDF consolidado ({len(results)} archivos) escrito en {pdf_out}[/green]")

    # codigo de salida para CI (peor archivo del lote)
    if fail_on:
        threshold = _LEVELS.get(fail_on.upper())
        if threshold is None:
            console.print(f"[red]--fail-on invalido: {fail_on}[/red]")
            raise typer.Exit(2)
        worst = max((r.risk_score for r in results), default=0)
        if worst >= threshold:
            raise typer.Exit(1)
    raise typer.Exit(0)


@app.command()
def sanitize(
    path: str = typer.Argument(..., help="PDF a limpiar."),
    out: str = typer.Option(..., "--out", "-o", help="Ruta del PDF de salida."),
):
    """Genera una copia mas limpia de un PDF (Fase 1: metadatos y JavaScript)."""
    from veilscan.sanitizer.pdf_sanitizer import sanitize_pdf

    if not path.lower().endswith(".pdf"):
        console.print("[red]La sanitizacion en Fase 1 solo soporta PDF.[/red]")
        raise typer.Exit(2)
    actions = sanitize_pdf(path, out)
    console.print(f"[green]Copia sanitizada escrita en {out}[/green]")
    for a in actions:
        console.print(f"  - {a}")


@app.command()
def formats():
    """Lista los formatos soportados."""
    console.print("Formatos soportados:", ", ".join(scanner.supported_extensions()))


@app.command()
def mitre():
    """Muestra el crosswalk completo VEIL-TXXX -> MITRE ATT&CK."""
    from rich.table import Table

    from veilscan.core.mitre import full_crosswalk

    table = Table(title="VeilScan — Crosswalk MITRE ATT&CK", show_lines=True, expand=True)
    table.add_column("VEIL", width=12)
    table.add_column("ATT&CK", width=14)
    table.add_column("Tecnica ATT&CK", overflow="fold")
    table.add_column("Tactica", width=20)
    table.add_column("Conf.", width=10)

    for technique, mapped in full_crosswalk():
        veil_code = technique.value.split(":")[0]
        if not mapped:
            table.add_row(veil_code, "-", "-", "-", "-")
            continue
        for i, m in enumerate(mapped):
            conf_style = "green" if m.confidence == "direct" else "yellow"
            table.add_row(
                veil_code if i == 0 else "",
                m.id,
                m.name,
                m.tactic,
                f"[{conf_style}]{m.confidence}[/{conf_style}]",
            )
    console.print(table)
    console.print("[dim]direct = correspondencia 1:1 con ATT&CK · analogous = mapeo conceptual "
                  "(ATT&CK Enterprise no cubre ataques dirigidos a LLMs de forma nativa)[/dim]")


def main():
    app()


if __name__ == "__main__":
    main()
