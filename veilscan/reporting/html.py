"""Reporte en HTML con jinja2 (un solo archivo autocontenido)."""

from __future__ import annotations

import datetime as _dt
import html

from jinja2 import Template

from veilscan.core.models import ScanResult

_TEMPLATE = Template("""<!DOCTYPE html>
<html lang="es"><head><meta charset="utf-8">
<title>VeilScan — {{ name }}</title>
<style>
  :root{--crit:#b00020;--high:#d32f2f;--med:#f9a825;--low:#0288d1;--clean:#2e7d32;}
  body{font-family:system-ui,Segoe UI,Roboto,sans-serif;margin:0;background:#0f1117;color:#e6e6e6;}
  header{padding:28px 32px;border-bottom:1px solid #262b36;}
  h1{margin:0;font-size:20px;letter-spacing:.5px;}
  .sub{color:#8a93a6;font-size:13px;margin-top:6px;}
  .badge{display:inline-block;padding:4px 12px;border-radius:999px;font-weight:700;font-size:13px;color:#fff;}
  .b-CRITICAL{background:var(--crit);} .b-HIGH{background:var(--high);}
  .b-MEDIUM{background:var(--med);color:#1a1a1a;} .b-LOW{background:var(--low);} .b-CLEAN{background:var(--clean);}
  main{padding:24px 32px;}
  .meta{color:#8a93a6;font-size:13px;margin-bottom:20px;}
  table{width:100%;border-collapse:collapse;font-size:14px;}
  th,td{text-align:left;padding:10px 12px;border-bottom:1px solid #262b36;vertical-align:top;}
  th{color:#8a93a6;font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.5px;}
  .sev{font-weight:700;font-size:12px;padding:2px 8px;border-radius:4px;color:#fff;white-space:nowrap;}
  .s-CRITICAL{background:var(--crit);} .s-HIGH{background:var(--high);}
  .s-MEDIUM{background:var(--med);color:#1a1a1a;} .s-LOW{background:var(--low);} .s-INFO{background:#555;}
  code{background:#1a1f2b;padding:2px 6px;border-radius:4px;font-size:13px;color:#9ecbff;word-break:break-all;}
  .clean{color:var(--clean);font-size:16px;padding:20px 0;}
  .llm{background:#161b26;border:1px solid #2a3550;border-radius:8px;padding:16px 18px;margin-bottom:22px;}
  .llm-head{font-size:13px;color:#b08cff;font-weight:700;margin-bottom:10px;text-transform:uppercase;letter-spacing:.5px;}
  .llm-model{color:#5a6173;font-weight:400;text-transform:none;}
  .verdict{display:inline-block;padding:3px 10px;border-radius:4px;font-weight:700;font-size:13px;color:#fff;}
  .v-malicious{background:var(--crit);} .v-suspicious{background:var(--med);color:#1a1a1a;} .v-benign{background:var(--clean);}
  .llm p{margin:10px 0 0;font-size:14px;line-height:1.5;}
  footer{padding:18px 32px;color:#5a6173;font-size:12px;border-top:1px solid #262b36;}
</style></head><body>
<header>
  <h1>VeilScan — Reporte de inyeccion oculta</h1>
  <div class="sub">{{ path }}</div>
  <div style="margin-top:14px">
    <span class="badge b-{{ label }}">{{ label }} · {{ score }}/100</span>
    <span class="sub">&nbsp;&nbsp;visible: {{ visible }} chars · oculto: {{ hidden }} chars · tipo: {{ ftype }}</span>
  </div>
</header>
<main>
{% if llm %}
  <div class="llm">
    <div class="llm-head">Juez LLM <span class="llm-model">{{ llm.model }}</span></div>
    {% if llm.available %}
      <span class="verdict v-{{ llm.verdict }}">{{ llm.verdict|upper }}</span>
      {% if llm.intent %}<span class="sub">&nbsp;Objetivo: {{ llm.intent }}</span>{% endif %}
      {% if llm.summary %}<p>{{ llm.summary }}</p>{% endif %}
      {% if llm.recommendation %}<p><strong>Recomendacion:</strong> {{ llm.recommendation }}</p>{% endif %}
    {% else %}
      <p class="sub">No disponible: {{ llm.error }}</p>
    {% endif %}
  </div>
{% endif %}
{% if findings %}
  <table>
    <thead><tr><th>#</th><th>Sev</th><th>Tecnica</th><th>Ubicacion</th><th>Hallazgo / Evidencia</th></tr></thead>
    <tbody>
    {% for f in findings %}
      <tr>
        <td>{{ loop.index }}</td>
        <td><span class="sev s-{{ f.sev }}">{{ f.sev }}</span></td>
        <td>{{ f.tech }}</td>
        <td>{{ f.loc }}</td>
        <td><strong>{{ f.title }}</strong><br><code>{{ f.evidence }}</code><br><span class="sub">{{ f.detail }}</span></td>
      </tr>
    {% endfor %}
    </tbody>
  </table>
{% else %}
  <div class="clean">✓ Sin hallazgos. Documento limpio.</div>
{% endif %}
</main>
<footer>Generado por VeilScan · {{ ts }} · Herramienta defensiva para uso autorizado. · Autor: Jorge Barrera Espinoza</footer>
</body></html>""")


def render(result: ScanResult) -> str:
    findings = [
        {
            "sev": f.severity.value,
            "tech": html.escape(f.technique.value.split(":")[0]),
            "loc": html.escape(f.location),
            "title": html.escape(f.title),
            "evidence": html.escape(f.evidence_preview(400)),
            "detail": html.escape(f.detail),
        }
        for f in sorted(result.findings, key=lambda x: -x.severity.weight)
    ]
    import os
    llm = None
    if result.llm is not None:
        llm = {
            "available": result.llm.available,
            "verdict": html.escape(result.llm.verdict),
            "summary": html.escape(result.llm.summary),
            "intent": html.escape(result.llm.intent),
            "recommendation": html.escape(result.llm.recommendation),
            "model": html.escape(result.llm.model),
            "error": html.escape(result.llm.error),
        }
    return _TEMPLATE.render(
        name=os.path.basename(result.path),
        path=html.escape(result.path),
        label=result.risk_label,
        score=result.risk_score,
        visible=result.visible_chars,
        hidden=result.hidden_chars,
        ftype=result.file_type,
        findings=findings,
        llm=llm,
        ts=_dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )
