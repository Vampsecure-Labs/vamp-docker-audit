# © VampSecure Studios — VampSecure Labs Security Research Division
"""
_report.py — Report generation (console Rich, JSON, HTML) and VSL conversion
             for vamp-docker-audit.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from html import escape

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ._models import (
    VERSION,
    TOOL_NAME,
    SEVERITY_ORDER,
    SEVERITY_COLOR,
    Finding,
    ContainerAuditResult,
    DockerAuditResult,
)
from vampsec_report import (
    Finding as VSLFinding,
)
from vampsec_report import (
    VampSecReport,
    add_report_args,
    meta_from_args,
)


class DockerReporter:
    """
    Genera la salida en consola, JSON y HTML de la auditoría Docker.

    Produce paneles Rich por contenedor con hallazgos coloreados por severidad,
    una tabla resumen global y exportaciones opcionales.
    """

    def __init__(self, cons: Console) -> None:
        self._c = cons

    # ── Consola ────────────────────────────────────────────────────────────

    def print_env_error(self, error: str) -> None:
        """Muestra el error fatal de acceso al entorno Docker."""
        self._c.print(
            Panel(
                f"[bold red]{error}[/bold red]",
                title="[bold red]ERROR DE ENTORNO[/bold red]",
                border_style="red",
            )
        )

    def print_env_info(self, resultado: DockerAuditResult) -> None:
        """Muestra la información básica del entorno Docker auditado."""
        self._c.print(f"\n[bold cyan]Host:[/]         [white]{resultado.host}[/]")
        self._c.print(f"[bold cyan]Docker:[/]       [white]{resultado.docker_version}[/]")
        self._c.print(
            f"[bold cyan]Contenedores:[/] [white]{len(resultado.containers)}[/] "
            f"auditados\n"
        )

    def print_container(self, car: ContainerAuditResult) -> None:
        """Muestra el panel de hallazgos de un contenedor individual."""
        sev_color = SEVERITY_COLOR.get(car.max_severity, "white")

        if not car.findings:
            self._c.print(
                Panel(
                    "[bold green]Sin hallazgos de seguridad[/bold green]",
                    title=(
                        f"[bold]{car.container_name}[/bold] [{sev_color}]"
                        f"{car.max_severity}[/{sev_color}]"
                    ),
                    border_style="green",
                    expand=False,
                )
            )
            return

        tbl = Table(show_header=True, header_style="bold cyan", box=None, padding=(0, 1))
        tbl.add_column("ID",          width=10)
        tbl.add_column("SEV",         width=10)
        tbl.add_column("Categoría",   width=14)
        tbl.add_column("Hallazgo",    min_width=36)
        tbl.add_column("Evidencia",   min_width=28)

        for f in car.findings:
            color = SEVERITY_COLOR.get(f.severity, "white")
            tbl.add_row(
                Text(f.id,         style="dim"),
                Text(f.severity,   style=color),
                Text(f.category),
                Text(f.title),
                Text(f.evidence[:80] if f.evidence else "—"),
            )

        self._c.print(
            Panel(
                tbl,
                title=(
                    f"[bold]{car.container_name}[/bold] "
                    f"[dim]({car.image})[/dim]  "
                    f"[{sev_color}]{car.max_severity}[/{sev_color}]"
                ),
                border_style=sev_color.replace("bold ", ""),
            )
        )

        crits = [f for f in car.findings if f.severity in ("CRITICAL", "HIGH") and f.remediation]
        if crits:
            for f in crits:
                color = SEVERITY_COLOR.get(f.severity, "white")
                self._c.print(
                    Panel(
                        f.remediation,
                        title=f"[{color}]{f.severity}[/{color}] — {f.title}",
                        border_style="cyan",
                        expand=False,
                    )
                )

    def print_extra_findings(
        self,
        titulo: str,
        findings: list[Finding],
    ) -> None:
        """Muestra hallazgos de imágenes, redes o ENV en un panel dedicado."""
        if not findings:
            return

        tbl = Table(show_header=True, header_style="bold cyan", box=None, padding=(0, 1))
        tbl.add_column("ID",        width=10)
        tbl.add_column("SEV",       width=10)
        tbl.add_column("Hallazgo",  min_width=44)
        tbl.add_column("Evidencia", min_width=28)

        for f in findings:
            color = SEVERITY_COLOR.get(f.severity, "white")
            tbl.add_row(
                Text(f.id,       style="dim"),
                Text(f.severity, style=color),
                Text(f.title),
                Text(f.evidence[:80] if f.evidence else "—"),
            )

        max_sev = min(findings, key=lambda f: f.order).severity
        border_color = SEVERITY_COLOR.get(max_sev, "white").replace("bold ", "")
        self._c.print(Panel(tbl, title=titulo, border_style=border_color))

    def print_summary(self, resultado: DockerAuditResult) -> None:
        """Tabla resumen global de todos los contenedores auditados."""
        self._c.print("\n")
        tbl = Table(
            title="Resumen de Auditoría Docker",
            header_style="bold cyan",
            show_lines=True,
        )
        tbl.add_column("Contenedor",  min_width=22)
        tbl.add_column("Imagen",      min_width=26)
        tbl.add_column("Estado",      width=10)
        tbl.add_column("CRIT",        width=6)
        tbl.add_column("HIGH",        width=6)
        tbl.add_column("MED",         width=6)
        tbl.add_column("LOW",         width=6)
        tbl.add_column("INFO",        width=6)
        tbl.add_column("Total",       width=7)
        tbl.add_column("Sev. máx.",   width=10)

        for car in resultado.containers:
            sev_col = SEVERITY_COLOR.get(car.max_severity, "white")
            tbl.add_row(
                f"[bold]{car.container_name}[/bold]",
                car.image[:32],
                car.status,
                str(car.count_by_severity("CRITICAL")),
                str(car.count_by_severity("HIGH")),
                str(car.count_by_severity("MEDIUM")),
                str(car.count_by_severity("LOW")),
                str(car.count_by_severity("INFO")),
                str(len(car.findings)),
                f"[{sev_col}]{car.max_severity}[/{sev_col}]",
            )

        all_f = resultado.all_findings
        tbl.add_row(
            "[bold dim]── GLOBAL ──[/]",
            "",
            "",
            str(sum(1 for f in all_f if f.severity == "CRITICAL")),
            str(sum(1 for f in all_f if f.severity == "HIGH")),
            str(sum(1 for f in all_f if f.severity == "MEDIUM")),
            str(sum(1 for f in all_f if f.severity == "LOW")),
            str(sum(1 for f in all_f if f.severity == "INFO")),
            str(len(all_f)),
            "",
        )

        self._c.print(tbl)

    # ── JSON ───────────────────────────────────────────────────────────────

    def to_json(self, resultado: DockerAuditResult) -> str:
        """Serializa el resultado completo de la auditoría en formato JSON."""
        def _finding_dict(f: Finding) -> dict:
            return {
                "id":          f.id,
                "severity":    f.severity,
                "category":    f.category,
                "title":       f.title,
                "description": f.description,
                "evidence":    f.evidence,
                "remediation": f.remediation,
                "container":   f.container,
            }

        def _container_dict(car: ContainerAuditResult) -> dict:
            return {
                "id":           car.container_id,
                "name":         car.container_name,
                "image":        car.image,
                "status":       car.status,
                "max_severity": car.max_severity,
                "findings":     [_finding_dict(f) for f in car.findings],
            }

        all_f = resultado.all_findings
        by_sev = {s: sum(1 for f in all_f if f.severity == s) for s in SEVERITY_ORDER}

        return json.dumps(
            {
                "tool":           TOOL_NAME,
                "version":        VERSION,
                "generated":      datetime.now(timezone.utc).isoformat(),
                "host":           resultado.host,
                "docker_version": resultado.docker_version,
                "error":          resultado.error,
                "summary": {
                    "total_findings":     len(all_f),
                    "max_severity":       resultado.max_severity,
                    "by_severity":        by_sev,
                    "containers_audited": len(resultado.containers),
                },
                "containers":       [_container_dict(c) for c in resultado.containers],
                "image_findings":   [_finding_dict(f) for f in resultado.image_findings],
                "network_findings": [_finding_dict(f) for f in resultado.network_findings],
                "env_findings":     [_finding_dict(f) for f in resultado.env_findings],
            },
            indent=2,
            ensure_ascii=False,
        )

    # ── HTML dark-theme ────────────────────────────────────────────────────

    def to_html(self, resultado: DockerAuditResult) -> str:
        """Genera un informe HTML standalone con tema oscuro profesional."""
        SEV_CSS = {
            "CRITICAL": "sev-crit",
            "HIGH":     "sev-high",
            "MEDIUM":   "sev-med",
            "LOW":      "sev-low",
            "INFO":     "sev-info",
        }

        generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        def _findings_table(findings: list[Finding]) -> str:
            if not findings:
                return '<p class="good">Sin hallazgos</p>'
            rows = ""
            for f in findings:
                remed = ""
                if f.remediation:
                    remed = (
                        f'<details class="remed"><summary>Ver remediación</summary>'
                        f'<pre>{escape(f.remediation)}</pre></details>'
                    )
                rows += (
                    f'<tr>'
                    f'<td class="dim">{escape(f.id)}</td>'
                    f'<td class="{SEV_CSS.get(f.severity, "")}">{escape(f.severity)}</td>'
                    f'<td>{escape(f.category)}</td>'
                    f'<td>{escape(f.title)}{remed}</td>'
                    f'<td class="dim">{escape(f.evidence[:120] if f.evidence else "")}</td>'
                    f'</tr>'
                )
            return (
                '<table class="findings-table">'
                '<thead><tr><th>ID</th><th>SEV</th><th>Categoría</th>'
                '<th>Hallazgo / Remediación</th><th>Evidencia</th></tr></thead>'
                f'<tbody>{rows}</tbody>'
                '</table>'
            )

        bloques_contenedores = ""
        for car in resultado.containers:
            sev_css = SEV_CSS.get(car.max_severity, "sev-info")
            bloques_contenedores += f"""
            <div class="result-block">
              <div class="container-header">
                <span class="badge {sev_css}">{escape(car.max_severity)}</span>
                <h2>{escape(car.container_name)}</h2>
                <span class="dim">{escape(car.image)}</span>
                <span class="dim">Estado: {escape(car.status)}</span>
              </div>
              <h3>Hallazgos ({len(car.findings)})</h3>
              {_findings_table(car.findings)}
            </div>"""

        hallazgos_globales: list[Finding] = (
            resultado.image_findings
            + resultado.network_findings
            + resultado.env_findings
        )

        bloque_global = ""
        if hallazgos_globales:
            bloque_global = f"""
            <div class="result-block">
              <h2>Hallazgos de Entorno, Imágenes y Redes</h2>
              {_findings_table(hallazgos_globales)}
            </div>"""

        filas_resumen = ""
        for car in resultado.containers:
            sev_css = SEV_CSS.get(car.max_severity, "sev-info")
            filas_resumen += (
                f'<tr>'
                f'<td><strong>{escape(car.container_name)}</strong></td>'
                f'<td class="dim">{escape(car.image[:32])}</td>'
                f'<td class="dim">{escape(car.status)}</td>'
                f'<td class="sev-crit">{car.count_by_severity("CRITICAL")}</td>'
                f'<td class="sev-high">{car.count_by_severity("HIGH")}</td>'
                f'<td class="sev-med">{car.count_by_severity("MEDIUM")}</td>'
                f'<td class="sev-low">{car.count_by_severity("LOW")}</td>'
                f'<td class="sev-info">{car.count_by_severity("INFO")}</td>'
                f'<td><strong>{len(car.findings)}</strong></td>'
                f'<td class="{sev_css}">{escape(car.max_severity)}</td>'
                f'</tr>'
            )

        return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VampSecure Labs — Docker Audit Report</title>
<style>
:root {{
  --bg: #0d0d0d; --surface: #141414; --border: #1e1e1e;
  --text: #e0e0e0; --text-dim: #888; --accent: #9b59b6;
  --crit: #ff4444; --high: #ff8800; --med: #ffcc00; --low: #4488ff;
  --info: #888; --good: #44cc88;
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ background: var(--bg); color: var(--text);
       font-family: 'Consolas','Courier New',monospace;
       font-size: 14px; padding: 24px; }}
header {{ border-bottom: 1px solid var(--accent);
          padding-bottom: 16px; margin-bottom: 24px; }}
header h1 {{ color: var(--accent); font-size: 22px; letter-spacing: .1em; }}
header p {{ color: var(--text-dim); font-size: 12px; margin-top: 4px; }}
.result-block {{ background: var(--surface); border: 1px solid var(--border);
                 border-radius: 6px; padding: 20px; margin-bottom: 20px; }}
.container-header {{ display: flex; align-items: center; gap: 12px;
                      margin-bottom: 14px; flex-wrap: wrap; }}
.container-header h2 {{ font-size: 16px; }}
.result-block h3 {{ font-size: 13px; color: var(--text-dim); margin: 14px 0 6px;
                    text-transform: uppercase; letter-spacing: .07em; }}
.badge {{ display: inline-block; padding: 2px 8px; border-radius: 3px;
          font-size: .74em; font-weight: 700; letter-spacing: .3px; }}
.sev-crit {{ color: var(--crit); }}
.sev-high {{ color: var(--high); }}
.sev-med  {{ color: var(--med); }}
.sev-low  {{ color: var(--low); }}
.sev-info, .dim {{ color: var(--text-dim); }}
.good {{ color: var(--good); }}
.badge.sev-crit {{ background: rgba(255,68,68,.15); }}
.badge.sev-high {{ background: rgba(255,136,0,.15); }}
.badge.sev-med  {{ background: rgba(255,204,0,.15); }}
.badge.sev-low  {{ background: rgba(68,136,255,.15); }}
.badge.sev-info {{ background: rgba(136,136,136,.1); }}
.findings-table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
.findings-table th {{ text-align: left; padding: 6px 10px;
                      color: var(--text-dim); border-bottom: 1px solid var(--border);
                      font-size: 11px; text-transform: uppercase; }}
.findings-table td {{ padding: 6px 10px; border-bottom: 1px solid var(--border);
                      vertical-align: top; }}
.findings-table tr:last-child td {{ border-bottom: none; }}
details.remed {{ margin-top: 6px; }}
details.remed summary {{ cursor: pointer; color: var(--accent); font-size: 11px; }}
details.remed pre {{ background: #0a0a0a; border: 1px solid var(--border);
                     border-radius: 4px; padding: 10px; font-size: 11px;
                     margin-top: 6px; overflow-x: auto; white-space: pre-wrap; }}
.summary-table {{ width: 100%; border-collapse: collapse; font-size: 12px; margin-top: 10px; }}
.summary-table th {{ background: var(--surface); color: var(--text-dim);
                     padding: 6px 8px; border: 1px solid var(--border);
                     font-size: 10px; text-transform: uppercase; }}
.summary-table td {{ padding: 5px 8px; border: 1px solid var(--border); }}
footer {{ margin-top: 32px; text-align: center;
          color: var(--text-dim); font-size: 11px; }}
</style>
</head>
<body>
<header>
  <h1>VampSecure Labs — Docker Security Audit Report</h1>
  <p>{TOOL_NAME} v{VERSION} · {generated} · Host: {escape(resultado.host)}
     · {escape(resultado.docker_version)}
     · VampSecure Studios · Uso exclusivo en auditorías autorizadas</p>
</header>

{bloque_global}
{bloques_contenedores}

<div class="result-block">
  <h2>Tabla Resumen Global</h2>
  <table class="summary-table">
    <thead>
      <tr>
        <th>Contenedor</th><th>Imagen</th><th>Estado</th>
        <th class="sev-crit">CRIT</th><th class="sev-high">HIGH</th>
        <th class="sev-med">MED</th><th class="sev-low">LOW</th>
        <th class="sev-info">INFO</th><th>Total</th><th>Sev. Máx.</th>
      </tr>
    </thead>
    <tbody>
      {filas_resumen}
    </tbody>
  </table>
</div>

<footer>© VampSecure Studios — VampSecure Labs Security Research Division</footer>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Conversión al formato de informe unificado VSL
# ---------------------------------------------------------------------------

def _findings_vsl(resultado: DockerAuditResult) -> list[VSLFinding]:
    """
    Convierte los hallazgos Docker al formato Finding unificado de VampSecure Labs.
    """
    INCLUIDOS = {"CRITICAL", "HIGH", "MEDIUM"}
    hallazgos: list[VSLFinding] = []

    for f in resultado.all_findings:
        if f.severity not in INCLUIDOS:
            continue
        afectado = f.container if f.container else resultado.host
        hallazgos.append(VSLFinding(
            id          = f.id,
            title       = f.title,
            severity    = f.severity,
            description = f.description,
            evidence    = f.evidence or "Ver descripción",
            affected    = afectado,
            remediation = f.remediation or "Consultar CIS Docker Benchmark.",
            tags        = ["docker", f.category.lower(), f.severity.lower()],
        ))

    return hallazgos
