# © VampSecure Studios — VampSecure Labs Security Research Division
"""
cli.py — Command-line interface entry point for vamp-docker-audit v1.6.0
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from rich.console import Console

from ._models import VERSION, TOOL_NAME, DockerAuditResult, _s
import vamp_docker_audit._models as _m
from ._core import DockerAuditor, _sbom_para_imagen, apply_delta_scan
from ._report import DockerReporter, _findings_vsl
from vampsec_report import VampSecReport, add_report_args, meta_from_args

console = Console()

BANNER = r"""
__   ___   __  __ ___  ___ ___ ___ _   _ ___ ___ _      _   ___ ___
\ \ / /_\ |  \/  | _ \/ __| __/ __| | | | _ \ __| |    /_\ | _ ) __|
 \ V / _ \| |\/| |  _/\__ \ _| (__| |_| |   / _|| |__ / _ \| _ \__ \
  \_/_/ \_\_|  |_|_|  |___/___\___|\___/|_|_\___|____/_/ \_\___/___/
  by Antonio Hernandez "Belky" — VampSecure Studios
  vamp-docker-audit v1.6.0 · Docker Security Auditor
  ────────────────────────────────────────────────────────────────────────
  FOR AUTHORIZED AUDITS ONLY · El uso no autorizado es ilegal
"""


# ---------------------------------------------------------------------------
# SBOM orchestration (uses console output)
# ---------------------------------------------------------------------------

def _generar_sboms(
    resultado:  "DockerAuditResult",
    sbom_file:  str | None,
    sbom_dir:   str | None,
    cons:       Console,
) -> None:
    """
    Orquesta la generación de SBOMs para las imágenes de los contenedores auditados.

    --sbom FILE    → genera un único JSON agregado con todos los SBOMs
    --sbom-dir DIR → genera un fichero .sbom.json por imagen en el directorio
    """
    if not sbom_file and not sbom_dir:
        return

    imagenes: set[str] = set()
    for car in resultado.containers:
        if car.image and "<none>" not in car.image:
            imagenes.add(car.image)

    if not imagenes:
        cons.print(_s("[yellow]SBOM: No images found to process.[/]", "[yellow]SBOM: No se encontraron imágenes para procesar.[/]"))
        return

    sboms_generados: list[dict] = []

    cons.print(_s(f"\n[bold cyan]Generating SBOMs for {len(imagenes)} image(s)…[/]\n", f"\n[bold cyan]Generando SBOMs para {len(imagenes)} imagen(es)…[/]\n"))
    for imagen in sorted(imagenes):
        cons.print(f"  [dim]SBOM:[/dim] {imagen}…", end=" ")
        sbom = _sbom_para_imagen(imagen)
        sbom["imagen"] = imagen
        n_comp = len(sbom.get("components", []))
        estado = (
            _s("[yellow]no shell[/yellow]", "[yellow]sin shell[/yellow]")
            if sbom.get("components_unavailable")
            else _s(f"[green]{n_comp} components[/green]", f"[green]{n_comp} componentes[/green]")
        )
        cons.print(estado)
        sboms_generados.append(sbom)

    if sbom_file:
        Path(sbom_file).write_text(
            json.dumps({"sboms": sboms_generados}, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        cons.print(_s(f"\n[green]✔[/] Aggregated SBOM saved to [bold]{sbom_file}[/]", f"\n[green]✔[/] SBOM agregado guardado en [bold]{sbom_file}[/]"))

    if sbom_dir:
        dir_path = Path(sbom_dir)
        dir_path.mkdir(parents=True, exist_ok=True)
        for sbom in sboms_generados:
            imagen = sbom.get("imagen", "unknown")
            nombre_fichero = re.sub(r"[^a-zA-Z0-9._-]", "_", imagen) + ".sbom.json"
            (dir_path / nombre_fichero).write_text(
                json.dumps(sbom, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        cons.print(
            _s(f"[green]✔[/] Individual SBOMs saved to [bold]{sbom_dir}/[/] "
            f"({len(sboms_generados)} file(s))", f"[green]✔[/] SBOMs individuales guardados en [bold]{sbom_dir}/[/] "
            f"({len(sboms_generados)} fichero(s))")
        )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    """Parsea los argumentos de la línea de comandos."""
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=(
            f"VampSecure Labs Docker Audit v{VERSION} — "
            "Docker Security Auditor / Auditor de seguridad Docker"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples / Ejemplos:
  vamp-docker-audit
  vamp-docker-audit --containers my-app,db-postgres
  vamp-docker-audit --include-stopped --json result.json
  vamp-docker-audit --html report.html --report-html client.html
  vamp-docker-audit --no-env-scan --client "AcmeCorp" --engagement "Pentest-2026"
        """,
    )
    p.add_argument(
        "--socket", metavar="PATH", default="/var/run/docker.sock",
        help="Path to Docker socket (default: /var/run/docker.sock)",
    )
    p.add_argument(
        "--containers", metavar="NOMBRES",
        help="Comma-separated list of container names/IDs (default: all)",
    )
    p.add_argument(
        "--include-stopped", action="store_true",
        help="Include stopped containers in the audit",
    )
    p.add_argument(
        "--no-env-scan", action="store_true",
        help="Skip scanning environment variables for secrets",
    )
    p.add_argument(
        "--json", metavar="FICHERO",
        help="Save complete result in JSON format",
    )
    p.add_argument(
        "--html", metavar="FICHERO",
        help="Save report as standalone dark-theme HTML",
    )

    # SBOM — Software Bill of Materials (v1.1)
    p.add_argument(
        "--sbom", metavar="FICHERO",
        help="Generate aggregated CycloneDX 1.4 SBOM for all audited images and save to FILE (JSON)",
    )
    p.add_argument(
        "--sbom-dir", metavar="DIR", dest="sbom_dir",
        help="Generate one CycloneDX 1.4 SBOM per audited image and save to DIR (one .sbom.json per image)",
    )

    p.add_argument(
        "--delta", metavar="FILE",
        help="Delta scan: compare against a previous JSON report (--json). "
             "Shows findings as NEW/RECURRING and lists RESOLVED ones.",
    )

    # Argumentos de informe unificado VSL
    add_report_args(p)

    p.add_argument(
        "--lang", choices=["en", "es"], default="en",
        help="Output language / Idioma de salida (default: en)",
    )
    return p.parse_args()


def main() -> None:
    """Punto de entrada principal de la herramienta."""
    console.print(BANNER, style="bold magenta")

    args = _parse_args()
    _m.LANG = args.lang

    # Parsear nombres de contenedores objetivo
    target_names: list[str] | None = None
    if args.containers:
        target_names = [n.strip() for n in args.containers.split(",") if n.strip()]

    auditor = DockerAuditor(
        socket_path=args.socket,
        include_stopped=args.include_stopped,
        scan_env=not args.no_env_scan,
        target_names=target_names,
    )

    reporter = DockerReporter(console)

    console.print(_s("[bold cyan]Starting Docker environment audit…[/]\n", "[bold cyan]Iniciando auditoría de entorno Docker…[/]\n"))

    with console.status(_s("[cyan]Auditing containers and configuration…[/]", "[cyan]Auditando contenedores y configuración…[/]"), spinner="dots"):
        resultado = auditor.audit()

    # Error fatal de acceso al daemon
    if resultado.error:
        reporter.print_env_error(resultado.error)
        sys.exit(2)

    # Información del entorno
    reporter.print_env_info(resultado)

    # Hallazgos de entorno (socket, imágenes, redes, ENV)
    hallazgos_entorno = resultado.image_findings + resultado.network_findings
    if hallazgos_entorno:
        reporter.print_extra_findings(
            _s("[bold]Environment & Image Findings[/bold]", "[bold]Hallazgos de Entorno e Imágenes[/bold]"),
            hallazgos_entorno,
        )

    if resultado.env_findings:
        reporter.print_extra_findings(
            _s("[bold]Environment Variable Findings (ENV secrets)[/bold]", "[bold]Hallazgos de Variables de Entorno (ENV secrets)[/bold]"),
            resultado.env_findings,
        )

    # Resultados por contenedor
    if resultado.containers:
        console.print(f"\n[bold cyan]{'─'*60}[/]")
        console.print(f"  Auditoría de {len(resultado.containers)} contenedor(es)")
        console.print(f"[bold cyan]{'─'*60}[/]\n")
        for car in resultado.containers:
            reporter.print_container(car)
    else:
        console.print(_s("[yellow]No containers found to audit.[/]", "[yellow]No se encontraron contenedores para auditar.[/]"))

    # Tabla resumen global
    if resultado.containers:
        reporter.print_summary(resultado)

    # ── Delta scan (--delta) ─────────────────────────────────────────────
    if getattr(args, "delta", None):
        try:
            new_keys, recurring_keys, resolved_keys = apply_delta_scan(resultado, args.delta)
            console.print(
                f"\n[bold cyan]  DELTA vs {args.delta}:[/] "
                f"[bold green]{len(new_keys)} NEW[/] · [yellow]{len(recurring_keys)} RECURRING[/] · "
                f"[dim]{len(resolved_keys)} RESOLVED[/]"
            )
            for k in sorted(new_keys):
                console.print(f"[dim]  [+NEW     ] {k}[/]")
            for k in sorted(resolved_keys):
                console.print(f"[dim]  [-RESOLVED] {k}[/]")
        except ValueError as exc:
            console.print(f"[bold red]  [!] Delta error: {exc}[/]")

    # Exportar JSON
    if args.json:
        Path(args.json).write_text(reporter.to_json(resultado), encoding="utf-8")
        console.print(_s(f"\n[green]✔[/] JSON saved to [bold]{args.json}[/]", f"\n[green]✔[/] JSON guardado en [bold]{args.json}[/]"))

    # Exportar HTML
    if args.html:
        Path(args.html).write_text(reporter.to_html(resultado), encoding="utf-8")
        console.print(_s(f"[green]✔[/] HTML saved to [bold]{args.html}[/]", f"[green]✔[/] HTML guardado en [bold]{args.html}[/]"))

    # Generar SBOM (v1.1)
    if getattr(args, "sbom", None) or getattr(args, "sbom_dir", None):
        _generar_sboms(
            resultado,
            sbom_file=getattr(args, "sbom", None),
            sbom_dir=getattr(args, "sbom_dir", None),
            cons=console,
        )

    # Informe unificado VSL
    if getattr(args, "report_html", None) or getattr(args, "report_pdf", None):
        meta   = meta_from_args(args, tool=TOOL_NAME, version=VERSION)
        vsl_f  = _findings_vsl(resultado)
        report = VampSecReport(meta=meta, findings=vsl_f)
        if args.report_html:
            report.to_html_client(args.report_html)
            console.print(_s(f"[green]✔[/] Client HTML report saved to [bold]{args.report_html}[/]", f"[green]✔[/] Informe cliente HTML guardado en [bold]{args.report_html}[/]"))
        if args.report_pdf:
            report.to_pdf(args.report_pdf)
            console.print(_s(f"[green]✔[/] Client PDF report saved to [bold]{args.report_pdf}[/]", f"[green]✔[/] Informe cliente PDF guardado en [bold]{args.report_pdf}[/]"))

    # Código de salida según severidad máxima global
    max_sev = resultado.max_severity
    sys.exit(2 if max_sev == "CRITICAL" else 1 if max_sev == "HIGH" else 0)


if __name__ == "__main__":
    main()
