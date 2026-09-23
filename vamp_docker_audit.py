#!/usr/bin/env python3
# © VampSecure Studios — VampSecure Labs Security Research Division
"""
vamp_docker_audit.py — Auditor de Seguridad de Entornos Docker
===============================================================
VampSecure Labs · VampSecure Studios
Para Uso Exclusivo en Pruebas de Penetración Autorizadas — v1.3

DESCRIPCIÓN GENERAL
-------------------
Auditor profesional de configuraciones y entornos Docker. Detecta
configuraciones peligrosas en contenedores, imágenes, redes y volúmenes
utilizando únicamente la CLI de Docker vía subprocess, sin dependencia
del SDK de Python para Docker.

COMPROBACIONES REALIZADAS
--------------------------
  Fase 0: Entorno Docker
    · Verificación de instalación y acceso al daemon
    · Permisos del socket /var/run/docker.sock

  Fase 1: Contenedores (running + stopped opcionales)
    · Modo privilegiado (DOCK-001)
    · Capacidades peligrosas añadidas (DOCK-002)
    · Proceso raíz (DOCK-003)
    · Socket Docker montado dentro del contenedor (DOCK-004)
    · Red en modo host (DOCK-005)
    · Volúmenes sensibles montados en bind (DOCK-006)
    · PID namespace del host (DOCK-007)
    · IPC namespace del host (DOCK-008)
    · Política de reinicio sin límite (DOCK-009)
    · Puertos expuestos en 0.0.0.0 (DOCK-010)

  Fase 2: Variables de entorno — búsqueda de secretos
    · Nombres de variable con patrones de credencial/token
    · Valores con prefijos conocidos de secreto (sk_, ghp_, ey…)
    · Connection strings (DATABASE_URL, REDIS_URL, MONGO_URL)

  Fase 3: Imágenes
    · Uso de etiqueta :latest sin versión fija
    · Imágenes antiguas (>90 días) sin actualización

  Fase 4: Redes
    · Redes en modo host (resumen)
    · Inventario de redes y subredes

  Fase 5: Volúmenes
    · Inventario de volúmenes registrados

  Fase 6: Secretos en historia de capas de imagen
    · Detección de credenciales en RUN/ENV/ARG de capas (v1.1)

  Fase 7: CVEs específicos (v1.2)
    · CVE-2026-34040: Docker AuthZ Plugin Bypass
      - DOCK-AUTHZ-001: plugin AuthZ activo + daemon vulnerable (CRITICAL)
      - DOCK-AUTHZ-002: plugin AuthZ activo, versión no determinada (HIGH)
      - DOCK-AUTHZ-003: socket Docker montado en contenedor en marcha (CRITICAL)
    · CVE-2025-52881: runc Container Escape
      - DOCK-RUNC-001: versión runc vulnerable (CRITICAL)
      - DOCK-RUNC-002: seccomp no habilitado por defecto (HIGH)
    · Perfiles AppArmor
      - DOCK-SEC-010: AppArmor no habilitado en Linux (MEDIUM)

FORMATOS DE SALIDA
------------------
  Consola  · Rich con paneles por contenedor y tabla resumen
  JSON     · --json FILE   (estructura completa con hallazgos)
  HTML     · --html FILE   (informe dark-theme standalone)
  Informe VSL  · --report-html / --report-pdf (formato cliente unificado)

DEPENDENCIAS
------------
  rich >= 13.7.0
  Docker CLI instalado y accesible en PATH

AUTORÍA
-------
  © VampSecure Studios — VampSecure Labs Security Research Division
  Todos los derechos reservados. Uso exclusivo en entornos autorizados.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import socket
import stat
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from vampsec_report import (
    Finding as VSLFinding,
    VampSecReport,
    add_report_args,
    meta_from_args,
)

VERSION   = "1.3"
TOOL_NAME = "vamp-docker-audit"

console = Console()

BANNER = r"""
__   ___   __  __ ___  ___ ___ ___ _   _ ___ ___ _      _   ___ ___
\ \ / /_\ |  \/  | _ \/ __| __/ __| | | | _ \ __| |    /_\ | _ ) __|
 \ V / _ \| |\/| |  _/\__ \ _| (__| |_| |   / _|| |__ / _ \| _ \__ \
  \_/_/ \_\_|  |_|_|  |___/___\___|\___/|_|_\___|____/_/ \_\___/___/
  by Antonio Hernandez "Belky" — VampSecure Studios
  vamp-docker-audit v1.3 · Docker Security Auditor
  ────────────────────────────────────────────────────────────────────────
  USO EXCLUSIVO EN AUDITORÍAS AUTORIZADAS · El uso no autorizado es ilegal
"""

# ---------------------------------------------------------------------------
# Constantes y mapas de severidad
# ---------------------------------------------------------------------------

SEVERITY_ORDER: dict[str, int] = {
    "CRITICAL": 0,
    "HIGH":     1,
    "MEDIUM":   2,
    "LOW":      3,
    "INFO":     4,
}

SEVERITY_COLOR: dict[str, str] = {
    "CRITICAL": "bold red",
    "HIGH":     "bold yellow",
    "MEDIUM":   "bold magenta",
    "LOW":      "cyan",
    "INFO":     "green",
}

# Capacidades de Linux consideradas peligrosas
DANGEROUS_CAPS = {
    "CAP_SYS_ADMIN",
    "CAP_NET_ADMIN",
    "CAP_SYS_PTRACE",
    "CAP_DAC_READ_SEARCH",
    "CAP_SYS_MODULE",
    "CAP_SYS_RAWIO",
    "SYS_ADMIN",
    "NET_ADMIN",
    "SYS_PTRACE",
    "DAC_READ_SEARCH",
    "SYS_MODULE",
    "SYS_RAWIO",
}

# Rutas de origen de bind mount consideradas sensibles
SENSITIVE_MOUNT_PREFIXES = (
    "/etc",
    "/var/run",
    "/proc",
    "/sys",
    "/root",
    "/home",
)

# Patrones en nombres de variable de entorno que sugieren credenciales
SECRET_VAR_PATTERNS = re.compile(
    r"(PASSWORD|PASSWD|SECRET|TOKEN|KEY|API_KEY|APIKEY|PRIVATE|"
    r"CREDENTIALS|AUTH|DSN)",
    re.IGNORECASE,
)

# Patrones en el valor que sugieren secretos
SECRET_VALUE_PATTERNS = [
    re.compile(r"^sk_"),                        # Stripe / clave secreta de API de servicio
    re.compile(r"^pk_"),                        # Stripe public key (poco dañino, pero lo informamos)
    re.compile(r"^ghp_"),                       # GitHub personal access token
    re.compile(r"^glpat-"),                     # GitLab personal access token
    re.compile(r"^xox[bpoa]-"),                 # Slack token
    re.compile(r"^Bearer "),                    # Bearer token
    re.compile(r"^AKIA[0-9A-Z]{16}"),          # AWS access key
    re.compile(r"^ey[A-Za-z0-9]"),             # JWT (base64 header)
    re.compile(r"^[A-Za-z0-9/+]{20,}={0,2}$"), # Base64 genérico largo (>20 chars)
]

# Variables de connection string (siempre reportadas aunque el valor no parezca secreto)
CONNECTION_STRING_VARS = re.compile(
    r"(DATABASE_URL|MONGO_URL|REDIS_URL|JDBC:|POSTGRES_URL|MYSQL_URL|"
    r"DB_URL|DB_CONNECTION|CONNECTION_STRING)",
    re.IGNORECASE,
)

# Patrones de secretos en comandos de historia de capas de imagen (v1.1)
LAYER_SECRET_PATTERNS = [
    (
        re.compile(
            r"(?i)(password|passwd|secret|token|api[_-]?key|apikey|"
            r"private[_-]?key|credentials|auth[_-]?token|access[_-]?key|"
            r"secret[_-]?key)\s*[=:]\s*\S+",
        ),
        "Posible credencial en parámetro RUN/ENV",
    ),
    (
        re.compile(r"(?i)--password\s+\S+"),
        "Contraseña como argumento CLI en RUN",
    ),
    (
        re.compile(r"(?i)--token\s+\S+"),
        "Token como argumento CLI en RUN",
    ),
    (
        re.compile(r"AKIA[0-9A-Z]{16}"),
        "AWS Access Key ID en historia de capa",
    ),
    (
        re.compile(r"(?i)bearer\s+[A-Za-z0-9\-._~+/]{20,}"),
        "Bearer token en historia de capa",
    ),
    (
        re.compile(r"(?i)sk_live_[0-9a-zA-Z]{24,}"),
        "Stripe Live Secret Key",
    ),
    (
        re.compile(r"ghp_[0-9a-zA-Z]{36,}"),
        "GitHub Personal Access Token",
    ),
    (
        re.compile(r"glpat-[0-9a-zA-Z\-]{20,}"),
        "GitLab Personal Access Token",
    ),
    (
        re.compile(r"xox[bpoa]-[0-9]{8,}-[0-9]{8,}-\S{8,}"),
        "Slack Token",
    ),
]


# ---------------------------------------------------------------------------
# Estructuras de datos
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """
    Hallazgo de seguridad individual en el contexto de la auditoría Docker.

    Atributos
    ---------
    id          : Identificador único en formato DOCK-NNN
    severity    : Nivel de riesgo (CRITICAL / HIGH / MEDIUM / LOW / INFO)
    category    : Categoría del hallazgo (Contenedor, Red, Imagen, Volumen, ENV)
    title       : Título descriptivo corto
    description : Descripción técnica del problema detectado
    evidence    : Dato técnico concreto que sustenta el hallazgo
    remediation : Pasos de corrección recomendados
    container   : Nombre del contenedor afectado (vacío si no aplica)
    """
    id:          str
    severity:    str
    category:    str
    title:       str
    description: str
    evidence:    str = ""
    remediation: str = ""
    container:   str = ""

    @property
    def order(self) -> int:
        """Orden numérico para ordenación por severidad descendente."""
        return SEVERITY_ORDER.get(self.severity, 99)


@dataclass
class ContainerAuditResult:
    """
    Resultado de la auditoría de un contenedor individual.

    Atributos
    ---------
    container_id   : ID corto del contenedor (primeros 12 caracteres)
    container_name : Nombre asignado al contenedor
    image          : Imagen y etiqueta usadas al crear el contenedor
    status         : Estado actual (running, exited, etc.)
    findings       : Lista de hallazgos detectados en este contenedor
    """
    container_id:   str
    container_name: str
    image:          str
    status:         str
    findings:       List[Finding] = field(default_factory=list)

    @property
    def max_severity(self) -> str:
        """Severidad máxima entre todos los hallazgos del contenedor."""
        if not self.findings:
            return "INFO"
        return min(self.findings, key=lambda f: f.order).severity

    def count_by_severity(self, sev: str) -> int:
        """Cuenta hallazgos de una severidad concreta."""
        return sum(1 for f in self.findings if f.severity == sev)


@dataclass
class DockerAuditResult:
    """
    Resultado completo de la auditoría del entorno Docker.

    Atributos
    ---------
    host            : Nombre del host auditado
    docker_version  : Versión del daemon Docker detectada
    containers      : Resultados por contenedor
    image_findings  : Hallazgos relativos a imágenes
    network_findings: Hallazgos relativos a redes
    env_findings    : Hallazgos relativos a variables de entorno
    error           : Error fatal si el daemon no es accesible
    """
    host:             str
    docker_version:   str
    containers:       List[ContainerAuditResult] = field(default_factory=list)
    image_findings:   List[Finding] = field(default_factory=list)
    network_findings: List[Finding] = field(default_factory=list)
    env_findings:     List[Finding] = field(default_factory=list)
    error:            Optional[str] = None

    @property
    def all_findings(self) -> List[Finding]:
        """Todos los hallazgos del entorno, ordenados por severidad."""
        found: List[Finding] = []
        for c in self.containers:
            found.extend(c.findings)
        found.extend(self.image_findings)
        found.extend(self.network_findings)
        found.extend(self.env_findings)
        return sorted(found, key=lambda f: f.order)

    @property
    def max_severity(self) -> str:
        """Severidad máxima global del entorno auditado."""
        all_f = self.all_findings
        if not all_f:
            return "INFO"
        return min(all_f, key=lambda f: f.order).severity


# ---------------------------------------------------------------------------
# Utilidades de ejecución de Docker CLI
# ---------------------------------------------------------------------------

def _docker(args: list[str], timeout: int = 30) -> tuple[bool, str, str]:
    """
    Ejecuta un subcomando docker y devuelve (éxito, stdout, stderr).

    Parámetros
    ----------
    args    : Lista de argumentos para docker (sin 'docker' al inicio)
    timeout : Segundos máximos de espera (default 30)

    Retorna
    -------
    Tupla (ok: bool, stdout: str, stderr: str).
    ok es False si el proceso retorna código != 0 o lanza excepción.
    """
    try:
        resultado = subprocess.run(
            ["docker"] + args,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        ok = resultado.returncode == 0
        return ok, resultado.stdout.strip(), resultado.stderr.strip()
    except FileNotFoundError:
        return False, "", "docker: comando no encontrado en PATH"
    except subprocess.TimeoutExpired:
        return False, "", f"docker {args[0]}: timeout tras {timeout}s"
    except Exception as exc:
        return False, "", str(exc)


def _docker_inspect(name: str) -> Optional[dict]:
    """
    Ejecuta `docker inspect` sobre un contenedor y devuelve el objeto JSON.

    Retorna None si el inspect falla o el JSON no puede parsearse.
    """
    ok, stdout, stderr = _docker(["inspect", name])
    if not ok or not stdout:
        return None
    try:
        data = json.loads(stdout)
        if isinstance(data, list) and data:
            return data[0]
    except json.JSONDecodeError:
        pass
    return None


# ---------------------------------------------------------------------------
# Motor de auditoría Docker
# ---------------------------------------------------------------------------

class DockerAuditor:
    """
    Motor principal de la auditoría de entornos Docker.

    Opera exclusivamente via subprocess sobre la CLI de Docker. No utiliza
    el SDK de Python para Docker. Todas las fases son independientes y el
    fallo de una no impide la ejecución de las siguientes.

    Parámetros
    ----------
    socket_path    : Ruta al socket Docker (comprobación de permisos)
    include_stopped: Incluir contenedores parados en el análisis
    scan_env       : Escanear variables de entorno en busca de secretos
    target_names   : Lista de nombres/IDs específicos (None = todos)
    """

    # Contador global de hallazgos para asignar IDs DOCK-NNN
    _counter: int = 0

    def __init__(
        self,
        socket_path: str = "/var/run/docker.sock",
        include_stopped: bool = False,
        scan_env: bool = True,
        target_names: Optional[list[str]] = None,
    ) -> None:
        self._socket_path    = socket_path
        self._include_stopped = include_stopped
        self._scan_env       = scan_env
        self._target_names   = target_names
        self._counter        = 0

    # ── API pública ────────────────────────────────────────────────────────

    def audit(self) -> DockerAuditResult:
        """
        Ejecuta la auditoría completa del entorno Docker.

        Fases:
          0. Verificación del entorno (instalación, daemon, socket)
          1. Auditoría de contenedores
          2. Variables de entorno (si no se desactiva con --no-env-scan)
          3. Imágenes
          4. Redes
          5. Volúmenes

        Retorna un DockerAuditResult con todos los hallazgos consolidados.
        """
        resultado = DockerAuditResult(
            host=socket.gethostname(),
            docker_version="",
        )

        # Fase 0: verificación del entorno
        error = self._phase0_entorno(resultado)
        if error:
            resultado.error = error
            return resultado

        # Fase 1: contenedores
        self._phase1_contenedores(resultado)

        # Fase 2: variables de entorno
        if self._scan_env:
            self._phase2_env(resultado)

        # Fase 3: imágenes
        self._phase3_imagenes(resultado)

        # Fase 4: redes
        self._phase4_redes(resultado)

        # Fase 5: volúmenes
        self._phase5_volumenes(resultado)

        # Fase 6: secretos en historia de capas de imagen (v1.1)
        self._phase6_layer_secrets(resultado)

        # Fase 7: checks de CVEs específicos (v1.2)
        self._phase7_cve_checks(resultado)

        return resultado

    # ── Fase 0: entorno Docker ─────────────────────────────────────────────

    def _phase0_entorno(self, resultado: DockerAuditResult) -> Optional[str]:
        """
        Verifica la instalación y accesibilidad del daemon Docker.
        Comprueba permisos del socket Unix.

        Retorna un mensaje de error si el daemon no es accesible, None si todo OK.
        """
        # Verificar instalación
        ok, stdout, stderr = _docker(["--version"])
        if not ok:
            return f"Docker no está instalado o no está en PATH: {stderr}"

        resultado.docker_version = stdout.strip()

        # Verificar acceso al daemon
        ok, stdout, stderr = _docker(["info", "--format", "{{.ServerVersion}}"])
        if not ok:
            return (
                f"No se puede conectar al daemon Docker. "
                f"¿Está en ejecución? Error: {stderr}"
            )

        # Permisos del socket
        self._check_socket_perms(resultado)

        return None

    def _check_socket_perms(self, resultado: DockerAuditResult) -> None:
        """
        Analiza los permisos del socket Docker y genera hallazgos si son inseguros.

        El socket en modo 666 (lectura/escritura para todos) permite escalada de
        privilegios a cualquier usuario del sistema.
        """
        sock_path = self._socket_path
        if not os.path.exists(sock_path):
            return

        try:
            st = os.stat(sock_path)
            mode = stat.S_IMODE(st.st_mode)
            mode_oct = oct(mode)

            # Mundo con escritura: cualquiera puede hablar con el daemon
            if mode & stat.S_IWOTH:
                self._counter += 1
                resultado.image_findings.append(Finding(
                    id=f"DOCK-{self._counter:03d}",
                    severity="HIGH",
                    category="Entorno",
                    title="Socket Docker accesible para todos (world-writable)",
                    description=(
                        f"El socket Unix {sock_path} tiene permisos {mode_oct} "
                        "que permiten a cualquier usuario del sistema comunicarse "
                        "directamente con el daemon Docker. Esto es equivalente a "
                        "acceso root en el host."
                    ),
                    evidence=f"{sock_path} permisos={mode_oct}",
                    remediation=(
                        "Restringir los permisos del socket:\n"
                        f"  chmod 660 {sock_path}\n"
                        "  chown root:docker {sock_path}\n"
                        "Solo los usuarios del grupo 'docker' deben tener acceso.\n"
                        "Ref: CIS Docker Benchmark §3.15"
                    ),
                ))
            else:
                # Socket accesible por grupo (comprobamos si el usuario actual es del grupo)
                gid = st.st_gid
                try:
                    import grp
                    grupo = grp.getgrgid(gid)
                    usuario_actual = os.environ.get("USER", "")
                    if usuario_actual in grupo.gr_mem:
                        self._counter += 1
                        resultado.image_findings.append(Finding(
                            id=f"DOCK-{self._counter:03d}",
                            severity="INFO",
                            category="Entorno",
                            title=f"Usuario '{usuario_actual}' pertenece al grupo docker",
                            description=(
                                f"El usuario actual ({usuario_actual}) es miembro del grupo "
                                f"'{grupo.gr_name}' (GID {gid}), lo que le da acceso "
                                "completo al socket Docker y por extensión privilegios root."
                            ),
                            evidence=f"{sock_path} grupo={grupo.gr_name} usuario={usuario_actual}",
                            remediation=(
                                "Revisar los miembros del grupo 'docker' y asegurarse\n"
                                "de que solo los administradores autorizados pertenecen a él.\n"
                                "Ref: CIS Docker Benchmark §3.15"
                            ),
                        ))
                except (KeyError, ImportError):
                    pass
        except PermissionError:
            pass
        except OSError:
            pass

    # ── Fase 1: contenedores ───────────────────────────────────────────────

    def _phase1_contenedores(self, resultado: DockerAuditResult) -> None:
        """
        Audita todos los contenedores en ejecución (y parados si se solicita).

        Para cada contenedor ejecuta `docker inspect` y analiza la configuración
        en busca de los problemas definidos (DOCK-001 a DOCK-010).
        """
        # Obtener lista de contenedores
        ps_args = ["ps", "--format", "{{.ID}}"]
        if self._include_stopped:
            ps_args.append("-a")

        ok, stdout, _ = _docker(ps_args)
        if not ok or not stdout:
            return

        ids_todos = [line.strip() for line in stdout.splitlines() if line.strip()]

        # Filtrar por nombres si se especificaron
        if self._target_names:
            ids_filtrados: list[str] = []
            for t in self._target_names:
                ok2, out2, _ = _docker(["inspect", "--format", "{{.Id}}", t])
                if ok2 and out2.strip():
                    ids_filtrados.append(out2.strip()[:12])
            ids = ids_filtrados if ids_filtrados else ids_todos
        else:
            ids = ids_todos

        for cid in ids:
            data = _docker_inspect(cid)
            if data is None:
                continue
            car = self._audit_container(data)
            resultado.containers.append(car)

    def _audit_container(self, data: dict) -> ContainerAuditResult:
        """
        Genera un ContainerAuditResult a partir de los datos de `docker inspect`.

        Analiza HostConfig y Config en busca de configuraciones inseguras.
        """
        cid   = data.get("Id", "")[:12]
        names = data.get("Name", "")
        name  = names.lstrip("/") if names else cid
        image = data.get("Config", {}).get("Image", "desconocida")
        state = data.get("State", {}).get("Status", "unknown")

        car = ContainerAuditResult(
            container_id=cid,
            container_name=name,
            image=image,
            status=state,
        )

        host_cfg = data.get("HostConfig", {})
        config   = data.get("Config", {})

        # 1. Modo privilegiado
        if host_cfg.get("Privileged", False):
            self._counter += 1
            car.findings.append(Finding(
                id=f"DOCK-{self._counter:03d}",
                severity="CRITICAL",
                category="Contenedor",
                title="Contenedor en modo privilegiado",
                description=(
                    "El contenedor se ejecuta con --privileged, que le otorga "
                    "acceso completo a todos los dispositivos del host y elimina "
                    "las restricciones de seguridad del kernel (capabilities, "
                    "seccomp, AppArmor). Equivale a acceso root en el host."
                ),
                evidence=f"Contenedor: {name} | Imagen: {image} | Privileged: true",
                remediation=(
                    "Eliminar el flag --privileged y añadir únicamente las capabilities\n"
                    "estrictamente necesarias con --cap-add:\n"
                    "  docker run --cap-add NET_ADMIN ... (ejemplo)\n"
                    "En Compose:\n"
                    "  cap_add:\n"
                    "    - NET_ADMIN\n"
                    "Ref: CIS Docker Benchmark §5.4"
                ),
                container=name,
            ))

        # 2. Capacidades peligrosas añadidas
        cap_add = host_cfg.get("CapAdd") or []
        caps_peligrosas = [
            c for c in cap_add
            if c.upper() in DANGEROUS_CAPS or c.upper().replace("CAP_", "") in DANGEROUS_CAPS
        ]
        if caps_peligrosas:
            self._counter += 1
            car.findings.append(Finding(
                id=f"DOCK-{self._counter:03d}",
                severity="HIGH",
                category="Contenedor",
                title="Capacidades Linux peligrosas habilitadas",
                description=(
                    "El contenedor tiene añadidas capabilities de Linux que pueden "
                    "permitir escalada de privilegios o comprometer el aislamiento "
                    "del kernel: " + ", ".join(caps_peligrosas)
                ),
                evidence=f"CapAdd: {', '.join(caps_peligrosas)}",
                remediation=(
                    "Revisar si las capabilities son estrictamente necesarias.\n"
                    "CAP_SYS_ADMIN en particular equivale a casi root completo.\n"
                    "Usar perfiles Seccomp y AppArmor para restringir syscalls.\n"
                    "Ref: CIS Docker Benchmark §5.24-5.30"
                ),
                container=name,
            ))

        # 3. Proceso raíz (usuario root dentro del contenedor)
        user = config.get("User", "")
        if not user or user in ("0", "root", "0:0", "root:root"):
            self._counter += 1
            car.findings.append(Finding(
                id=f"DOCK-{self._counter:03d}",
                severity="MEDIUM",
                category="Contenedor",
                title="Contenedor ejecutándose como root",
                description=(
                    "El proceso principal del contenedor se ejecuta como root "
                    f"(User={user!r}). Si se produce una escapada de contenedor, "
                    "el atacante obtiene privilegios de root en el host."
                ),
                evidence=f"Config.User={user!r}",
                remediation=(
                    "Especificar un usuario no privilegiado en el Dockerfile:\n"
                    "  RUN useradd -u 1000 appuser\n"
                    "  USER appuser\n"
                    "O con --user en docker run:\n"
                    "  docker run --user 1000:1000 ...\n"
                    "Ref: CIS Docker Benchmark §4.1"
                ),
                container=name,
            ))

        # 4. Socket Docker montado dentro del contenedor
        mounts = data.get("Mounts", [])
        for m in mounts:
            src = m.get("Source", "")
            if "docker.sock" in src:
                self._counter += 1
                spec = f"{src}:{m.get('Destination', '')}:{m.get('Mode', 'rw')}"
                car.findings.append(Finding(
                    id=f"DOCK-{self._counter:03d}",
                    severity="CRITICAL",
                    category="Contenedor",
                    title="Socket Docker montado dentro del contenedor",
                    description=(
                        "El socket del daemon Docker está montado en el interior "
                        "del contenedor. Cualquier proceso dentro puede crear "
                        "nuevos contenedores privilegiados o acceder al host completo."
                    ),
                    evidence=f"Montaje: {spec}",
                    remediation=(
                        "Eliminar el montaje del socket Docker del contenedor.\n"
                        "Si el contenedor necesita orquestación, evaluar alternativas "
                        "como Docker-in-Docker con TLS o el uso de un socket proxy "
                        "(p.ej. docker-socket-proxy) que limite los métodos de API.\n"
                        "Ref: CIS Docker Benchmark §5.31"
                    ),
                    container=name,
                ))

        # 5. Red en modo host
        net_mode = host_cfg.get("NetworkMode", "")
        if net_mode == "host":
            self._counter += 1
            car.findings.append(Finding(
                id=f"DOCK-{self._counter:03d}",
                severity="HIGH",
                category="Contenedor",
                title="Contenedor en red host (NetworkMode=host)",
                description=(
                    "El contenedor comparte la pila de red del host. Cualquier "
                    "servicio que arranque el contenedor escucha directamente en "
                    "la interfaz del host, eliminando el aislamiento de red."
                ),
                evidence=f"NetworkMode: host",
                remediation=(
                    "Usar redes de bridge con mapeo de puertos explícito:\n"
                    "  docker run -p 127.0.0.1:8080:8080 ...\n"
                    "En Compose:\n"
                    "  ports:\n"
                    "    - '127.0.0.1:8080:8080'\n"
                    "Ref: CIS Docker Benchmark §5.15"
                ),
                container=name,
            ))

        # 6. Volúmenes sensibles montados en bind
        for m in mounts:
            if m.get("Type") != "bind":
                continue
            src = m.get("Source", "")
            if any(src.startswith(prefix) for prefix in SENSITIVE_MOUNT_PREFIXES):
                self._counter += 1
                spec = f"{src}:{m.get('Destination', '')}:{m.get('Mode', 'ro')}"
                car.findings.append(Finding(
                    id=f"DOCK-{self._counter:03d}",
                    severity="MEDIUM",
                    category="Contenedor",
                    title=f"Montaje bind en ruta sensible del host: {src}",
                    description=(
                        f"El contenedor tiene montada la ruta {src!r} del host. "
                        "Dependiendo de los permisos, el contenedor puede leer o "
                        "modificar ficheros de sistema o configuración del host."
                    ),
                    evidence=f"Montaje: {spec}",
                    remediation=(
                        "Evaluar si el montaje es estrictamente necesario.\n"
                        "Si lo es, montarlo en modo solo lectura:\n"
                        "  -v /etc/resolv.conf:/etc/resolv.conf:ro\n"
                        "Usar volúmenes nombrados de Docker en lugar de bind mounts\n"
                        "cuando sea posible.\n"
                        "Ref: CIS Docker Benchmark §5.5"
                    ),
                    container=name,
                ))

        # 7. PID namespace del host
        pid_mode = host_cfg.get("PidMode", "")
        if pid_mode == "host":
            self._counter += 1
            car.findings.append(Finding(
                id=f"DOCK-{self._counter:03d}",
                severity="HIGH",
                category="Contenedor",
                title="Contenedor comparte PID namespace del host",
                description=(
                    "El contenedor usa --pid=host, lo que le permite ver y enviar "
                    "señales a todos los procesos del host. Esto puede facilitar "
                    "ataques de espionaje o terminación de procesos del host."
                ),
                evidence=f"PidMode: host",
                remediation=(
                    "Eliminar --pid=host del comando docker run o del Compose:\n"
                    "  # Eliminar: pid: host\n"
                    "Solo usar --pid=host si la aplicación requiere inspeccionar\n"
                    "procesos del host y el riesgo es aceptado explícitamente.\n"
                    "Ref: CIS Docker Benchmark §5.16"
                ),
                container=name,
            ))

        # 8. IPC namespace del host
        ipc_mode = host_cfg.get("IpcMode", "")
        if ipc_mode == "host":
            self._counter += 1
            car.findings.append(Finding(
                id=f"DOCK-{self._counter:03d}",
                severity="MEDIUM",
                category="Contenedor",
                title="Contenedor comparte IPC namespace del host",
                description=(
                    "El contenedor usa --ipc=host, compartiendo la memoria "
                    "compartida del host. Un proceso dentro del contenedor puede "
                    "leer memoria compartida de otros procesos del host."
                ),
                evidence=f"IpcMode: host",
                remediation=(
                    "Eliminar --ipc=host. Usar el IPC namespace por defecto.\n"
                    "Si dos contenedores necesitan IPC compartido, usar:\n"
                    "  --ipc=container:<nombre> (solo entre ellos).\n"
                    "Ref: CIS Docker Benchmark §5.17"
                ),
                container=name,
            ))

        # 9. Política de reinicio sin límite (informativo)
        restart = host_cfg.get("RestartPolicy", {})
        if restart.get("Name") == "always":
            self._counter += 1
            car.findings.append(Finding(
                id=f"DOCK-{self._counter:03d}",
                severity="INFO",
                category="Contenedor",
                title="Política de reinicio 'always' sin límite de intentos",
                description=(
                    "La política de reinicio 'always' hace que Docker reinicie "
                    "el contenedor indefinidamente, incluso tras fallos en bucle. "
                    "No es un fallo de seguridad en sí, pero puede ocultar problemas "
                    "y dificultar la detección de compromisos."
                ),
                evidence=f"RestartPolicy: {restart}",
                remediation=(
                    "Considerar 'on-failure' con un máximo de intentos:\n"
                    "  --restart=on-failure:5\n"
                    "En Compose:\n"
                    "  restart: on-failure\n"
                    "  deploy:\n"
                    "    restart_policy:\n"
                    "      condition: on-failure\n"
                    "      max_attempts: 5"
                ),
                container=name,
            ))

        # 10. Puertos expuestos en 0.0.0.0
        port_bindings = host_cfg.get("PortBindings") or {}
        puertos_expuestos: list[str] = []
        for cport, bindings in port_bindings.items():
            if not bindings:
                continue
            for b in bindings:
                host_ip   = b.get("HostIp", "")
                host_port = b.get("HostPort", "")
                if host_ip in ("0.0.0.0", ""):
                    puertos_expuestos.append(f"0.0.0.0:{host_port}->{cport}")

        if puertos_expuestos:
            self._counter += 1
            car.findings.append(Finding(
                id=f"DOCK-{self._counter:03d}",
                severity="LOW",
                category="Contenedor",
                title="Puertos expuestos en todas las interfaces (0.0.0.0)",
                description=(
                    "El contenedor tiene puertos publicados en 0.0.0.0, haciéndolos "
                    "accesibles desde cualquier interfaz de red del host, incluidas "
                    "interfaces externas si el host tiene conectividad pública."
                ),
                evidence="Puertos: " + " | ".join(puertos_expuestos),
                remediation=(
                    "Enlazar los puertos a 127.0.0.1 si solo necesitan acceso local:\n"
                    "  docker run -p 127.0.0.1:8080:80 ...\n"
                    "En Compose:\n"
                    "  ports:\n"
                    "    - '127.0.0.1:8080:80'\n"
                    "Usar un proxy inverso (nginx, Caddy, Traefik) para exponerlos\n"
                    "selectivamente con TLS.\n"
                    "Ref: CIS Docker Benchmark §5.7"
                ),
                container=name,
            ))

        # Ordenar hallazgos por severidad
        car.findings.sort(key=lambda f: f.order)
        return car

    # ── Fase 2: variables de entorno ───────────────────────────────────────

    def _phase2_env(self, resultado: DockerAuditResult) -> None:
        """
        Escanea las variables de entorno de todos los contenedores auditados
        en busca de secretos, tokens o connection strings.

        Los valores se redactan en los hallazgos para no exponerlos en el informe.
        """
        for car in resultado.containers:
            data = _docker_inspect(car.container_name)
            if data is None:
                continue

            env_list: list[str] = data.get("Config", {}).get("Env") or []
            for env_entry in env_list:
                if "=" not in env_entry:
                    continue
                var_name, _, var_value = env_entry.partition("=")
                var_name  = var_name.strip()
                var_value = var_value.strip()

                # Nombres de variable que sugieren credencial
                if SECRET_VAR_PATTERNS.search(var_name):
                    redacted = var_value[:4] + "****" if var_value else "****"
                    self._counter += 1
                    resultado.env_findings.append(Finding(
                        id=f"DOCK-{self._counter:03d}",
                        severity="HIGH",
                        category="ENV",
                        title=f"Posible secreto en variable de entorno: {var_name}",
                        description=(
                            f"La variable {var_name!r} del contenedor {car.container_name!r} "
                            "tiene un nombre que sugiere credencial, token o clave. Inyectar "
                            "secretos como variables de entorno los expone en `docker inspect` "
                            "y en los logs del proceso."
                        ),
                        evidence=f"{var_name}={redacted} (contenedor: {car.container_name})",
                        remediation=(
                            "Usar Docker Secrets (Swarm) o un gestor externo:\n"
                            "  docker secret create mi_password fichero.txt\n"
                            "En entornos sin Swarm, usar ficheros de secrets montados\n"
                            "en modo solo lectura y con permisos 400.\n"
                            "Alternativamente: HashiCorp Vault, AWS Secrets Manager.\n"
                            "Ref: CIS Docker Benchmark §4.6"
                        ),
                        container=car.container_name,
                    ))
                    continue  # Una alerta por variable, no duplicar

                # Valores con prefijos conocidos de token
                for pattern in SECRET_VALUE_PATTERNS:
                    if var_value and pattern.search(var_value):
                        redacted = var_value[:4] + "****" if len(var_value) > 4 else "****"
                        self._counter += 1
                        resultado.env_findings.append(Finding(
                            id=f"DOCK-{self._counter:03d}",
                            severity="HIGH",
                            category="ENV",
                            title=f"Valor con patrón de secreto en variable: {var_name}",
                            description=(
                                f"La variable {var_name!r} en {car.container_name!r} contiene "
                                "un valor que coincide con el patrón de un token conocido "
                                "(JWT, clave de API, token de acceso GitHub/GitLab/Slack/AWS…)."
                            ),
                            evidence=f"{var_name}={redacted} (contenedor: {car.container_name})",
                            remediation=(
                                "Rotar el secreto inmediatamente si está comprometido.\n"
                                "Migrar a Docker Secrets, variables de entorno desde fichero\n"
                                "con permisos restrictivos, o un gestor de secretos externo.\n"
                                "Ref: CIS Docker Benchmark §4.6"
                            ),
                            container=car.container_name,
                        ))
                        break

                # Connection strings con posibles credenciales
                if CONNECTION_STRING_VARS.search(var_name):
                    redacted = var_value[:8] + "****" if len(var_value) > 8 else "****"
                    self._counter += 1
                    resultado.env_findings.append(Finding(
                        id=f"DOCK-{self._counter:03d}",
                        severity="MEDIUM",
                        category="ENV",
                        title=f"Connection string en variable: {var_name}",
                        description=(
                            f"La variable {var_name!r} en {car.container_name!r} parece "
                            "contener una URL de conexión a base de datos que puede incluir "
                            "usuario, contraseña y host en texto claro."
                        ),
                        evidence=f"{var_name}={redacted} (contenedor: {car.container_name})",
                        remediation=(
                            "Separar las credenciales de la cadena de conexión.\n"
                            "Usar variables individuales para usuario y contraseña,\n"
                            "y gestionar la contraseña como Docker Secret.\n"
                            "Ref: OWASP Secrets Management Cheat Sheet"
                        ),
                        container=car.container_name,
                    ))

    # ── Fase 3: imágenes ───────────────────────────────────────────────────

    def _phase3_imagenes(self, resultado: DockerAuditResult) -> None:
        """
        Audita las imágenes Docker disponibles localmente.

        Detecta el uso de la etiqueta :latest (sin fijación de versión) e
        imágenes antiguas que podrían contener vulnerabilidades no parcheadas.
        """
        ok, stdout, _ = _docker(
            ["images", "--format",
             "{{.Repository}}:{{.Tag}}|{{.CreatedAt}}|{{.ID}}"]
        )
        if not ok or not stdout:
            return

        ahora = datetime.now(timezone.utc)
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            partes = line.split("|", 2)
            if len(partes) < 3:
                continue
            imagen, created_str, img_id = partes

            # Etiqueta :latest — sin fijación de versión
            if imagen.endswith(":latest") or imagen.endswith(":<none>"):
                self._counter += 1
                resultado.image_findings.append(Finding(
                    id=f"DOCK-{self._counter:03d}",
                    severity="LOW",
                    category="Imagen",
                    title=f"Imagen sin versión fija: {imagen}",
                    description=(
                        f"La imagen {imagen!r} usa la etiqueta 'latest' (o ninguna), "
                        "lo que impide garantizar reproducibilidad y puede descargar "
                        "versiones distintas en cada pull, potencialmente con regresiones "
                        "o vulnerabilidades nuevas."
                    ),
                    evidence=f"Imagen: {imagen} | ID: {img_id}",
                    remediation=(
                        "Fijar la versión de la imagen con digest SHA256 o tag semántico:\n"
                        "  FROM nginx:1.25.3\n"
                        "  FROM nginx@sha256:abc123...\n"
                        "Ref: CIS Docker Benchmark §4.8 · OCI Image Spec"
                    ),
                ))

            # Imágenes antiguas (>90 días)
            try:
                # Docker devuelve formatos variados; intentamos parsearlo
                # Ejemplos: "2024-01-15 10:23:45 +0000 UTC"
                created_clean = created_str.strip().replace(" +0000 UTC", "+00:00")
                if " " in created_clean:
                    # Reemplazar el espacio entre fecha y hora por T
                    created_clean = created_clean.replace(" ", "T", 1)
                    # Quitar el posible trailing timezone como "+0000 UTC"
                    created_clean = re.sub(r'\s+\+\d+\s+UTC$', '+00:00', created_clean)
                dt_created = datetime.fromisoformat(created_clean)
                if dt_created.tzinfo is None:
                    dt_created = dt_created.replace(tzinfo=timezone.utc)
                dias = (ahora - dt_created).days
                if dias > 90:
                    self._counter += 1
                    resultado.image_findings.append(Finding(
                        id=f"DOCK-{self._counter:03d}",
                        severity="INFO",
                        category="Imagen",
                        title=f"Imagen antigua ({dias}d) sin actualización: {imagen}",
                        description=(
                            f"La imagen {imagen!r} tiene {dias} días sin actualizarse. "
                            "Imágenes antiguas pueden contener paquetes de base con "
                            "vulnerabilidades conocidas no parcheadas."
                        ),
                        evidence=f"Imagen: {imagen} | Creada: {created_str.strip()} | {dias} días",
                        remediation=(
                            "Establecer un proceso periódico de actualización de imágenes base:\n"
                            "  docker pull <imagen>  # descargar versión actualizada\n"
                            "  docker build --pull ...\n"
                            "Usar herramientas como Trivy, Grype o Snyk para escanear\n"
                            "las imágenes en busca de CVEs conocidos."
                        ),
                    ))
            except (ValueError, TypeError):
                pass

    # ── Fase 4: redes ──────────────────────────────────────────────────────

    def _phase4_redes(self, resultado: DockerAuditResult) -> None:
        """
        Audita las redes Docker definidas en el host.

        Detecta redes en modo host y enumera las subredes configuradas.
        """
        ok, stdout, _ = _docker(
            ["network", "ls", "--format", "{{.ID}}|{{.Name}}|{{.Driver}}"]
        )
        if not ok or not stdout:
            return

        redes_host: list[str] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            partes = line.split("|", 2)
            if len(partes) < 3:
                continue
            net_id, net_name, driver = partes

            if driver == "host":
                redes_host.append(net_name)

        if redes_host:
            self._counter += 1
            resultado.network_findings.append(Finding(
                id=f"DOCK-{self._counter:03d}",
                severity="INFO",
                category="Red",
                title=f"Redes en modo host detectadas: {', '.join(redes_host)}",
                description=(
                    "Existen redes Docker en modo host. Los contenedores conectados "
                    "a ellas comparten la pila de red del sistema anfitrión (ya "
                    "reportado por contenedor si aplica)."
                ),
                evidence="Redes host: " + ", ".join(redes_host),
                remediation=(
                    "Migrar a redes de tipo bridge con publicación de puertos explícita.\n"
                    "Ref: CIS Docker Benchmark §5.15"
                ),
            ))

    # ── Fase 5: volúmenes ──────────────────────────────────────────────────

    def _phase5_volumenes(self, resultado: DockerAuditResult) -> None:
        """
        Enumera los volúmenes Docker registrados en el host.

        Actualmente genera un hallazgo INFO de inventario. Volúmenes sensibles
        via bind mount ya se detectan en la fase de contenedores.
        """
        ok, stdout, _ = _docker(
            ["volume", "ls", "--format", "{{.Name}}|{{.Driver}}"]
        )
        if not ok or not stdout:
            return

        volumenes = [l.strip() for l in stdout.splitlines() if l.strip()]
        if volumenes:
            self._counter += 1
            resultado.network_findings.append(Finding(
                id=f"DOCK-{self._counter:03d}",
                severity="INFO",
                category="Volumen",
                title=f"Inventario de volúmenes Docker ({len(volumenes)} encontrados)",
                description=(
                    "Se han encontrado los siguientes volúmenes Docker registrados en el host. "
                    "Revisar que no contengan datos sensibles sin cifrar y que los permisos "
                    "de acceso en el host sean adecuados."
                ),
                evidence="Volúmenes: " + " | ".join(volumenes[:20])
                         + (" …" if len(volumenes) > 20 else ""),
                remediation=(
                    "Documentar el propósito de cada volumen.\n"
                    "Eliminar volúmenes huérfanos: docker volume prune\n"
                    "Cifrar datos sensibles en reposo dentro de los volúmenes.\n"
                    "Ref: CIS Docker Benchmark §7"
                ),
            ))

    # ── Fase 6: secretos en historia de capas de imagen (v1.1) ────────────

    def _phase6_layer_secrets(self, resultado: DockerAuditResult) -> None:
        """
        Fase 6 — Análisis de secretos en historia de capas de imágenes.

        Ejecuta 'docker history --no-trunc' sobre cada imagen en uso y busca
        en los comandos RUN/ENV/ARG patrones de secretos conocidos (mismos
        regex que vamp-secrets-scanner). Cualquier coincidencia genera un
        hallazgo CRITICAL "Secret in image layer history".

        Los secretos en capas son persistentes: aunque se sobreescriban en
        capas posteriores son recuperables inspeccionando la capa afectada.
        """
        # Recopilar imágenes únicas de los contenedores auditados + imágenes locales
        imagenes_en_uso: set[str] = set()
        for car in resultado.containers:
            if car.image and not car.image.endswith("<none>"):
                imagenes_en_uso.add(car.image)

        ok, stdout, _ = _docker(["images", "--format", "{{.Repository}}:{{.Tag}}"])
        if ok and stdout:
            for line in stdout.splitlines():
                line = line.strip()
                if line and "<none>" not in line:
                    imagenes_en_uso.add(line)

        if not imagenes_en_uso:
            return

        # Evitar analizar la misma imagen dos veces (por distintos alias)
        imagenes_procesadas: set[str] = set()

        for imagen in sorted(imagenes_en_uso):
            if imagen in imagenes_procesadas:
                continue
            imagenes_procesadas.add(imagen)

            ok, stdout, _ = _docker(
                ["history", "--no-trunc", "--format", "{{.CreatedBy}}", imagen],
                timeout=20,
            )
            if not ok or not stdout:
                continue

            for linea in stdout.splitlines():
                linea = linea.strip()
                if not linea:
                    continue

                for patron, descripcion in LAYER_SECRET_PATTERNS:
                    match = patron.search(linea)
                    if match:
                        match_texto = match.group(0)
                        # Redactar el valor para no exponer el secreto real
                        redacted = match_texto[:8] + "****" if len(match_texto) > 8 else "****"
                        self._counter += 1
                        resultado.image_findings.append(Finding(
                            id=f"DOCK-{self._counter:03d}",
                            severity="CRITICAL",
                            category="Imagen",
                            title=f"Secreto en historia de capa de imagen: {imagen}",
                            description=(
                                f"Se ha detectado un posible secreto en la historia de "
                                f"capas de la imagen '{imagen}'. Tipo: {descripcion}. "
                                "Los secretos en capas de imagen son persistentes — aunque "
                                "se sobreescriban en capas posteriores son recuperables "
                                "inspeccionando las capas anteriores con 'docker history'."
                            ),
                            evidence=(
                                f"Imagen: {imagen}\n"
                                f"Capa: ...{linea[-120:]}\n"
                                f"Patrón detectado: {redacted}"
                            ),
                            remediation=(
                                "1. Rotar inmediatamente el secreto expuesto.\n"
                                "2. Reconstruir la imagen desde cero sin el secreto en el Dockerfile:\n"
                                "   - No usar RUN con credenciales en claro\n"
                                "   - No usar ENV para inyectar secretos en build time\n"
                                "3. Usar Docker BuildKit secrets:\n"
                                "   RUN --mount=type=secret,id=mi_secreto cat /run/secrets/mi_secreto\n"
                                "4. Eliminar la imagen comprometida del registro y todos sus tags.\n"
                                "Ref: CIS Docker Benchmark §4.10 · OWASP Docker Security"
                            ),
                        ))
                        break  # Un hallazgo por línea; evitar múltiples patrones sobre la misma

    # ── Fase 7: CVEs específicos (v1.2) ────────────────────────────────────

    def _phase7_cve_checks(self, resultado: DockerAuditResult) -> None:
        """
        Fase 7 — Comprobaciones de CVEs específicos (v1.2).

        Cubre los siguientes vectores:
          - CVE-2026-34040: Docker AuthZ Plugin Bypass
          - CVE-2025-52881: runc Container Escape
          - AppArmor no habilitado en Linux (DOCK-SEC-010)
          - Resumen de contenedores con socket Docker montado (DOCK-AUTHZ-003)
        """
        self._check_cve_authz(resultado)
        self._check_cve_runc(resultado)
        self._check_apparmor(resultado)
        self._check_authz_sock_resumen(resultado)

    def _check_cve_authz(self, resultado: DockerAuditResult) -> None:
        """
        CVE-2026-34040 — Docker AuthZ Plugin Bypass.

        Si hay plugins de autorización (AuthZ) activos, obtiene la versión del
        daemon y comprueba si es vulnerable. Un atacante con acceso al socket
        puede eludir los plugins AuthZ mediante peticiones HTTP con
        Transfer-Encoding chunked manipulado.

        Versiones afectadas:
          - Rama 27.x: < 27.5.1
          - Rama 26.x: < 26.1.9
          - Rama 25.x: < 25.0.9
        """
        # Obtener plugins AuthZ activos del daemon
        ok, stdout, _ = _docker(
            ["info", "--format", "{{json .Plugins.Authorization}}"]
        )
        if not ok or not stdout or stdout.strip() in ("null", "[]", ""):
            return  # Sin plugins AuthZ activos, no hay riesgo

        try:
            plugins = json.loads(stdout.strip())
        except json.JSONDecodeError:
            plugins = [stdout.strip()]

        # Lista vacía o nula → sin riesgo
        if not plugins:
            return

        plugins_str = (
            ", ".join(plugins) if isinstance(plugins, list) else str(plugins)
        )

        # Obtener versión del daemon para determinar si es vulnerable
        ok_v, daemon_ver, _ = _docker(
            ["version", "--format", "{{.Server.Version}}"]
        )

        if not ok_v or not daemon_ver.strip():
            # No se puede determinar la versión: alerta de precaución (HIGH)
            resultado.image_findings.append(Finding(
                id="DOCK-AUTHZ-002",
                severity="HIGH",
                category="CVE",
                title="CVE-2026-34040: Plugin AuthZ activo — versión daemon no determinada",
                description=(
                    "Hay plugins de autorización (AuthZ) activos en el daemon Docker. "
                    "No se ha podido determinar la versión del daemon para confirmar "
                    "si es vulnerable a CVE-2026-34040. Este CVE permite eludir los "
                    "plugins AuthZ mediante peticiones HTTP con Transfer-Encoding "
                    "chunked manipulado, obteniendo acceso no autorizado al daemon. "
                    "Verificar manualmente si el daemon está en una versión parcheada."
                ),
                evidence=f"Plugins AuthZ activos: {plugins_str}",
                remediation=(
                    "Actualizar el daemon Docker a una versión parcheada:\n"
                    "  Rama 27.x → 27.5.1 o superior\n"
                    "  Rama 26.x → 26.1.9 o superior\n"
                    "  Rama 25.x → 25.0.9 o superior\n"
                    "Verificar versión actual: docker version --format '{{.Server.Version}}'\n"
                    "Ref: CVE-2026-34040 · Docker Security Advisory"
                ),
            ))
            return

        daemon_ver = daemon_ver.strip()
        if self._is_authz_daemon_vulnerable(daemon_ver):
            resultado.image_findings.append(Finding(
                id="DOCK-AUTHZ-001",
                severity="CRITICAL",
                category="CVE",
                title=(
                    f"CVE-2026-34040: Plugin AuthZ activo con daemon Docker vulnerable "
                    f"({daemon_ver})"
                ),
                description=(
                    f"El daemon Docker v{daemon_ver} tiene plugins de autorización "
                    f"activos ({plugins_str}) y es vulnerable a CVE-2026-34040. "
                    "Este CVE permite eludir los plugins AuthZ mediante peticiones "
                    "HTTP con Transfer-Encoding chunked manipulado, obteniendo acceso "
                    "no autorizado al daemon. La combinación de AuthZ activo con "
                    "versión vulnerable es directamente explotable."
                ),
                evidence=(
                    f"Daemon: {daemon_ver} | Plugins AuthZ: {plugins_str}"
                ),
                remediation=(
                    "URGENTE — Actualizar el daemon Docker inmediatamente:\n"
                    "  Rama 27.x → 27.5.1 o superior\n"
                    "  Rama 26.x → 26.1.9 o superior\n"
                    "  Rama 25.x → 25.0.9 o superior\n"
                    "Como mitigación temporal, restringir el acceso al socket Docker\n"
                    "exclusivamente a procesos autorizados (chmod 660 + grupo docker).\n"
                    "Ref: CVE-2026-34040 · Docker Security Advisory"
                ),
            ))

    def _is_authz_daemon_vulnerable(self, version_str: str) -> bool:
        """
        Determina si una versión del daemon Docker es vulnerable a CVE-2026-34040.

        Versiones parcheadas por rama:
          - 27.x → 27.5.1 o superior
          - 26.x → 26.1.9 o superior
          - 25.x → 25.0.9 o superior

        Versiones de otras ramas (< 25 o > 27) se consideran fuera del alcance
        conocido del CVE y se devuelve False (sin falsos positivos).
        """
        match = re.match(r"^(\d+)\.(\d+)\.(\d+)", version_str)
        if not match:
            return False
        major = int(match.group(1))
        minor = int(match.group(2))
        patch_v = int(match.group(3))

        if major == 27:
            # Vulnerable si < 27.5.1
            return (minor, patch_v) < (5, 1)
        elif major == 26:
            # Vulnerable si < 26.1.9
            return (minor, patch_v) < (1, 9)
        elif major == 25:
            # Vulnerable si < 25.0.9
            return (minor, patch_v) < (0, 9)

        # Ramas no cubiertas por el CVE conocido
        return False

    def _check_cve_runc(self, resultado: DockerAuditResult) -> None:
        """
        CVE-2025-52881 — runc Container Escape.

        Comprueba la versión de runc instalada y si seccomp está habilitado
        como mecanismo de mitigación parcial.

        Versiones parcheadas:
          - runc >= 1.2.8  (rama 1.2.x)
          - runc >= 1.3.3  (rama 1.3.x)
          - runc >= 1.4.0-rc.3 (rama 1.4.x)

        Versiones 1.0.x y 1.1.x son vulnerables.
        """
        # 1. Obtener versión de runc e informar si es vulnerable
        runc_ver = self._get_runc_version()
        if runc_ver and self._is_runc_vulnerable(runc_ver):
            resultado.image_findings.append(Finding(
                id="DOCK-RUNC-001",
                severity="CRITICAL",
                category="CVE",
                title=f"CVE-2025-52881: Versión runc vulnerable ({runc_ver})",
                description=(
                    f"La versión de runc instalada ({runc_ver}) es vulnerable a "
                    "CVE-2025-52881, que permite la escapada del contenedor mediante "
                    "una condición de carrera en la gestión de namespaces de red al "
                    "arrancar el proceso de inicio del contenedor. Un atacante con "
                    "capacidad de ejecutar contenedores puede obtener acceso root "
                    "en el host."
                ),
                evidence=f"runc versión detectada: {runc_ver}",
                remediation=(
                    "Actualizar runc a una versión parcheada:\n"
                    "  Rama 1.2.x → 1.2.8 o superior\n"
                    "  Rama 1.3.x → 1.3.3 o superior\n"
                    "  Rama 1.4.x → 1.4.0-rc.3 o superior\n"
                    "En sistemas Debian/Ubuntu:\n"
                    "  apt-get update && apt-get upgrade runc\n"
                    "O actualizar Docker Engine, que distribuye runc actualizado:\n"
                    "  apt-get upgrade docker-ce\n"
                    "Ref: CVE-2025-52881 · runc Security Advisory"
                ),
            ))

        # 2. Comprobar si seccomp está habilitado por defecto (mitigación parcial)
        ok, stdout, _ = _docker(["info", "--format", "{{.SecurityOptions}}"])
        if ok and stdout:
            if "seccomp" not in stdout.lower():
                resultado.image_findings.append(Finding(
                    id="DOCK-RUNC-002",
                    severity="HIGH",
                    category="CVE",
                    title="Seccomp no habilitado por defecto — mitigación CVE-2025-52881 ausente",
                    description=(
                        "El perfil seccomp por defecto no está activo en este entorno Docker. "
                        "Seccomp restringe las syscalls disponibles para los contenedores y "
                        "actúa como capa de defensa adicional frente a escapadas de contenedor, "
                        "incluyendo CVE-2025-52881. Sin seccomp, el riesgo de explotación "
                        "de vulnerabilidades de escapada es significativamente mayor."
                    ),
                    evidence=f"SecurityOptions del daemon: {stdout.strip()}",
                    remediation=(
                        "Habilitar el perfil seccomp por defecto en el daemon Docker.\n"
                        "En /etc/docker/daemon.json añadir o verificar:\n"
                        '  {"seccomp-profile": "/etc/docker/seccomp.json"}\n'
                        "El perfil por defecto de Docker ya restringe las syscalls más "
                        "peligrosas y está incluido en la instalación estándar.\n"
                        "Verificar: docker info | grep -i seccomp\n"
                        "Ref: Docker Security — Seccomp profiles · CVE-2025-52881"
                    ),
                ))

    def _get_runc_version(self) -> Optional[str]:
        """
        Obtiene la versión semántica de runc del sistema.

        Intenta primero con 'runc --version' (da versión legible).
        Como fallback intenta extraer el ID de commit de 'docker info'
        (no es una versión semántica, pero registra disponibilidad).

        Retorna la versión semántica (p.ej. "1.1.12") o None si no se puede
        determinar de forma fiable.
        """
        # Intentar obtener versión semántica directamente de runc
        try:
            res = subprocess.run(
                ["runc", "--version"],
                capture_output=True, text=True, timeout=10,
            )
            if res.returncode == 0 and res.stdout:
                # Formato habitual: "runc version 1.1.12\ncommit: ...\nspec: ..."
                match = re.search(r"runc version (\S+)", res.stdout)
                if match:
                    return match.group(1)
        except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
            pass

        # Fallback: docker info devuelve el hash de commit de runc, no la versión
        # Solo lo intentamos para documentación; no sirve para comparación semántica
        ok, stdout, _ = _docker(
            ["info", "--format", "{{.RuncCommit.ID}}"]
        )
        # Si docker info reporta un commit hash válido pero no tenemos versión,
        # devolvemos None para no generar falsos positivos en la comparación
        return None

    def _is_runc_vulnerable(self, version_str: str) -> bool:
        """
        Determina si una versión de runc es vulnerable a CVE-2025-52881.

        Versiones parcheadas:
          - 1.2.x: >= 1.2.8
          - 1.3.x: >= 1.3.3
          - 1.4.x: >= 1.4.0-rc.3 (o cualquier 1.4.0 release)

        Las ramas 1.0.x y 1.1.x se consideran vulnerables (sin parche oficial).
        """
        # Parsear versión incluyendo sufijos de pre-release tipo "rc.N"
        match = re.match(r"^(\d+)\.(\d+)\.(\d+)(?:-rc\.(\d+))?", version_str)
        if not match:
            return False

        major    = int(match.group(1))
        minor    = int(match.group(2))
        patch_v  = int(match.group(3))
        rc_num   = int(match.group(4)) if match.group(4) else None

        # Solo aplica a la rama 1.x de runc
        if major != 1:
            return False

        if minor == 2:
            # Parcheado en >= 1.2.8
            return patch_v < 8
        elif minor == 3:
            # Parcheado en >= 1.3.3
            return patch_v < 3
        elif minor == 4:
            if patch_v > 0:
                return False  # 1.4.1+ está parcheado
            # Es 1.4.0 o 1.4.0-rc.N
            if rc_num is None:
                return False  # 1.4.0 release final está parcheado
            return rc_num < 3  # rc.1 y rc.2 son vulnerables; rc.3+ parcheado
        elif minor <= 1:
            # Ramas 1.0.x y 1.1.x — sin parche oficial, vulnerables
            return True

        # Ramas futuras (1.5+) se asumen parcheadas
        return False

    def _check_apparmor(self, resultado: DockerAuditResult) -> None:
        """
        DOCK-SEC-010 — Comprobación de AppArmor habilitado (solo Linux).

        AppArmor es un mecanismo de control de acceso obligatorio (MAC) que
        restringe las operaciones de los contenedores en el host. Si no está
        activo en un sistema Linux, el aislamiento de los contenedores es menor.
        """
        # AppArmor solo aplica en Linux; en macOS/Windows no es relevante
        if platform.system() != "Linux":
            return

        ok, stdout, _ = _docker(["info", "--format", "{{.SecurityOptions}}"])
        if not ok or not stdout:
            return

        if "apparmor" not in stdout.lower():
            resultado.image_findings.append(Finding(
                id="DOCK-SEC-010",
                severity="MEDIUM",
                category="Entorno",
                title="AppArmor no habilitado en el daemon Docker (Linux)",
                description=(
                    "El daemon Docker no reporta AppArmor como mecanismo de seguridad "
                    "activo. En sistemas Linux, AppArmor proporciona control de acceso "
                    "obligatorio (MAC) que restringe las operaciones disponibles para "
                    "los procesos dentro de los contenedores, limitando el impacto de "
                    "una posible escapada o compromiso de contenedor."
                ),
                evidence=f"SecurityOptions del daemon: {stdout.strip()}",
                remediation=(
                    "Habilitar AppArmor en el sistema e instalar el perfil Docker:\n"
                    "  apt-get install apparmor apparmor-utils\n"
                    "  systemctl enable apparmor && systemctl start apparmor\n"
                    "El perfil 'docker-default' se activa automáticamente al "
                    "reiniciar el daemon Docker.\n"
                    "Verificar estado: docker info | grep -i apparmor\n"
                    "Ref: CIS Docker Benchmark §5.1 · Docker AppArmor Security Profile"
                ),
            ))

    def _check_authz_sock_resumen(self, resultado: DockerAuditResult) -> None:
        """
        DOCK-AUTHZ-003 — Resumen de contenedores con socket Docker montado.

        Genera un hallazgo host-level que agrupa todos los contenedores en marcha
        que tienen /var/run/docker.sock montado. Complementa los hallazgos
        individuales DOCK-004 de la fase 1 con un vector adicional relacionado
        con CVE-2026-34040: si hay un plugin AuthZ activo, la presencia del
        socket en un contenedor permite ejecutar la escalada directamente desde
        dentro del contenedor comprometido.
        """
        contenedores_con_sock: list[str] = []

        for car in resultado.containers:
            data = _docker_inspect(car.container_name)
            if data is None:
                continue
            mounts = data.get("Mounts", [])
            for m in mounts:
                if "docker.sock" in m.get("Source", ""):
                    contenedores_con_sock.append(car.container_name)
                    break  # Un contenedor puede tener el sock en varios mounts; contarlo una vez

        if not contenedores_con_sock:
            return

        num = len(contenedores_con_sock)
        resultado.image_findings.append(Finding(
            id="DOCK-AUTHZ-003",
            severity="CRITICAL",
            category="CVE",
            title=(
                f"Socket Docker montado en {num} contenedor(es) en marcha "
                "(vector CVE-2026-34040)"
            ),
            description=(
                f"{num} contenedor(es) en ejecución tienen el socket Docker "
                "(/var/run/docker.sock) montado como volumen. Cualquier proceso "
                "dentro de esos contenedores puede comunicarse directamente con el "
                "daemon, crear contenedores privilegiados y obtener acceso root en "
                "el host. En presencia de CVE-2026-34040, este escenario también "
                "permite eludir los plugins de autorización (AuthZ) activos, "
                "amplificando el impacto del bypass."
            ),
            evidence=(
                f"Contenedores con socket montado: {', '.join(contenedores_con_sock)}"
            ),
            remediation=(
                "Eliminar el montaje del socket Docker de todos los contenedores listados.\n"
                "Alternativas si el contenedor necesita gestionar otros contenedores:\n"
                "  1. docker-socket-proxy: restringe los métodos de API expuestos\n"
                "     (https://github.com/Tecnativa/docker-socket-proxy)\n"
                "  2. Docker-in-Docker (DinD) con TLS y credenciales rotativas\n"
                "  3. API de Kubernetes si el entorno lo permite\n"
                "Ref: CIS Docker Benchmark §5.31 · CVE-2026-34040"
            ),
        ))

    def _generate_sbom(
        self,
        container_id_or_name: str,
        output_dir: Optional[str] = None,
    ) -> dict:
        """
        Genera un SBOM CycloneDX 1.4 para un contenedor específico (v1.3).

        Inspecciona el contenedor para obtener la imagen base, detecta el SO
        y extrae la lista de paquetes instalados vía dpkg (Debian/Ubuntu) o
        rpm (RHEL/CentOS).

        Parámetros
        ----------
        container_id_or_name : ID o nombre del contenedor Docker
        output_dir           : Si se indica, guarda el resultado en
                               <output_dir>/sbom-<contenedor>.json

        Retorna
        -------
        dict — SBOM en formato CycloneDX 1.4; clave 'error' si falla.
        """
        # Obtener metadatos del contenedor vía docker inspect
        ok, stdout, _ = _docker(["inspect", container_id_or_name], timeout=15)
        if not ok or not stdout:
            return {"error": f"No se pudo inspeccionar el contenedor '{container_id_or_name}'"}

        try:
            data = json.loads(stdout)
            if not (isinstance(data, list) and data):
                return {"error": "Respuesta de inspect inesperada"}
            info = data[0]
        except (json.JSONDecodeError, TypeError):
            return {"error": "JSON de inspect inválido"}

        # Nombre del contenedor y de la imagen base
        nombre_cont = (info.get("Name") or container_id_or_name).lstrip("/")
        imagen      = info.get("Config", {}).get("Image", "")

        sbom: dict = {
            "bomFormat":    "CycloneDX",
            "specVersion":  "1.4",
            "serialNumber": f"urn:uuid:{_uuid_simple()}",
            "version":      1,
            "metadata": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "tools": [{
                    "vendor":  "VampSecure Studios",
                    "name":    TOOL_NAME,
                    "version": VERSION,
                }],
                "component": {
                    "type": "container",
                    "name": imagen,
                },
            },
            "components": [],
        }

        if not imagen:
            sbom["components_unavailable"] = True
            sbom["components_unavailable_reason"] = (
                "No se pudo determinar la imagen base del contenedor"
            )
            return sbom

        # Detectar SO arrancando un contenedor temporal
        ok_os, stdout_os, _ = _docker(
            ["run", "--rm", "--entrypoint", "", imagen, "cat", "/etc/os-release"],
            timeout=20,
        )

        componentes: list[dict] = []

        if ok_os and stdout_os:
            # Parsear nombre del SO desde /etc/os-release
            for linea in stdout_os.splitlines():
                if linea.startswith("PRETTY_NAME="):
                    os_name = linea.split("=", 1)[1].strip().strip('"')
                    componentes.append({
                        "type":    "operating-system",
                        "name":    os_name,
                        "version": "",
                    })
                    break

            # Intentar paquetes Debian/Ubuntu vía /var/lib/dpkg/status
            ok_dpkg, stdout_dpkg, _ = _docker(
                ["run", "--rm", "--entrypoint", "", imagen,
                 "sh", "-c",
                 "awk '/^Package:/{p=$2} /^Version:/{print p,$2}' "
                 "/var/lib/dpkg/status 2>/dev/null | head -200"],
                timeout=20,
            )
            if ok_dpkg and stdout_dpkg:
                for linea in stdout_dpkg.splitlines():
                    partes = linea.strip().split(None, 1)
                    if len(partes) == 2:
                        componentes.append({
                            "type":    "library",
                            "name":    partes[0],
                            "version": partes[1],
                            "purl":    f"pkg:deb/{partes[0]}@{partes[1]}",
                        })
            else:
                # Intentar paquetes RPM (RHEL/CentOS) como alternativa
                ok_rpm, stdout_rpm, _ = _docker(
                    ["run", "--rm", "--entrypoint", "", imagen,
                     "rpm", "-qa", "--queryformat", "%{NAME} %{VERSION}-%{RELEASE}\n"],
                    timeout=20,
                )
                if ok_rpm and stdout_rpm:
                    for linea in stdout_rpm.splitlines():
                        partes = linea.strip().split(None, 1)
                        if len(partes) == 2:
                            componentes.append({
                                "type":    "library",
                                "name":    partes[0],
                                "version": partes[1],
                                "purl":    f"pkg:rpm/{partes[0]}@{partes[1]}",
                            })
        else:
            # Sin shell disponible (imagen distroless, scratch, etc.)
            sbom["components_unavailable"] = True
            sbom["components_unavailable_reason"] = (
                "La imagen no tiene shell disponible para inspección de paquetes"
            )

        sbom["components"] = componentes
        n_comp = len(componentes)
        if n_comp:
            console.print(
                f"  [dim]SBOM[/dim] {nombre_cont}: "
                f"[green]{n_comp} componentes[/green]"
            )

        # Guardar en fichero si se especificó directorio de salida
        if output_dir:
            nombre_seg = re.sub(r"[^a-zA-Z0-9._-]", "_", nombre_cont)
            ruta = Path(output_dir) / f"sbom-{nombre_seg}.json"
            try:
                Path(output_dir).mkdir(parents=True, exist_ok=True)
                ruta.write_text(
                    json.dumps(sbom, indent=2, ensure_ascii=False),
                    encoding="utf-8",
                )
            except OSError:
                pass

        return sbom


# ---------------------------------------------------------------------------
# Reportes en consola Rich
# ---------------------------------------------------------------------------

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

        # Remediaciones para CRITICAL y HIGH
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
        findings: List[Finding],
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

        # Fila de totales globales
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
        """
        Serializa el resultado completo de la auditoría en formato JSON.

        Estructura:
          tool · version · generated · host · docker_version ·
          summary.by_severity · containers[] · image_findings[] ·
          network_findings[] · env_findings[]
        """
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
                "id":       car.container_id,
                "name":     car.container_name,
                "image":    car.image,
                "status":   car.status,
                "max_severity": car.max_severity,
                "findings": [_finding_dict(f) for f in car.findings],
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
                    "total_findings":   len(all_f),
                    "max_severity":     resultado.max_severity,
                    "by_severity":      by_sev,
                    "containers_audited": len(resultado.containers),
                },
                "containers":      [_container_dict(c) for c in resultado.containers],
                "image_findings":  [_finding_dict(f) for f in resultado.image_findings],
                "network_findings":[_finding_dict(f) for f in resultado.network_findings],
                "env_findings":    [_finding_dict(f) for f in resultado.env_findings],
            },
            indent=2,
            ensure_ascii=False,
        )

    # ── HTML dark-theme ────────────────────────────────────────────────────

    def to_html(self, resultado: DockerAuditResult) -> str:
        """
        Genera un informe HTML standalone con tema oscuro profesional.

        Incluye:
          · Cabecera con metadatos del host y versión de Docker
          · Panel de hallazgos de entorno, ENV, imágenes y redes
          · Sección por contenedor con tabla de hallazgos y remediaciones
          · Tabla resumen global al final
        """
        SEV_CSS = {
            "CRITICAL": "sev-crit",
            "HIGH":     "sev-high",
            "MEDIUM":   "sev-med",
            "LOW":      "sev-low",
            "INFO":     "sev-info",
        }

        generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        def _findings_table(findings: List[Finding]) -> str:
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

        # Bloques por contenedor
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

        # Hallazgos globales (entorno, imágenes, redes, ENV)
        hallazgos_globales: List[Finding] = (
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

        # Tabla resumen
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

def _findings_vsl(resultado: DockerAuditResult) -> List[VSLFinding]:
    """
    Convierte los hallazgos Docker al formato Finding unificado de VampSecure Labs.

    Se incluyen hallazgos de severidad MEDIUM, HIGH y CRITICAL. Los INFO y LOW
    se omiten del informe de cliente para mantener el foco en riesgos operativos.

    Parámetros
    ----------
    resultado : DockerAuditResult — Resultado completo de la auditoría Docker

    Retorna
    -------
    List[VSLFinding] — Lista de hallazgos en formato VSL con prefijo DOCK-NNN
    """
    INCLUIDOS = {"CRITICAL", "HIGH", "MEDIUM"}
    hallazgos: List[VSLFinding] = []

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


# ---------------------------------------------------------------------------
# SBOM — Software Bill of Materials (CycloneDX simplificado) — v1.1
# ---------------------------------------------------------------------------

def _uuid_simple() -> str:
    """Genera un UUID v4 sin dependencias externas (solo os.urandom)."""
    b = bytearray(os.urandom(16))
    b[6] = (b[6] & 0x0F) | 0x40  # versión 4
    b[8] = (b[8] & 0x3F) | 0x80  # variante RFC 4122
    h = b.hex()
    return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def _sbom_para_imagen(image_name: str) -> dict:
    """
    Genera un SBOM básico en formato CycloneDX 1.4 para una imagen Docker.

    Ejecuta 'docker inspect' para obtener layers y metadatos, y arranca un
    contenedor temporal para obtener OS + paquetes pip + paquetes dpkg.

    Si la imagen no tiene shell disponible, marca 'components_unavailable': True.

    Retorna un diccionario con esquema CycloneDX simplificado:
      {"bomFormat":"CycloneDX","specVersion":"1.4","components":[{...}]}
    """
    sbom: dict = {
        "bomFormat":    "CycloneDX",
        "specVersion":  "1.4",
        "serialNumber": f"urn:uuid:{_uuid_simple()}",
        "version":      1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [{
                "vendor":  "VampSecure Studios",
                "name":    TOOL_NAME,
                "version": VERSION,
            }],
            "component": {
                "type": "container",
                "name": image_name,
            },
        },
        "components": [],
    }

    # Obtener metadatos e identificadores de layers vía docker inspect
    ok, stdout, _ = _docker(["inspect", image_name], timeout=15)
    if ok and stdout:
        try:
            data = json.loads(stdout)
            if isinstance(data, list) and data:
                img = data[0]
                layers = img.get("RootFS", {}).get("Layers", [])
                sbom["metadata"]["component"]["hashes"] = [
                    {"alg": "SHA-256", "content": la.replace("sha256:", "")}
                    for la in layers[:10]
                ]
                labels = img.get("Config", {}).get("Labels") or {}
                if labels:
                    sbom["metadata"]["component"]["labels"] = labels
        except (json.JSONDecodeError, TypeError, KeyError):
            pass

    # Intentar obtener OS + paquetes con un contenedor temporal
    cmd_paquetes = (
        "cat /etc/os-release 2>/dev/null; "
        "echo '---PACKAGES---'; "
        "(pip list --format=json 2>/dev/null || echo '[]'); "
        "echo '---DPKG---'; "
        "(dpkg -l 2>/dev/null | awk 'NR>5{print $2,$3}' | head -100 || echo '')"
    )
    ok, stdout, _stderr = _docker(
        ["run", "--rm", "--entrypoint", "sh", image_name, "-c", cmd_paquetes],
        timeout=30,
    )

    if not ok:
        # La imagen no tiene shell disponible (imagen distroless, scratch, etc.)
        sbom["components_unavailable"] = True
        sbom["components_unavailable_reason"] = (
            "La imagen no tiene shell disponible o el contenedor no pudo ejecutarse"
        )
        return sbom

    # Parsear la salida del contenedor temporal
    componentes: list[dict] = []

    try:
        partes_principales = stdout.split("---PACKAGES---", 1)
        os_info = partes_principales[0].strip()

        # Extraer nombre del OS
        for linea_os in os_info.splitlines():
            if linea_os.startswith("PRETTY_NAME="):
                os_name = linea_os.split("=", 1)[1].strip().strip('"')
                componentes.append({
                    "type":    "operating-system",
                    "name":    os_name,
                    "version": "",
                })
                break

        if len(partes_principales) > 1:
            resto = partes_principales[1]
            partes_pkg = resto.split("---DPKG---", 1)

            # Paquetes pip
            try:
                pip_raw = partes_pkg[0].strip()
                if pip_raw and pip_raw != "[]":
                    pip_pkgs = json.loads(pip_raw)
                    for pkg in pip_pkgs:
                        n = pkg.get("name", "")
                        v = pkg.get("version", "")
                        componentes.append({
                            "type":    "library",
                            "name":    n,
                            "version": v,
                            "purl":    f"pkg:pypi/{n.lower()}@{v}",
                        })
            except (json.JSONDecodeError, TypeError):
                pass

            # Paquetes dpkg
            if len(partes_pkg) > 1:
                for linea_dpkg in partes_pkg[1].splitlines():
                    linea_dpkg = linea_dpkg.strip()
                    if not linea_dpkg:
                        continue
                    partes_dpkg = linea_dpkg.split(None, 1)
                    if len(partes_dpkg) == 2:
                        nombre_pkg, version_pkg = partes_dpkg
                        componentes.append({
                            "type":    "library",
                            "name":    nombre_pkg,
                            "version": version_pkg,
                            "purl":    f"pkg:deb/{nombre_pkg}@{version_pkg}",
                        })
    except Exception:
        pass

    sbom["components"] = componentes
    return sbom


def _generar_sboms(
    resultado:  DockerAuditResult,
    sbom_file:  Optional[str],
    sbom_dir:   Optional[str],
    cons:       Console,
) -> None:
    """
    Orquesta la generación de SBOMs para las imágenes de los contenedores auditados.

    --sbom FILE    → genera un único JSON agregado con todos los SBOMs
    --sbom-dir DIR → genera un fichero .sbom.json por imagen en el directorio
    """
    if not sbom_file and not sbom_dir:
        return

    # Recopilar imágenes únicas de los contenedores auditados
    imagenes: set[str] = set()
    for car in resultado.containers:
        if car.image and "<none>" not in car.image:
            imagenes.add(car.image)

    if not imagenes:
        cons.print("[yellow]SBOM: No se encontraron imágenes para procesar.[/]")
        return

    sboms_generados: list[dict] = []

    cons.print(f"\n[bold cyan]Generando SBOMs para {len(imagenes)} imagen(es)…[/]\n")
    for imagen in sorted(imagenes):
        cons.print(f"  [dim]SBOM:[/dim] {imagen}…", end=" ")
        sbom = _sbom_para_imagen(imagen)
        sbom["imagen"] = imagen
        n_comp = len(sbom.get("components", []))
        estado = (
            "[yellow]sin shell[/yellow]"
            if sbom.get("components_unavailable")
            else f"[green]{n_comp} componentes[/green]"
        )
        cons.print(estado)
        sboms_generados.append(sbom)

    # Salida agregada en un único fichero
    if sbom_file:
        Path(sbom_file).write_text(
            json.dumps({"sboms": sboms_generados}, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        cons.print(f"\n[green]✔[/] SBOM agregado guardado en [bold]{sbom_file}[/]")

    # Salida por directorio (un fichero por imagen)
    if sbom_dir:
        dir_path = Path(sbom_dir)
        dir_path.mkdir(parents=True, exist_ok=True)
        for sbom in sboms_generados:
            imagen = sbom.get("imagen", "unknown")
            # Normalizar el nombre de la imagen para usarlo como nombre de fichero
            nombre_fichero = re.sub(r"[^a-zA-Z0-9._-]", "_", imagen) + ".sbom.json"
            (dir_path / nombre_fichero).write_text(
                json.dumps(sbom, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        cons.print(
            f"[green]✔[/] SBOMs individuales guardados en [bold]{sbom_dir}/[/] "
            f"({len(sboms_generados)} fichero(s))"
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
            "Auditor de seguridad de entornos Docker"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Ejemplos:
  vamp-docker-audit
  vamp-docker-audit --containers mi-app,db-postgres
  vamp-docker-audit --include-stopped --json resultado.json
  vamp-docker-audit --html informe.html --report-html cliente.html
  vamp-docker-audit --no-env-scan --client "AcmeCorp" --engagement "Pentest-2026"
        """,
    )
    p.add_argument(
        "--socket", metavar="PATH", default="/var/run/docker.sock",
        help="Ruta al socket Docker (default: /var/run/docker.sock)",
    )
    p.add_argument(
        "--containers", metavar="NOMBRES",
        help="Lista de nombres/IDs de contenedores separada por comas (default: todos)",
    )
    p.add_argument(
        "--include-stopped", action="store_true",
        help="Incluir también contenedores parados en la auditoría",
    )
    p.add_argument(
        "--no-env-scan", action="store_true",
        help="Omitir el escaneo de variables de entorno en busca de secretos",
    )
    p.add_argument(
        "--json", metavar="FICHERO",
        help="Guardar el resultado completo en formato JSON",
    )
    p.add_argument(
        "--html", metavar="FICHERO",
        help="Guardar informe en HTML dark-theme standalone",
    )

    # SBOM — Software Bill of Materials (v1.1)
    p.add_argument(
        "--sbom", metavar="FICHERO",
        help=(
            "Generar SBOM CycloneDX 1.4 agregado para todas las imágenes "
            "auditadas y guardarlo en FICHERO (JSON)"
        ),
    )
    p.add_argument(
        "--sbom-dir", metavar="DIR", dest="sbom_dir",
        help=(
            "Generar un SBOM CycloneDX 1.4 por imagen auditada y guardarlos "
            "en DIR (un fichero .sbom.json por imagen)"
        ),
    )

    # Argumentos de informe unificado VSL
    add_report_args(p)

    return p.parse_args()


def main() -> None:
    """Punto de entrada principal de la herramienta."""
    console.print(BANNER, style="bold magenta")

    args = _parse_args()

    # Parsear nombres de contenedores objetivo
    target_names: Optional[list[str]] = None
    if args.containers:
        target_names = [n.strip() for n in args.containers.split(",") if n.strip()]

    auditor = DockerAuditor(
        socket_path=args.socket,
        include_stopped=args.include_stopped,
        scan_env=not args.no_env_scan,
        target_names=target_names,
    )

    reporter = DockerReporter(console)

    console.print("[bold cyan]Iniciando auditoría de entorno Docker…[/]\n")

    with console.status("[cyan]Auditando contenedores y configuración…[/]", spinner="dots"):
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
            "[bold]Hallazgos de Entorno e Imágenes[/bold]",
            hallazgos_entorno,
        )

    if resultado.env_findings:
        reporter.print_extra_findings(
            "[bold]Hallazgos de Variables de Entorno (ENV secrets)[/bold]",
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
        console.print("[yellow]No se encontraron contenedores para auditar.[/]")

    # Tabla resumen global
    if resultado.containers:
        reporter.print_summary(resultado)

    # Exportar JSON
    if args.json:
        Path(args.json).write_text(reporter.to_json(resultado), encoding="utf-8")
        console.print(f"\n[green]✔[/] JSON guardado en [bold]{args.json}[/]")

    # Exportar HTML
    if args.html:
        Path(args.html).write_text(reporter.to_html(resultado), encoding="utf-8")
        console.print(f"[green]✔[/] HTML guardado en [bold]{args.html}[/]")

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
            console.print(f"[green]✔[/] Informe cliente HTML guardado en [bold]{args.report_html}[/]")
        if args.report_pdf:
            report.to_pdf(args.report_pdf)
            console.print(f"[green]✔[/] Informe cliente PDF guardado en [bold]{args.report_pdf}[/]")

    # Código de salida según severidad máxima global
    max_sev = resultado.max_severity
    sys.exit(2 if max_sev == "CRITICAL" else 1 if max_sev == "HIGH" else 0)


if __name__ == "__main__":
    main()
