# © VampSecure Studios — VampSecure Labs Security Research Division
"""
_models.py — Constants, severity mappings, regex patterns, and data models
             for vamp-docker-audit.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

VERSION   = "1.5.0"
TOOL_NAME = "vamp-docker-audit"

# ---------------------------------------------------------------------------
# Mapas de severidad
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

# ---------------------------------------------------------------------------
# Constantes de auditoría
# ---------------------------------------------------------------------------

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
    re.compile(r"^sk_"),                         # Stripe / clave secreta de API de servicio
    re.compile(r"^pk_"),                         # Stripe public key
    re.compile(r"^ghp_"),                        # GitHub personal access token
    re.compile(r"^glpat-"),                      # GitLab personal access token
    re.compile(r"^xox[bpoa]-"),                  # Slack token
    re.compile(r"^Bearer "),                     # Bearer token
    re.compile(r"^AKIA[0-9A-Z]{16}"),           # AWS access key
    re.compile(r"^ey[A-Za-z0-9]"),              # JWT (base64 header)
    re.compile(r"^[A-Za-z0-9/+]{20,}={0,2}$"),  # Base64 genérico largo (>20 chars)
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
    findings:       list[Finding] = field(default_factory=list)

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
    containers:       list[ContainerAuditResult] = field(default_factory=list)
    image_findings:   list[Finding] = field(default_factory=list)
    network_findings: list[Finding] = field(default_factory=list)
    env_findings:     list[Finding] = field(default_factory=list)
    error:            str | None = None

    @property
    def all_findings(self) -> list[Finding]:
        """Todos los hallazgos del entorno, ordenados por severidad."""
        found: list[Finding] = []
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
