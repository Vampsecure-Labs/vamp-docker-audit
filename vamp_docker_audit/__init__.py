# © VampSecure Studios — VampSecure Labs Security Research Division
"""
vamp_docker_audit — Docker/container security auditor package.

VampSecure Labs · VampSecure Studios
Para Uso Exclusivo en Pruebas de Penetración Autorizadas — v1.5.0

Public API
----------
  from vamp_docker_audit import DockerAuditor, DockerAuditResult, Finding
  result = DockerAuditor().audit()
"""
from __future__ import annotations

from ._models import (
    VERSION,
    TOOL_NAME,
    SEVERITY_ORDER,
    SEVERITY_COLOR,
    DANGEROUS_CAPS,
    SENSITIVE_MOUNT_PREFIXES,
    SECRET_VAR_PATTERNS,
    SECRET_VALUE_PATTERNS,
    CONNECTION_STRING_VARS,
    LAYER_SECRET_PATTERNS,
    Finding,
    ContainerAuditResult,
    DockerAuditResult,
)
from ._core import (
    _docker,
    _docker_inspect,
    _uuid_simple,
    _sbom_para_imagen,
    DockerAuditor,
    apply_delta_scan,
)
from ._report import (
    DockerReporter,
    _findings_vsl,
)
from .cli import (
    main,
    _parse_args,
    _generar_sboms,
    console,
    BANNER,
)

__all__ = [
    # Version
    "VERSION",
    "TOOL_NAME",
    # Severity
    "SEVERITY_ORDER",
    "SEVERITY_COLOR",
    # Constants
    "DANGEROUS_CAPS",
    "SENSITIVE_MOUNT_PREFIXES",
    "SECRET_VAR_PATTERNS",
    "SECRET_VALUE_PATTERNS",
    "CONNECTION_STRING_VARS",
    "LAYER_SECRET_PATTERNS",
    # Data models
    "Finding",
    "ContainerAuditResult",
    "DockerAuditResult",
    # Core logic
    "_docker",
    "_docker_inspect",
    "_uuid_simple",
    "_sbom_para_imagen",
    "DockerAuditor",
    "apply_delta_scan",
    # Report
    "DockerReporter",
    "_findings_vsl",
    # CLI
    "main",
    "_parse_args",
    "_generar_sboms",
    "console",
    "BANNER",
]
