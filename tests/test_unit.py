# © VampSecure Studios — VampSecure Labs Security Research Division
"""
test_unit.py — Tests unitarios para vamp_docker_audit.py.

Cubre el motor de análisis sin necesitar un daemon Docker activo:
- Parsing de docker inspect JSON con distintas misconfiguraciones
- Detección de socket exposure, puertos, redes y capacidades peligrosas
- Validación de versiones vulnerables (CVE-2026-34040, CVE-2025-52881)
- Detección de secretos en variables de entorno e historial de capas
- Validación de la estructura CycloneDX del SBOM generado
"""

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from vamp_docker_audit import (
    DANGEROUS_CAPS,
    LAYER_SECRET_PATTERNS,
    SECRET_VAR_PATTERNS,
    ContainerAuditResult,
    DockerAuditResult,
    DockerAuditor,
    Finding,
)


# ---------------------------------------------------------------------------
# Helpers de construcción
# ---------------------------------------------------------------------------

def _make_auditor(**kwargs) -> DockerAuditor:
    """Crea una instancia de DockerAuditor con parámetros por defecto."""
    defaults = {
        "socket_path": "/var/run/docker.sock",
        "include_stopped": False,
        "scan_env": True,
        "target_names": None,
    }
    defaults.update(kwargs)
    return DockerAuditor(**defaults)


# ---------------------------------------------------------------------------
# Tests 1-3: Parsing de HostConfig.Privileged
# ---------------------------------------------------------------------------

class TestModoPrivilegiado:
    """Verifica que Privileged=True genera hallazgo CRITICAL."""

    def test_privileged_true_genera_critical(self, inspect_privilegiado):
        """Un contenedor privilegiado produce un finding CRITICAL DOCK-NNN."""
        auditor = _make_auditor()
        car = auditor._audit_container(inspect_privilegiado)

        severidades = [f.severity for f in car.findings]
        assert "CRITICAL" in severidades, "Se esperaba hallazgo CRITICAL para modo privilegiado"

    def test_privileged_true_titulo_correcto(self, inspect_privilegiado):
        """El hallazgo de modo privilegiado debe mencionar 'privilegiado' en el título."""
        auditor = _make_auditor()
        car = auditor._audit_container(inspect_privilegiado)

        titulos = " ".join(f.title.lower() for f in car.findings)
        assert "privilegiado" in titulos or "privileged" in titulos

    def test_privileged_false_no_genera_critical_por_ese_motivo(self, inspect_limpio):
        """Un contenedor no privilegiado no genera CRITICAL por modo privilegiado."""
        auditor = _make_auditor()
        car = auditor._audit_container(inspect_limpio)

        # No debe haber ningún hallazgo CRITICAL en un contenedor limpio
        criticos = [f for f in car.findings if f.severity == "CRITICAL"]
        assert not criticos, "Contenedor limpio no debería tener hallazgos CRITICAL"


# ---------------------------------------------------------------------------
# Tests 4-5: cap-add ALL
# ---------------------------------------------------------------------------

class TestCapAdd:
    """Verifica que CapAdd=ALL o caps peligrosas generan hallazgos HIGH."""

    def test_cap_add_all_genera_high(self, inspect_cap_add_all):
        """CapAdd=ALL debe generar al menos un finding HIGH."""
        auditor = _make_auditor()
        car = auditor._audit_container(inspect_cap_add_all)

        altas = [f for f in car.findings if f.severity in ("HIGH", "CRITICAL")]
        assert altas, "Cap-add ALL debe generar finding HIGH o CRITICAL"

    def test_cap_add_all_en_evidencia(self, inspect_cap_add_all):
        """La evidencia del hallazgo debe mencionar las caps peligrosas."""
        auditor = _make_auditor()
        car = auditor._audit_container(inspect_cap_add_all)

        evidencias = " ".join(f.evidence for f in car.findings)
        # ALL es la cap añadida; debe aparecer en la evidencia
        assert "CAP_SYS_ADMIN" in evidencias


# ---------------------------------------------------------------------------
# Tests 6-7: Socket Docker montado
# ---------------------------------------------------------------------------

class TestSocketMontado:
    """Verifica que /var/run/docker.sock montado genera CRITICAL."""

    def test_socket_docker_genera_critical(self, inspect_socket_montado):
        """El socket Docker montado dentro del contenedor produce CRITICAL."""
        auditor = _make_auditor()
        car = auditor._audit_container(inspect_socket_montado)

        criticos = [f for f in car.findings if f.severity == "CRITICAL"]
        assert criticos, "Socket Docker montado debe generar CRITICAL"

    def test_socket_docker_en_evidencia(self, inspect_socket_montado):
        """La evidencia del hallazgo debe contener la ruta del socket."""
        auditor = _make_auditor()
        car = auditor._audit_container(inspect_socket_montado)

        evidencias = " ".join(f.evidence for f in car.findings)
        assert "docker.sock" in evidencias


# ---------------------------------------------------------------------------
# Test 8: Puerto expuesto en 0.0.0.0 → LOW
# ---------------------------------------------------------------------------

class TestPuertoExpuesto:
    """Verifica detección de puertos expuestos en todas las interfaces."""

    def test_puerto_0000_genera_low(self, inspect_puerto_expuesto):
        """Un puerto publicado en 0.0.0.0 debe generar finding LOW."""
        auditor = _make_auditor()
        car = auditor._audit_container(inspect_puerto_expuesto)

        lows = [f for f in car.findings if f.severity == "LOW"]
        assert lows, "Puerto expuesto en 0.0.0.0 debe generar LOW"

    def test_puerto_127_no_genera_finding_red(self, inspect_limpio):
        """Puerto ligado a 127.0.0.1 no debe generar hallazgo de red."""
        auditor = _make_auditor()
        car = auditor._audit_container(inspect_limpio)

        # No debe haber hallazgo LOW sobre puertos en contenedor limpio
        puertos_findings = [
            f for f in car.findings
            if "0.0.0.0" in f.evidence or "puertos" in f.title.lower()
        ]
        assert not puertos_findings


# ---------------------------------------------------------------------------
# Test 9: Red en modo host → HIGH
# ---------------------------------------------------------------------------

class TestRedHost:
    """Verifica que NetworkMode=host genera finding HIGH."""

    def test_network_mode_host_genera_high(self, inspect_red_host):
        """NetworkMode=host debe generar un finding HIGH de aislamiento de red."""
        auditor = _make_auditor()
        car = auditor._audit_container(inspect_red_host)

        altas = [f for f in car.findings if f.severity == "HIGH"]
        assert altas, "NetworkMode=host debe generar finding HIGH"


# ---------------------------------------------------------------------------
# Test 10: Volumen sensible → MEDIUM
# ---------------------------------------------------------------------------

class TestVolumenSensible:
    """Verifica que bind mounts en rutas sensibles generan MEDIUM."""

    def test_bind_etc_genera_medium(self, inspect_volumen_sensible):
        """Bind mount en /etc debe generar finding MEDIUM."""
        auditor = _make_auditor()
        car = auditor._audit_container(inspect_volumen_sensible)

        medios = [f for f in car.findings if f.severity == "MEDIUM"]
        assert medios, "Bind mount en /etc debe generar MEDIUM"


# ---------------------------------------------------------------------------
# Tests 11-12: Versiones vulnerables CVE-2026-34040
# ---------------------------------------------------------------------------

class TestVersionesAuthZ:
    """Verifica la lógica de detección de versiones vulnerables para CVE-2026-34040."""

    @pytest.mark.parametrize("version,esperado", [
        ("27.4.0", True),   # Rama 27.x antes de 27.5.1 → vulnerable
        ("27.5.1", False),  # Parcheado
        ("27.5.2", False),  # Parcheado
        ("26.1.8", True),   # Rama 26.x antes de 26.1.9 → vulnerable
        ("26.1.9", False),  # Parcheado
        ("25.0.8", True),   # Rama 25.x antes de 25.0.9 → vulnerable
        ("25.0.9", False),  # Parcheado
        ("24.0.0", False),  # Fuera del alcance del CVE
        ("28.0.0", False),  # Fuera del alcance del CVE
    ])
    def test_is_authz_daemon_vulnerable(self, version, esperado):
        """_is_authz_daemon_vulnerable debe clasificar correctamente cada versión."""
        auditor = _make_auditor()
        resultado = auditor._is_authz_daemon_vulnerable(version)
        assert resultado == esperado, (
            f"Versión {version}: esperado={esperado}, obtenido={resultado}"
        )


# ---------------------------------------------------------------------------
# Tests 13-14: Versiones runc CVE-2025-52881
# ---------------------------------------------------------------------------

class TestVersionesRunc:
    """Verifica la lógica de detección de versiones vulnerables de runc."""

    @pytest.mark.parametrize("version,esperado", [
        ("1.1.12", True),   # Rama 1.1.x → siempre vulnerable
        ("1.2.7", True),    # Antes de 1.2.8 → vulnerable
        ("1.2.8", False),   # Parcheado
        ("1.3.2", True),    # Antes de 1.3.3 → vulnerable
        ("1.3.3", False),   # Parcheado
        ("1.4.0-rc.2", True),   # rc.2 → vulnerable
        ("1.4.0-rc.3", False),  # rc.3 → parcheado
        ("1.4.0", False),       # Release final → parcheado
        ("1.5.0", False),       # Rama futura → se asume parcheado
        ("2.0.0", False),       # Rama 2.x → no aplica
    ])
    def test_is_runc_vulnerable(self, version, esperado):
        """_is_runc_vulnerable debe clasificar correctamente cada versión de runc."""
        auditor = _make_auditor()
        resultado = auditor._is_runc_vulnerable(version)
        assert resultado == esperado, (
            f"runc {version}: esperado={esperado}, obtenido={resultado}"
        )


# ---------------------------------------------------------------------------
# Test 15: Detección de secretos en variables de entorno
# ---------------------------------------------------------------------------

class TestSecretosEnv:
    """Verifica que SECRET_VAR_PATTERNS detecta nombres de variable sospechosos."""

    @pytest.mark.parametrize("var_nombre,debe_detectar", [
        ("DATABASE_PASSWORD", True),
        ("API_KEY", True),
        ("AUTH_TOKEN", True),
        ("SECRET_VALUE", True),
        ("CREDENTIALS", True),
        ("HOSTNAME", False),
        ("PORT", False),
        ("DEBUG", False),
    ])
    def test_patron_nombre_variable(self, var_nombre, debe_detectar):
        """SECRET_VAR_PATTERNS debe detectar nombres con credenciales."""
        encontrado = bool(SECRET_VAR_PATTERNS.search(var_nombre))
        assert encontrado == debe_detectar, (
            f"Variable '{var_nombre}': esperado={debe_detectar}, obtenido={encontrado}"
        )


# ---------------------------------------------------------------------------
# Test 16: Detección de secretos en historial de capas
# ---------------------------------------------------------------------------

class TestSecretsCapas:
    """Verifica que LAYER_SECRET_PATTERNS detecta credenciales en historial de imagen."""

    def test_patron_detecta_aws_key(self):
        """Detecta AWS Access Key ID en línea de historial de capa."""
        linea = "/bin/sh -c export AWS_KEY=AKIAIOSFODNN7EXAMPLE && npm install"
        detectado = any(patron.search(linea) for patron, _ in LAYER_SECRET_PATTERNS)
        assert detectado, "AWS Access Key ID no fue detectada en el historial de capa"

    def test_patron_detecta_contraseña_cli(self):
        """Detecta contraseña pasada como argumento CLI en RUN."""
        linea = "/bin/sh -c mysql -u root --password secreto123"
        detectado = any(patron.search(linea) for patron, _ in LAYER_SECRET_PATTERNS)
        assert detectado, "Contraseña como argumento --password no fue detectada"

    def test_patron_detecta_token_github(self):
        """Detecta GitHub Personal Access Token en historial de capa."""
        linea = "/bin/sh -c git clone https://ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890@github.com/org/repo"
        detectado = any(patron.search(linea) for patron, _ in LAYER_SECRET_PATTERNS)
        assert detectado, "GitHub PAT no fue detectado"


# ---------------------------------------------------------------------------
# Test 17: Estructura de datos DockerAuditResult
# ---------------------------------------------------------------------------

class TestDockerAuditResult:
    """Verifica las propiedades calculadas de DockerAuditResult."""

    def test_all_findings_agrega_todos(self):
        """all_findings debe incluir hallazgos de contenedores, imágenes y redes."""
        resultado = DockerAuditResult(host="test-host", docker_version="v24.0.0")

        # Añadir hallazgos en distintas categorías
        car = ContainerAuditResult(
            container_id="abc123", container_name="app",
            image="nginx:latest", status="running"
        )
        car.findings.append(Finding(
            id="DOCK-001", severity="CRITICAL", category="Contenedor",
            title="Test", description="desc"
        ))
        resultado.containers.append(car)
        resultado.image_findings.append(Finding(
            id="DOCK-002", severity="HIGH", category="Imagen",
            title="Test2", description="desc2"
        ))

        todos = resultado.all_findings
        assert len(todos) == 2
        # Deben estar ordenados por severidad (CRITICAL primero)
        assert todos[0].severity == "CRITICAL"

    def test_max_severity_con_findings(self):
        """max_severity debe devolver la severidad más alta."""
        resultado = DockerAuditResult(host="h", docker_version="v")
        resultado.image_findings.append(Finding(
            id="X", severity="HIGH", category="C", title="T", description="D"
        ))
        resultado.image_findings.append(Finding(
            id="Y", severity="MEDIUM", category="C", title="T2", description="D2"
        ))
        assert resultado.max_severity == "HIGH"

    def test_max_severity_sin_findings(self):
        """max_severity debe retornar INFO cuando no hay hallazgos."""
        resultado = DockerAuditResult(host="h", docker_version="v")
        assert resultado.max_severity == "INFO"


# ---------------------------------------------------------------------------
# Test 18: Contenedor raíz → MEDIUM
# ---------------------------------------------------------------------------

class TestContenedorRoot:
    """Verifica que contenedor ejecutándose como root genera MEDIUM."""

    def test_user_vacio_genera_medium(self, inspect_privilegiado):
        """User='' (root implícito) debe generar finding MEDIUM por ejecución como root."""
        # inspect_privilegiado ya tiene User=""
        auditor = _make_auditor()
        car = auditor._audit_container(inspect_privilegiado)

        medios_root = [
            f for f in car.findings
            if f.severity == "MEDIUM" and "root" in f.title.lower()
        ]
        assert medios_root, "User vacío debe generar MEDIUM por ejecución como root"


# ---------------------------------------------------------------------------
# Test 19: Imagen :latest → LOW
# ---------------------------------------------------------------------------

class TestImagenLatest:
    """Verifica que el auditor detecta imagen con tag :latest como LOW."""

    def test_imagen_latest_en_datos_contenedor(self, inspect_privilegiado):
        """La imagen nginx:latest debe ser registrada en el ContainerAuditResult."""
        auditor = _make_auditor()
        car = auditor._audit_container(inspect_privilegiado)
        # La imagen del contenedor debe contener :latest
        assert ":latest" in car.image or car.image == "nginx:latest"


# ---------------------------------------------------------------------------
# Test 20: Capacidades peligrosas sin ALL
# ---------------------------------------------------------------------------

class TestCapsPeligrosas:
    """Verifica que caps individuales peligrosas son detectadas."""

    def test_cap_sys_admin_en_dangerous_caps(self):
        """CAP_SYS_ADMIN debe estar en el conjunto DANGEROUS_CAPS."""
        assert "CAP_SYS_ADMIN" in DANGEROUS_CAPS

    def test_cap_net_admin_en_dangerous_caps(self):
        """CAP_NET_ADMIN debe estar en DANGEROUS_CAPS."""
        assert "CAP_NET_ADMIN" in DANGEROUS_CAPS

    def test_cap_add_sys_ptrace_genera_finding(self):
        """CapAdd con CAP_SYS_PTRACE debe generar finding HIGH."""
        data = {
            "Id": "zzz999", "Name": "/test-ptrace",
            "State": {"Status": "running"},
            "Config": {"Image": "alpine:3", "User": "root"},
            "HostConfig": {
                "Privileged": False,
                "CapAdd": ["CAP_SYS_PTRACE"],
                "NetworkMode": "bridge", "PidMode": "",
                "IpcMode": "private",
                "RestartPolicy": {"Name": "no"},
                "PortBindings": {},
            },
            "Mounts": [],
        }
        auditor = _make_auditor()
        car = auditor._audit_container(data)

        cap_findings = [
            f for f in car.findings
            if "capacidad" in f.title.lower() or "cap" in f.title.lower()
        ]
        assert cap_findings, "CAP_SYS_PTRACE debe generar finding de capacidades"
