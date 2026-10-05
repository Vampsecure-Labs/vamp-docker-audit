# © VampSecure Studios — VampSecure Labs Security Research Division
"""
test_integration.py — Tests de integración para vamp_docker_audit.py.

Prueba el motor de auditoría con subprocess mockeado o contra el daemon
Docker local cuando está disponible. Verifica flujos end-to-end completos.
"""

import json
import shutil
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from vamp_docker_audit import (
    DockerAuditor,
    DockerAuditResult,
    _docker,
    _docker_inspect,
)


def docker_available() -> bool:
    """Comprueba disponibilidad del binario docker."""
    return shutil.which("docker") is not None


# ---------------------------------------------------------------------------
# Test integración 1: Auditoría con contenedor privilegiado mockeado
# ---------------------------------------------------------------------------

class TestAuditContenedorPrivilegiadoMock:
    """Verifica que la auditoría completa detecta CRITICAL en contenedor privilegiado."""

    def _make_ps_output(self) -> str:
        return "abc123def456"

    def _make_inspect_output(self) -> str:
        data = [{
            "Id": "abc123def456789",
            "Name": "/vulnerable-app",
            "State": {"Status": "running"},
            "Config": {"Image": "myapp:latest", "User": "", "Env": []},
            "HostConfig": {
                "Privileged": True,
                "CapAdd": None,
                "NetworkMode": "bridge",
                "PidMode": "", "IpcMode": "private",
                "RestartPolicy": {"Name": "no"},
                "PortBindings": {},
            },
            "Mounts": [],
        }]
        return json.dumps(data)

    def test_audit_detecta_critical_con_contenedor_privilegiado(self):
        """La auditoría end-to-end con subprocess mockeado detecta CRITICAL."""
        ps_output    = self._make_ps_output()
        insp_output  = self._make_inspect_output()
        version_out  = "Docker version 24.0.5, build abc123"
        info_out     = "24.0.5"

        # Mapeamos los distintos subcomandos docker a sus salidas correspondientes
        def side_effect(cmd, **kwargs):
            mock_result = MagicMock()
            mock_result.returncode = 0
            if "--version" in cmd:
                mock_result.stdout = version_out
            elif "info" in cmd and "ServerVersion" in " ".join(cmd):
                mock_result.stdout = info_out
            elif "info" in cmd and "SecurityOptions" in " ".join(cmd):
                mock_result.stdout = "[name=apparmor name=seccomp]"
            elif "info" in cmd and "Authorization" in " ".join(cmd):
                mock_result.stdout = "null"
            elif "info" in cmd and "RuncCommit" in " ".join(cmd):
                mock_result.stdout = "abc123"
            elif "ps" in cmd:
                mock_result.stdout = ps_output
            elif "inspect" in cmd:
                mock_result.stdout = insp_output
            elif "images" in cmd or "network" in cmd or "volume" in cmd or "history" in cmd:
                mock_result.stdout = ""
            else:
                mock_result.stdout = ""
            mock_result.stderr = ""
            return mock_result

        with patch("subprocess.run", side_effect=side_effect):
            # El socket no existe en el entorno de test
            with patch("os.path.exists", return_value=False):
                auditor = DockerAuditor(scan_env=False)
                resultado = auditor.audit()

        # Debe existir al menos un hallazgo CRITICAL por el contenedor privilegiado
        criticos = [f for f in resultado.all_findings if f.severity == "CRITICAL"]
        assert criticos, "La auditoría debe detectar CRITICAL en contenedor privilegiado"


# ---------------------------------------------------------------------------
# Test integración 2: _docker helper maneja FileNotFoundError
# ---------------------------------------------------------------------------

class TestDockerHelper:
    """Verifica el comportamiento del helper _docker ante errores."""

    def test_docker_no_encontrado_retorna_false(self):
        """Si docker no está en PATH, _docker retorna (False, '', mensaje)."""
        with patch("subprocess.run", side_effect=FileNotFoundError):
            ok, _stdout, stderr = _docker(["ps"])
        assert ok is False
        assert "no encontrado" in stderr.lower() or "not found" in stderr.lower()

    def test_docker_timeout_retorna_false(self):
        """Si docker supera el timeout, _docker retorna False."""
        import subprocess
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(["docker"], 30)):
            ok, _stdout, _stderr = _docker(["ps"])
        assert ok is False


# ---------------------------------------------------------------------------
# Test integración 3: _docker_inspect retorna None en JSON inválido
# ---------------------------------------------------------------------------

class TestDockerInspect:
    """Verifica que _docker_inspect maneja correctamente JSON inválido."""

    def test_inspect_json_invalido_retorna_none(self):
        """_docker_inspect debe retornar None si la salida no es JSON válido."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "not-valid-json"
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            resultado = _docker_inspect("fake-container")
        assert resultado is None

    def test_inspect_lista_vacia_retorna_none(self):
        """_docker_inspect con lista vacía retorna None."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "[]"
        mock_result.stderr = ""

        with patch("subprocess.run", return_value=mock_result):
            resultado = _docker_inspect("fake-container")
        assert resultado is None


# ---------------------------------------------------------------------------
# Test integración 4: Contra daemon Docker real (si disponible)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not docker_available(), reason="Docker no disponible en este entorno")
class TestConDaemonReal:
    """Tests que requieren acceso al daemon Docker local."""

    def test_audit_no_falla_con_daemon_real(self):
        """La auditoría contra el daemon real no debe lanzar excepciones."""
        auditor = DockerAuditor(scan_env=False)
        try:
            resultado = auditor.audit()
            # El resultado debe ser un DockerAuditResult válido
            assert isinstance(resultado, DockerAuditResult)
            assert resultado.host  # debe tener hostname
        except SystemExit:
            pytest.skip("Sin acceso al daemon Docker")

    def test_version_docker_es_string_no_vacio(self):
        """La versión del daemon real es una cadena no vacía."""
        auditor = DockerAuditor(scan_env=False)
        try:
            resultado = auditor.audit()
            if resultado.error is None:
                assert resultado.docker_version, "docker_version no debe estar vacío"
        except SystemExit:
            pytest.skip("Sin acceso al daemon Docker")


# ---------------------------------------------------------------------------
# Test integración 5: Detección de secreto en capa de imagen mockeada
# ---------------------------------------------------------------------------

class TestLayerSecretsMock:
    """Verifica la detección de secretos en historial de capas con subprocess mockeado."""

    def test_detecta_secreto_en_historia_de_capa(self):
        """La fase 6 detecta secreto AWS en historial de imagen mockeado."""
        # El historial contiene una AWS Access Key
        history_output = (
            "/bin/sh -c export AWS_ACCESS_KEY_ID=TESTKEY_FAKE_FOR_UNIT_TEST "
            "&& echo configurado"
        )

        def side_effect(cmd, **kwargs):
            mock_result = MagicMock()
            mock_result.returncode = 0
            if "history" in cmd:
                mock_result.stdout = history_output
            elif "images" in cmd and "Repository" in " ".join(cmd):
                mock_result.stdout = "myapp:1.0"
            else:
                mock_result.stdout = ""
            mock_result.stderr = ""
            return mock_result

        # Construir resultado con un contenedor que usa la imagen myapp:1.0
        from vamp_docker_audit import ContainerAuditResult
        resultado = DockerAuditResult(host="test", docker_version="v24")
        car = ContainerAuditResult(
            container_id="abc123", container_name="app",
            image="myapp:1.0", status="running"
        )
        resultado.containers.append(car)

        auditor = DockerAuditor()

        with patch("subprocess.run", side_effect=side_effect):
            auditor._phase6_layer_secrets(resultado)

        # Debe haber hallazgos CRITICAL de tipo Imagen sobre secretos en capas
        criticos = [f for f in resultado.image_findings if f.severity == "CRITICAL"]
        assert criticos, "Debe detectar secreto CRITICAL en historia de capa"
