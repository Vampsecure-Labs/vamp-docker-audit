# © VampSecure Studios — VampSecure Labs Security Research Division
"""
conftest.py — Fixtures compartidas para las suites de test de vamp-docker-audit.
"""

import shutil
import sys
from pathlib import Path

import pytest

# Añadir el directorio raíz de la herramienta al path para importar el módulo
sys.path.insert(0, str(Path(__file__).parent.parent))


# ---------------------------------------------------------------------------
# Helpers de disponibilidad de Docker
# ---------------------------------------------------------------------------

def docker_available() -> bool:
    """Comprueba si el binario docker está presente en el PATH."""
    return shutil.which("docker") is not None


# ---------------------------------------------------------------------------
# Fixtures de datos de inspect (JSON simulado)
# ---------------------------------------------------------------------------

@pytest.fixture
def inspect_privilegiado() -> dict:
    """Datos docker inspect de un contenedor en modo privilegiado."""
    return {
        "Id": "abc123def456",
        "Name": "/test-privileged",
        "State": {"Status": "running"},
        "Config": {"Image": "nginx:latest", "User": ""},
        "HostConfig": {
            "Privileged": True,
            "CapAdd": None,
            "NetworkMode": "bridge",
            "PidMode": "",
            "IpcMode": "private",
            "RestartPolicy": {"Name": "no"},
            "PortBindings": {},
        },
        "Mounts": [],
    }


@pytest.fixture
def inspect_cap_add_all() -> dict:
    """Datos docker inspect con --cap-add=ALL añadida."""
    return {
        "Id": "bbb222ccc333",
        "Name": "/test-capall",
        "State": {"Status": "running"},
        "Config": {"Image": "debian:11", "User": "appuser"},
        "HostConfig": {
            "Privileged": False,
            "CapAdd": ["CAP_SYS_ADMIN"],
            "NetworkMode": "bridge",
            "PidMode": "",
            "IpcMode": "private",
            "RestartPolicy": {"Name": "no"},
            "PortBindings": {},
        },
        "Mounts": [],
    }


@pytest.fixture
def inspect_socket_montado() -> dict:
    """Datos docker inspect con el socket Docker montado en el contenedor."""
    return {
        "Id": "ddd444eee555",
        "Name": "/test-docker-sock",
        "State": {"Status": "running"},
        "Config": {"Image": "alpine:3.18", "User": ""},
        "HostConfig": {
            "Privileged": False,
            "CapAdd": None,
            "NetworkMode": "bridge",
            "PidMode": "",
            "IpcMode": "private",
            "RestartPolicy": {"Name": "no"},
            "PortBindings": {},
        },
        "Mounts": [
            {
                "Type": "bind",
                "Source": "/var/run/docker.sock",
                "Destination": "/var/run/docker.sock",
                "Mode": "rw",
            }
        ],
    }


@pytest.fixture
def inspect_puerto_expuesto() -> dict:
    """Datos docker inspect con un puerto expuesto en 0.0.0.0."""
    return {
        "Id": "fff666ggg777",
        "Name": "/test-portbind",
        "State": {"Status": "running"},
        "Config": {"Image": "redis:7", "User": "redis"},
        "HostConfig": {
            "Privileged": False,
            "CapAdd": None,
            "NetworkMode": "bridge",
            "PidMode": "",
            "IpcMode": "private",
            "RestartPolicy": {"Name": "no"},
            "PortBindings": {
                "6379/tcp": [{"HostIp": "0.0.0.0", "HostPort": "6379"}]
            },
        },
        "Mounts": [],
    }


@pytest.fixture
def inspect_red_host() -> dict:
    """Datos docker inspect con NetworkMode=host."""
    return {
        "Id": "hhh888iii999",
        "Name": "/test-hostnet",
        "State": {"Status": "running"},
        "Config": {"Image": "postgres:15", "User": ""},
        "HostConfig": {
            "Privileged": False,
            "CapAdd": None,
            "NetworkMode": "host",
            "PidMode": "",
            "IpcMode": "private",
            "RestartPolicy": {"Name": "no"},
            "PortBindings": {},
        },
        "Mounts": [],
    }


@pytest.fixture
def inspect_volumen_sensible() -> dict:
    """Datos docker inspect con un bind mount en /etc (ruta sensible)."""
    return {
        "Id": "jjj000kkk111",
        "Name": "/test-etcmount",
        "State": {"Status": "running"},
        "Config": {"Image": "busybox:latest", "User": ""},
        "HostConfig": {
            "Privileged": False,
            "CapAdd": None,
            "NetworkMode": "bridge",
            "PidMode": "",
            "IpcMode": "private",
            "RestartPolicy": {"Name": "no"},
            "PortBindings": {},
        },
        "Mounts": [
            {
                "Type": "bind",
                "Source": "/etc",
                "Destination": "/host-etc",
                "Mode": "ro",
            }
        ],
    }


@pytest.fixture
def inspect_limpio() -> dict:
    """Datos docker inspect de un contenedor sin misconfiguraciones."""
    return {
        "Id": "lll222mmm333",
        "Name": "/test-clean",
        "State": {"Status": "running"},
        "Config": {"Image": "nginx:1.25.3", "User": "1000:1000"},
        "HostConfig": {
            "Privileged": False,
            "CapAdd": None,
            "NetworkMode": "bridge",
            "PidMode": "",
            "IpcMode": "private",
            "RestartPolicy": {"Name": "on-failure"},
            "PortBindings": {
                "80/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8080"}]
            },
        },
        "Mounts": [],
    }


@pytest.fixture
def docker_client():
    """Fixture que salta el test si Docker no está disponible en el entorno."""
    if not docker_available():
        pytest.skip("Docker no disponible en este entorno")
