# © VampSecure Studios — VampSecure Labs Security Research Division
"""
_core.py — Docker CLI interface, audit engine, SBOM generation,
           and delta-scan logic for vamp-docker-audit.
"""
from __future__ import annotations

import json
import os
import platform
import re
import socket
import stat
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from ._models import (
    VERSION,
    TOOL_NAME,
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


def _docker_inspect(name: str) -> dict | None:
    """
    Ejecuta `docker inspect` sobre un contenedor y devuelve el objeto JSON.

    Retorna None si el inspect falla o el JSON no puede parsearse.
    """
    ok, stdout, _stderr = _docker(["inspect", name])
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
        target_names: list[str] | None = None,
    ) -> None:
        self._socket_path     = socket_path
        self._include_stopped = include_stopped
        self._scan_env        = scan_env
        self._target_names    = target_names
        self._counter         = 0

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

    def _phase0_entorno(self, resultado: DockerAuditResult) -> str | None:
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
        """
        sock_path = self._socket_path
        if not os.path.exists(sock_path):
            return

        try:
            st = os.stat(sock_path)
            mode = stat.S_IMODE(st.st_mode)
            mode_oct = oct(mode)

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
        """
        ps_args = ["ps", "--format", "{{.ID}}"]
        if self._include_stopped:
            ps_args.append("-a")

        ok, stdout, _ = _docker(ps_args)
        if not ok or not stdout:
            return

        ids_todos = [line.strip() for line in stdout.splitlines() if line.strip()]

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

        # 3. Proceso raíz
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
                evidence="NetworkMode: host",
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
                evidence="PidMode: host",
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
                evidence="IpcMode: host",
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
                    continue

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

            if imagen.endswith((":latest", ":<none>")):
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

            try:
                created_clean = created_str.strip().replace(" +0000 UTC", "+00:00")
                if " " in created_clean:
                    created_clean = created_clean.replace(" ", "T", 1)
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
            _net_id, net_name, driver = partes

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
        """
        ok, stdout, _ = _docker(
            ["volume", "ls", "--format", "{{.Name}}|{{.Driver}}"]
        )
        if not ok or not stdout:
            return

        volumenes = [line.strip() for line in stdout.splitlines() if line.strip()]
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
        """
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
                        break

    # ── Fase 7: CVEs específicos (v1.2) ────────────────────────────────────

    def _phase7_cve_checks(self, resultado: DockerAuditResult) -> None:
        """
        Fase 7 — Comprobaciones de CVEs específicos (v1.2).
        """
        self._check_cve_authz(resultado)
        self._check_cve_runc(resultado)
        self._check_apparmor(resultado)
        self._check_authz_sock_resumen(resultado)

    def _check_cve_authz(self, resultado: DockerAuditResult) -> None:
        """CVE-2026-34040 — Docker AuthZ Plugin Bypass."""
        ok, stdout, _ = _docker(
            ["info", "--format", "{{json .Plugins.Authorization}}"]
        )
        if not ok or not stdout or stdout.strip() in ("null", "[]", ""):
            return

        try:
            plugins = json.loads(stdout.strip())
        except json.JSONDecodeError:
            plugins = [stdout.strip()]

        if not plugins:
            return

        plugins_str = (
            ", ".join(plugins) if isinstance(plugins, list) else str(plugins)
        )

        ok_v, daemon_ver, _ = _docker(
            ["version", "--format", "{{.Server.Version}}"]
        )

        if not ok_v or not daemon_ver.strip():
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
        """
        match = re.match(r"^(\d+)\.(\d+)\.(\d+)", version_str)
        if not match:
            return False
        major   = int(match.group(1))
        minor   = int(match.group(2))
        patch_v = int(match.group(3))

        if major == 27:
            return (minor, patch_v) < (5, 1)
        elif major == 26:
            return (minor, patch_v) < (1, 9)
        elif major == 25:
            return (minor, patch_v) < (0, 9)

        return False

    def _check_cve_runc(self, resultado: DockerAuditResult) -> None:
        """CVE-2025-52881 — runc Container Escape."""
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

    def _get_runc_version(self) -> str | None:
        """
        Obtiene la versión semántica de runc del sistema.
        """
        try:
            res = subprocess.run(
                ["runc", "--version"],
                capture_output=True, text=True, timeout=10,
            )
            if res.returncode == 0 and res.stdout:
                match = re.search(r"runc version (\S+)", res.stdout)
                if match:
                    return match.group(1)
        except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
            pass

        _ok, _stdout, _ = _docker(
            ["info", "--format", "{{.RuncCommit.ID}}"]
        )
        return None

    def _is_runc_vulnerable(self, version_str: str) -> bool:
        """
        Determina si una versión de runc es vulnerable a CVE-2025-52881.
        """
        match = re.match(r"^(\d+)\.(\d+)\.(\d+)(?:-rc\.(\d+))?", version_str)
        if not match:
            return False

        major   = int(match.group(1))
        minor   = int(match.group(2))
        patch_v = int(match.group(3))
        rc_num  = int(match.group(4)) if match.group(4) else None

        if major != 1:
            return False

        if minor == 2:
            return patch_v < 8
        elif minor == 3:
            return patch_v < 3
        elif minor == 4:
            if patch_v > 0:
                return False
            if rc_num is None:
                return False
            return rc_num < 3
        elif minor <= 1:
            return True

        return False

    def _check_apparmor(self, resultado: DockerAuditResult) -> None:
        """DOCK-SEC-010 — Comprobación de AppArmor habilitado (solo Linux)."""
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
        """DOCK-AUTHZ-003 — Resumen de contenedores con socket Docker montado."""
        contenedores_con_sock: list[str] = []

        for car in resultado.containers:
            data = _docker_inspect(car.container_name)
            if data is None:
                continue
            mounts = data.get("Mounts", [])
            for m in mounts:
                if "docker.sock" in m.get("Source", ""):
                    contenedores_con_sock.append(car.container_name)
                    break

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
        output_dir: str | None = None,
    ) -> dict:
        """
        Genera un SBOM CycloneDX 1.4 para un contenedor específico (v1.3).
        """
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

        ok_os, stdout_os, _ = _docker(
            ["run", "--rm", "--entrypoint", "", imagen, "cat", "/etc/os-release"],
            timeout=20,
        )

        componentes: list[dict] = []

        if ok_os and stdout_os:
            for linea in stdout_os.splitlines():
                if linea.startswith("PRETTY_NAME="):
                    os_name = linea.split("=", 1)[1].strip().strip('"')
                    componentes.append({
                        "type":    "operating-system",
                        "name":    os_name,
                        "version": "",
                    })
                    break

            ok_dpkg, stdout_dpkg, _ = _docker(
                ["run", "--rm", "--entrypoint", "", imagen,
                 "sh", "-c",
                 ("awk '/^Package:/{p=$2} /^Version:/{print p,$2}' "
                 "/var/lib/dpkg/status 2>/dev/null | head -200")],
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
            sbom["components_unavailable"] = True
            sbom["components_unavailable_reason"] = (
                "La imagen no tiene shell disponible para inspección de paquetes"
            )

        sbom["components"] = componentes

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
        sbom["components_unavailable"] = True
        sbom["components_unavailable_reason"] = (
            "La imagen no tiene shell disponible o el contenedor no pudo ejecutarse"
        )
        return sbom

    componentes: list[dict] = []

    try:
        partes_principales = stdout.split("---PACKAGES---", 1)
        os_info = partes_principales[0].strip()

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


# ---------------------------------------------------------------------------
# Delta scan
# ---------------------------------------------------------------------------

def apply_delta_scan(
    resultado: "DockerAuditResult", delta_path: str
) -> "tuple[set, set, set]":
    """
    Compara hallazgos actuales con un informe JSON previo (--delta FILE).
    Devuelve (new_keys, recurring_keys, resolved_keys).
    """
    try:
        baseline_data = json.loads(Path(delta_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"No se puede leer el delta baseline '{delta_path}': {exc}") from exc

    baseline_keys: set = set()
    for bc in baseline_data.get("containers", []):
        cname = bc.get("name", bc.get("id", "?"))
        for bf in bc.get("findings", []):
            baseline_keys.add(f"{cname}:{bf.get('id','?')}")
    for bf in baseline_data.get("image_findings", []) + baseline_data.get("network_findings", []):
        baseline_keys.add(f"__image__:{bf.get('id','?')}")
    for bf in baseline_data.get("env_findings", []):
        baseline_keys.add(f"__env__:{bf.get('id','?')}")

    current_keys: set = set()
    for car in resultado.containers:
        for f in car.findings:
            current_keys.add(f"{car.container_name}:{f.id}")
    for f in resultado.image_findings + resultado.network_findings:
        current_keys.add(f"__image__:{f.id}")
    for f in resultado.env_findings:
        current_keys.add(f"__env__:{f.id}")

    return current_keys - baseline_keys, current_keys & baseline_keys, baseline_keys - current_keys
