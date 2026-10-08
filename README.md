<!-- © VampSecure Studios — VampSecure Labs Security Research Division -->
<h1 align="center">vamp-docker-audit</h1>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.9%2B-blue?logo=python&logoColor=white" alt="Python 3.9+"/>
  <img src="https://img.shields.io/badge/platform-linux%20%7C%20macOS%20%7C%20windows-lightgrey" alt="Platform"/>
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License MIT"/>
  <img src="https://img.shields.io/badge/VampSecure-Labs-magenta" alt="VampSecure Labs"/>
  <img src="https://github.com/Vampsecure-Labs/vamp-docker-audit/actions/workflows/ci.yml/badge.svg" alt="CI"/>
</p>

## Overview

`vamp-docker-audit` is a CIS Docker Benchmark-aligned security auditor that inspects running Docker containers, their environment variables, images, networks, and volumes for misconfigurations and credential exposure. It operates entirely through the Docker CLI — no SDK dependency — making it portable across any Docker-capable host. A multi-phase architecture covers daemon access verification, per-container security checks, secret detection in environment variables, image freshness, and network driver analysis, with findings rated CRITICAL to INFO and exported to Console, JSON, or HTML.

## Features

- Phase 0: daemon access verification and Docker socket permission check (`/var/run/docker.sock` ownership and mode)
- Container checks (DOCK-001 to DOCK-010): privileged mode (CRITICAL), dangerous Linux capabilities including `CAP_SYS_ADMIN`, `CAP_NET_ADMIN`, `CAP_SYS_PTRACE` (HIGH), root user inside container (MEDIUM), Docker socket mounted inside container (CRITICAL), host network mode (HIGH), sensitive bind mounts (`/etc`, `/var/run`, `/proc`, `/sys`, `/root`, `/home`) (MEDIUM), host PID namespace (HIGH), host IPC namespace (MEDIUM), unlimited restart policy (INFO), ports bound to `0.0.0.0` (LOW)
- Environment variable secret scanning: variable names matching `PASSWORD`, `PASSWD`, `SECRET`, `TOKEN`, `KEY`, `API_KEY`, `APIKEY`, `PRIVATE`, `CREDENTIALS`, `AUTH`, `DSN` (HIGH); value patterns for `sk_`/`pk_`, `ghp_`, `glpat-`, `xox[bpoa]-`, `Bearer`, `AKIA...`, `ey...`, base64-encoded blobs (HIGH); connection string variables `DATABASE_URL`, `MONGO_URL`, `REDIS_URL` and variants (MEDIUM)
- Image checks: `:latest` or `<none>` tag (LOW), images older than 90 days (INFO)
- Network analysis: host-driver network inventory (INFO)
- Volume inventory (INFO)
- Selective container targeting with `--containers` (comma-separated names or IDs) or full-fleet scan
- Stopped container inclusion with `--include-stopped`
- ENV scan bypass with `--no-env-scan` for privacy-sensitive environments
- Custom Docker socket path via `--socket`
- Export to Console (Rich per-container panels), JSON, and HTML (dark-theme)

## Requirements

- Python 3.9 or later
- `rich >= 13.7.0`
- Docker CLI in `PATH` and a running Docker daemon
- Optional: `fpdf2 >= 2.7` for `--report-pdf`

## Installation


```bash
pip install vamp-docker-audit
# o con Homebrew:
brew install vampsecure-labs/labs/vamp-docker-audit
```

```bash
git clone https://github.com/belky-me/vamp-docker-audit.git
cd vamp-docker-audit
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Usage

```
python3 vamp_docker_audit.py --help
```

```
usage: vamp_docker_audit.py [-h]
                             [--socket PATH]
                             [--containers NAMES]
                             [--include-stopped]
                             [--no-env-scan]
                             [--json FILE] [--html FILE]
                             [--client CLIENT] [--engagement ENGAGEMENT]
                             [--auditor AUDITOR] [--report-scope SCOPE]
                             [--report-html FILE] [--report-pdf FILE]

vamp-docker-audit — Docker Security Auditor (VampSecure Labs)
```

## Examples

```bash
# Audit all running containers on the local host
python3 vamp_docker_audit.py

# Audit specific containers by name
python3 vamp_docker_audit.py --containers web,api,db

# Include stopped containers in the audit
python3 vamp_docker_audit.py --include-stopped

# Audit without ENV variable secret scanning
python3 vamp_docker_audit.py --no-env-scan

# Use a non-standard Docker socket (e.g. rootless Docker)
python3 vamp_docker_audit.py --socket /run/user/1000/docker.sock

# Export findings to JSON and HTML
python3 vamp_docker_audit.py --json results.json --html report.html

# Generate client-ready engagement report (HTML + PDF)
python3 vamp_docker_audit.py \
    --client "Acme Corp" --engagement "Container Security Review Q3 2026" \
    --auditor "J. Smith" --report-html client_report.html --report-pdf client_report.pdf
```

## CLI Reference

| Flag | Default | Description |
|------|---------|-------------|
| `--socket PATH` | `/var/run/docker.sock` | Path to Docker socket |
| `--containers NAMES` | all running | Comma-separated container names or IDs to target |
| `--include-stopped` | off | Include stopped containers in the audit |
| `--no-env-scan` | off | Skip environment variable secret scanning |
| `--json FILE` | — | Export results to JSON |
| `--html FILE` | — | Export dark-theme HTML report |
| `--client TEXT` | — | Client name for VSL engagement report |
| `--engagement TEXT` | — | Engagement title for VSL engagement report |
| `--auditor TEXT` | — | Auditor name for VSL engagement report |
| `--report-scope TEXT` | — | Scope description for VSL engagement report |
| `--report-html FILE` | — | Export unified VSL client report (HTML) |
| `--report-pdf FILE` | — | Export unified VSL client report (PDF, requires fpdf2) |

## Output Formats

| Format | Flag | Description |
|--------|------|-------------|
| Console | (default) | Rich panels per container with color-coded findings by severity |
| JSON | `--json FILE` | Machine-readable full result set |
| HTML | `--html FILE` | Dark-theme standalone report |
| Client HTML | `--report-html FILE` | Unified VampSecure Labs engagement report |
| Client PDF | `--report-pdf FILE` | PDF version of the VSL client report |

## Exit Codes

| Code | Meaning | CI/CD Behavior |
|------|---------|----------------|
| `0` | No critical or high findings | Pipeline passes |
| `1` | High-severity findings detected | Pipeline fails — review required |
| `2` | Critical-severity findings detected | Pipeline fails — immediate action required |

## Sample Output

```
$ python3 vamp_docker_audit.py --containers web,api,db,cache

 vamp-docker-audit v1.3 — VampSecure Labs
 Docker socket: /var/run/docker.sock  ✓ Accessible
 Containers targeted: 4  |  Running: 4  |  Stopped: 0

╭─────────────────────────────────── web ────────────────────────────────────╮
│ Image: nginx:latest   User: root   Network: bridge                         │
│                                                                             │
│ [CRITICAL] DOCK-001 Container runs in privileged mode                      │
│ [HIGH]     DOCK-003 Container runs as root (UID 0)                         │
│ [HIGH]     DOCK-010 Port 80 bound to 0.0.0.0 — exposed on all interfaces  │
│ [LOW]      DOCK-IMG-001 Image tagged :latest — pinned digest recommended   │
╰─────────────────────────────────────────────────────────────────────────────╯

╭─────────────────────────────────── api ────────────────────────────────────╮
│ Image: myapp-api:2.4.1   User: appuser(1001)   Network: app-net            │
│                                                                             │
│ [HIGH]   DOCK-ENV-001 ENV SECRET_KEY=sk_live_••••• — live credential       │
│ [MEDIUM] DOCK-ENV-003 ENV DATABASE_URL — connection string detected        │
│ [INFO]   DOCK-007 No healthcheck configured                                 │
╰─────────────────────────────────────────────────────────────────────────────╯

╭─────────────────────────────────── db ─────────────────────────────────────╮
│ Image: postgres:15   User: postgres(999)   Network: app-net                │
│                                                                             │
│ [CRITICAL] DOCK-004 Docker socket /var/run/docker.sock mounted in container│
│ [MEDIUM]   DOCK-006 Sensitive bind mount: /etc → /host-etc (read-write)    │
│ [INFO]     DOCK-008 Unlimited restart policy — consider max-retries        │
╰─────────────────────────────────────────────────────────────────────────────╯

╭─────────────────────────────────── cache ──────────────────────────────────╮
│ Image: redis:7-alpine   User: redis(999)   Network: host                   │
│                                                                             │
│ [HIGH] DOCK-005 host network mode — container shares host network stack    │
│ [HIGH] DOCK-002 Dangerous capability: CAP_NET_ADMIN granted                │
╰─────────────────────────────────────────────────────────────────────────────╯

 Summary: 2 CRITICAL  ·  5 HIGH  ·  2 MEDIUM  ·  1 LOW  ·  2 INFO
 Exit code: 2 (CRITICAL findings — immediate action required)
```

## Why vamp-docker-audit vs. Trivy (misconfig) · Hadolint · Docker Bench for Security

| Capability | vamp-docker-audit | Trivy misconfig | Hadolint | Docker Bench |
|---|---|---|---|---|
| Inspects running containers (live ENV vars) | ✅ | ❌ | ❌ | ✅ |
| Secret pattern scanning in ENV values | ✅ | ⚠️ partial | ❌ | ❌ |
| CIS Docker Benchmark aligned (DOCK-NNN IDs) | ✅ | ✅ | ⚠️ partial | ✅ |
| VSL engagement report (HTML + PDF) | ✅ | ❌ | ❌ | ❌ |
| Selective container targeting | ✅ | ❌ | ❌ | ❌ |
| Machine-readable JSON + CI/CD exit codes | ✅ | ✅ | ✅ | ⚠️ partial |
| No SDK or Docker daemon API dependency | ✅ | ❌ | ❌ | ❌ |
| Delta comparison — new findings only (`--delta`) | ✅ | ❌ | ❌ | ❌ |

- **Live runtime focus**: checks what is actually running in production, not the Dockerfile. A hardened image can still launch a privileged container; only live inspection catches it.
- **Secret density in ENV**: scanning variable names *and* value patterns (Stripe, GitHub PAT, Slack tokens, AWS AKIA keys, JWTs) catches credentials that misconfig scanners overlook.
- **Engagement-ready output**: `--report-html` / `--report-pdf` generate a client-deliverable report with client name, auditor, and scope — no post-processing required.
- **Delta mode**: `--delta FILE` surfaces only findings that are *new* since the last run, making it suitable for scheduled CI gates without alert fatigue.

## Check Coverage

| Check ID | Description | Standard | Severity |
|---|---|---|---|
| DOCK-001 | Container running in privileged mode | CIS DK Benchmark 5.4 | CRITICAL |
| DOCK-002 | Dangerous Linux capabilities granted (CAP_SYS_ADMIN, CAP_NET_ADMIN, CAP_SYS_PTRACE) | CIS DK Benchmark 5.3 | HIGH |
| DOCK-003 | Container process running as root (UID 0) | CIS DK Benchmark 4.1 | MEDIUM |
| DOCK-004 | Docker socket mounted inside container (/var/run/docker.sock) | CIS DK Benchmark 5.31 | CRITICAL |
| DOCK-005 | Host network mode — container shares host network stack | CIS DK Benchmark 5.15, NIST SP 800-190 §4.3 | HIGH |
| DOCK-006 | Sensitive bind mount (/etc, /proc, /sys, /root, /home) | CIS DK Benchmark 5.12 | MEDIUM |
| DOCK-007 | No HEALTHCHECK configured | CIS DK Benchmark 4.6 | INFO |
| DOCK-008 | Unlimited restart policy (always/unless-stopped without max-retries) | CIS DK Benchmark 5.14 | INFO |
| DOCK-009 | Host PID namespace shared (--pid=host) | CIS DK Benchmark 5.16 | HIGH |
| DOCK-010 | Port bound to 0.0.0.0 — exposed on all interfaces | NIST SP 800-190 §4.3 | LOW |
| DOCK-ENV-001 | ENV variable name matches secret pattern (SECRET, TOKEN, API_KEY, PRIVATE…) | CIS DK Benchmark 4.4 | HIGH |
| DOCK-ENV-002 | ENV variable value matches credential pattern (sk_, ghp_, AKIA, ey…) | CIS DK Benchmark 4.4 | HIGH |
| DOCK-ENV-003 | Connection string in ENV (DATABASE_URL, MONGO_URL, REDIS_URL) | CIS DK Benchmark 4.4 | MEDIUM |
| DOCK-IMG-001 | Image tagged :latest or \<none\> — unpinned digest | CIS DK Benchmark 4.1 | LOW |
| DOCK-IMG-002 | Image older than 90 days — may contain unpatched CVEs | NIST SP 800-190 §4.1 | INFO |

## Legal Notice

Use exclusively on systems you own or for which you hold explicit written authorization from the system owner. VampSecure Studios assumes no liability for unauthorized use.

## Part of VampSecure Labs Toolkit

`vamp-docker-audit` is one tool in the VampSecure Labs security research toolkit. For the full toolkit including the orchestrator that runs all tools in sequence and aggregates findings into a single engagement report, see:

- Portfolio: [github.com/belky-me](https://github.com/belky-me)
- Orchestrator: [github.com/belky-me/vamp-orchestrator](https://github.com/belky-me/vamp-orchestrator)

---

© VampSecure Studios — VampSecure Labs Security Research Division

## Versión
v1.3 — VampSecure Labs Security Research Division
