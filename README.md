<h1 align="center">vamp-docker-audit</h1>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.9%2B-blue?logo=python&logoColor=white" alt="Python 3.9+"/>
  <img src="https://img.shields.io/badge/platform-linux%20%7C%20macOS%20%7C%20windows-lightgrey" alt="Platform"/>
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License MIT"/>
  <img src="https://img.shields.io/badge/VampSecure-Labs-magenta" alt="VampSecure Labs"/>
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

## Legal Notice

Use exclusively on systems you own or for which you hold explicit written authorization from the system owner. VampSecure Studios assumes no liability for unauthorized use.

## Part of VampSecure Labs Toolkit

`vamp-docker-audit` is one tool in the VampSecure Labs security research toolkit. For the full toolkit including the orchestrator that runs all tools in sequence and aggregates findings into a single engagement report, see:

- Portfolio: [github.com/belky-me](https://github.com/belky-me)
- Orchestrator: [github.com/belky-me/vamp-orchestrator](https://github.com/belky-me/vamp-orchestrator)

---

© VampSecure Studios — VampSecure Labs Security Research Division
