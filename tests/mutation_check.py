#!/usr/bin/env python3
"""Negative-control harness: prove the test suite can go red.

Every guard's tests are run three times:

* against the real guard, which must score 0 mismatches;
* against an ALWAYS_ALLOW stand-in, which must miss every block case;
* against an ALWAYS_BLOCK stand-in, which must miss every allow case.

If a stand-in scores 0 mismatches, or a guard has 0 cases, the tests are not
measuring anything and this script exits 1.

Set AGH_FORCE_STANDIN=always_allow or always_block to put a stand-in in
place of the real guard. The script must then exit 1, which shows the check
itself can fail.
"""

import os
import re
import stat
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import run_cases  # noqa: E402

CASE_FILES = [
    ("protected_paths", os.path.join(HERE, "cases", "protected_paths.jsonl")),
    ("readonly_remote", os.path.join(HERE, "cases", "readonly_remote.jsonl")),
]
GIT_GUARD_TESTS = os.path.join(HERE, "test_git_guard.sh")

STANDIN_EXIT = {"always_allow": 0, "always_block": 2}
SHELL_STANDIN_EXIT = {"always_allow": 0, "always_block": 1}


def python_standin(kind):
    code = "import sys; sys.stdin.read(); sys.exit({})".format(STANDIN_EXIT[kind])
    return [sys.executable, "-c", code]


def case_file_row(guard, case_file, forced):
    real_cmd = python_standin(forced) if forced else None
    real = run_cases.run_cases(guard, case_file, command=real_cmd, verbose=False)
    allow = run_cases.run_cases(guard, case_file, command=python_standin("always_allow"),
                                verbose=False)
    block = run_cases.run_cases(guard, case_file, command=python_standin("always_block"),
                                verbose=False)
    return {
        "guard": guard,
        "cases": real["cases"],
        "real": real["mismatches"],
        "always_allow": allow["mismatches"],
        "always_block": block["mismatches"],
    }


def _run_git_tests(standin_path):
    env = dict(os.environ)
    if standin_path:
        env["GIT_GUARD_UNDER_TEST"] = standin_path
    else:
        env.pop("GIT_GUARD_UNDER_TEST", None)
    proc = subprocess.run(["bash", GIT_GUARD_TESTS], env=env, stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, universal_newlines=True)
    match = re.search(r"block_ok=(\d+) allow_ok=(\d+) failures=(\d+)", proc.stdout)
    if not match:
        raise RuntimeError("git guard tests printed no summary:\n" + proc.stdout)
    block_ok, allow_ok, failures = (int(x) for x in match.groups())
    return block_ok, allow_ok, failures


def git_guard_row(forced, tmp):
    paths = {}
    for kind, code in SHELL_STANDIN_EXIT.items():
        path = os.path.join(tmp, kind + ".sh")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("#!/usr/bin/env bash\nexit {}\n".format(code))
        os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR)
        paths[kind] = path
    real = _run_git_tests(paths[forced] if forced else None)
    allow = _run_git_tests(paths["always_allow"])
    block = _run_git_tests(paths["always_block"])
    # With a stand-in in place, the install and real-commit cases are skipped,
    # so stand-in counts cover the direct cases only.
    return {
        "guard": "git_guard",
        "cases": sum(real),
        "real": real[2],
        "always_allow": allow[2],
        "always_block": block[2],
    }


def main():
    forced = os.environ.get("AGH_FORCE_STANDIN") or None
    if forced and forced not in STANDIN_EXIT:
        sys.stderr.write("AGH_FORCE_STANDIN must be always_allow or always_block\n")
        return 2
    rows = [case_file_row(guard, path, forced) for guard, path in CASE_FILES]
    with tempfile.TemporaryDirectory() as tmp:
        rows.append(git_guard_row(forced, tmp))

    header = "{:<16} {:>6} {:>15} {:>21} {:>21}".format(
        "guard", "cases", "real_mismatch", "always_allow_mismatch", "always_block_mismatch")
    print(header)
    failed = []
    total = 0
    for row in rows:
        total += row["cases"]
        print("{guard:<16} {cases:>6} {real:>15} {always_allow:>21} {always_block:>21}".format(**row))
        if row["cases"] == 0:
            failed.append("{}: no cases examined".format(row["guard"]))
        if row["real"] != 0:
            failed.append("{}: the guard under test has {} mismatches".format(row["guard"], row["real"]))
        if row["always_allow"] == 0:
            failed.append("{}: an always-allow stand-in passes every case".format(row["guard"]))
        if row["always_block"] == 0:
            failed.append("{}: an always-block stand-in passes every case".format(row["guard"]))
    print("total_cases={}".format(total))
    if forced:
        print("stand-in forced in place of the real guards: {}".format(forced))
    if failed:
        for item in failed:
            print("FAIL " + item)
        return 1
    print("mutation check passed: every stand-in was caught")
    return 0


if __name__ == "__main__":
    sys.exit(main())
