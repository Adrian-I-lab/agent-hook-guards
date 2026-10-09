#!/usr/bin/env python3
"""Run a guard over a JSONL case file.

Usage: python3 tests/run_cases.py <guard> <case-file> [--quiet]

Each line of the case file is a JSON object:

    {"name": "...", "expect": "block" | "allow", "payload": {...}}

Lines that are blank or start with // are skipped. The string {ROOT} anywhere
in a payload is replaced with a fresh temporary directory built by
tests/fixtures/<guard>.py, and the guard runs with that directory's work
folder as its cwd and a generated config.

Prints: cases=N blocked_ok=X allowed_ok=Y mismatches=Z
Exits 1 if any case mismatches or the file holds no cases.
"""

import importlib.util
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)


def load_cases(path):
    cases = []
    with open(path, "r", encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            text = line.strip()
            if not text or text.startswith("//"):
                continue
            case = json.loads(text)
            if case.get("expect") not in ("block", "allow"):
                raise ValueError("{}:{}: expect must be block or allow".format(path, number))
            if not isinstance(case.get("payload"), dict):
                raise ValueError("{}:{}: payload must be an object".format(path, number))
            case.setdefault("name", "line {}".format(number))
            cases.append(case)
    return cases


def _substitute(value, root):
    if isinstance(value, str):
        return value.replace("{ROOT}", root)
    if isinstance(value, list):
        return [_substitute(v, root) for v in value]
    if isinstance(value, dict):
        return {k: _substitute(v, root) for k, v in value.items()}
    return value


def _load_fixture(guard):
    path = os.path.join(HERE, "fixtures", guard + ".py")
    spec = importlib.util.spec_from_file_location("fixture_" + guard, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def guard_command(guard):
    return [sys.executable, "-m", "agent_hook_guards." + guard]


def run_cases(guard, case_file, command=None, verbose=True):
    """Run every case. Return a dict of counts. `command` overrides the guard."""
    cases = load_cases(case_file)
    if command is None:
        command = guard_command(guard)
    fixture = _load_fixture(guard)
    counts = {"cases": 0, "blocked_ok": 0, "allowed_ok": 0, "mismatches": 0,
              "expect_block": 0, "expect_allow": 0}
    with tempfile.TemporaryDirectory() as tmp:
        root = os.path.realpath(tmp)
        config = fixture.build(root)
        config_path = os.path.join(root, "guard-config.json")
        with open(config_path, "w", encoding="utf-8") as handle:
            json.dump(config, handle)
        cwd = os.path.join(root, getattr(fixture, "CWD", ""))
        env = dict(os.environ)
        env["AGENT_GUARDS_CONFIG"] = config_path
        env["PYTHONPATH"] = REPO + os.pathsep + env.get("PYTHONPATH", "")
        for case in cases:
            payload = _substitute(case["payload"], root)
            payload.setdefault("cwd", cwd)
            proc = subprocess.run(
                command, input=json.dumps(payload), cwd=cwd, env=env,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
            )
            got = "block" if proc.returncode == 2 else "allow" if proc.returncode == 0 else "error"
            counts["cases"] += 1
            counts["expect_" + case["expect"]] += 1
            if got == case["expect"]:
                counts["blocked_ok" if got == "block" else "allowed_ok"] += 1
            else:
                counts["mismatches"] += 1
                if verbose:
                    sys.stdout.write("MISMATCH {}: expected {}, got {} (exit {})\n  {}\n".format(
                        case["name"], case["expect"], got, proc.returncode,
                        proc.stderr.strip().replace("\n", "\n  ")))
    return counts


def main(argv):
    args = [a for a in argv if not a.startswith("--")]
    if len(args) != 2:
        sys.stderr.write(__doc__)
        return 2
    counts = run_cases(args[0], args[1], verbose="--quiet" not in argv)
    print("cases={cases} blocked_ok={blocked_ok} allowed_ok={allowed_ok} "
          "mismatches={mismatches}".format(**counts))
    if counts["cases"] == 0 or counts["mismatches"] > 0:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
