#!/usr/bin/env bash
# Run the whole test suite. Stops at the first failing step.
#
#   1. unittest on /usr/bin/python3 and on python3 (each that exists)
#   2. every guard case file through tests/run_cases.py
#   3. the git guard tests
#   4. this repository's own hygiene hook tests
#   5. the mutation check (the suite must be able to go red)
set -euo pipefail

cd "$(dirname "$0")"
export PYTHONPATH="$PWD${PYTHONPATH:+:$PYTHONPATH}"

step() { printf '\n== %s\n' "$*"; }

interpreters=""
for py in /usr/bin/python3 "$(command -v python3 || true)"; do
  [ -n "$py" ] && [ -x "$py" ] || continue
  real="$(cd "$(dirname "$py")" && pwd -P)/$(basename "$py")"
  case " $interpreters " in *" $real "*) continue ;; esac
  interpreters="$interpreters $real"
done
[ -n "$interpreters" ] || { echo "no python3 found" >&2; exit 1; }

for py in $interpreters; do
  step "unittest on $py ($("$py" --version 2>&1))"
  "$py" -m unittest discover -s tests
done

step "case files"
for case_file in tests/cases/*.jsonl; do
  guard="$(basename "$case_file" .jsonl)"
  printf '%s: ' "$guard"
  python3 tests/run_cases.py "$guard" "$case_file"
done

step "git guard tests"
bash tests/test_git_guard.sh < /dev/null | tail -n 1

step "repository hygiene hook tests"
bash tests/test_repo_hooks.sh < /dev/null | tail -n 1

step "mutation check"
python3 tests/mutation_check.py < /dev/null

printf '\nAll steps passed.\n'
