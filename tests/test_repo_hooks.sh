#!/usr/bin/env bash
# Tests for this repository's own hygiene hooks in scripts/hooks/.
#
# Each case copies the hooks into a throwaway repository under mktemp -d and
# makes a real commit. The term list is synthetic and built at run time, so
# these tests never need anyone's private list.
#
# Prints: block_ok=X allow_ok=Y failures=Z, and exits 1 if Z > 0.
set -u

here="$(cd "$(dirname "$0")" && pwd)"
hooks_src="$(dirname "$here")/scripts/hooks"

export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_NOSYSTEM=1
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE

scratch="$(mktemp -d "${TMPDIR:-/tmp}/repo-hook-tests.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT

terms="$scratch/terms.txt"
term="example-private-""codename"
printf '# synthetic list for tests\n%s\n' "$term" > "$terms"
empty="$scratch/empty.txt"
printf '# only a comment\n\n' > "$empty"

block_ok=0
allow_ok=0
failures=0

new_repo() {
  local d
  d="$(mktemp -d "$scratch/repo.XXXXXX")"
  git -C "$d" init -q
  git -C "$d" config user.name "Test User"
  git -C "$d" config user.email "test@example.invalid"
  git -C "$d" config commit.gpgsign false
  mkdir -p "$d/.hooks"
  cp "$hooks_src/pre-commit" "$hooks_src/commit-msg" "$hooks_src/scan-lib.sh" "$d/.hooks/"
  git -C "$d" config core.hooksPath .hooks
  printf '%s\n' "$d"
}

record() {
  local expect="$1" name="$2" code="$3" got
  if [ "$code" -eq 0 ]; then got=allow; else got=block; fi
  if [ "$got" = "$expect" ]; then
    if [ "$expect" = block ]; then block_ok=$((block_ok + 1)); else allow_ok=$((allow_ok + 1)); fi
    printf 'ok   %-5s %s\n' "$expect" "$name"
  else
    failures=$((failures + 1))
    printf 'FAIL %-5s %s (exit %s)\n' "$expect" "$name" "$code"
  fi
}

# commit_case <expect> <name> <list path or ""> <file> <content> <message>
commit_case() {
  local expect="$1" name="$2" list="$3" file="$4" content="$5" message="$6" d code
  d="$(new_repo)"
  printf '%s\n' "$content" > "$d/$file"
  git -C "$d" add -- "$file"
  if [ -n "$list" ]; then
    PORTFOLIO_DENYLIST="$list" git -C "$d" commit -q -m "$message" < /dev/null >/dev/null 2>&1
  else
    env -u PORTFOLIO_DENYLIST git -C "$d" commit -q -m "$message" < /dev/null >/dev/null 2>&1
  fi
  code=$?
  record "$expect" "$name" "$code"
}

home_path="/""home/someone/project"
ip10="10.""1.2.3"
ip_cgnat="100.""100.1.2"
ip_below="100.""63.1.2"
aws="AK""IA""ABCDEFGHIJKLMNOP"

# A grep that fails whenever it is asked for line numbers (-n), as the scan
# does, and passes every other call to the real grep. It shows that a scan
# that cannot run refuses instead of allowing.
real_grep="$(command -v grep)"
broken_bin="$scratch/broken-grep"
mkdir -p "$broken_bin"
printf '#!/bin/sh\nfor a in "$@"; do [ "$a" = -n ] && exit 2; done\nexec "%s" "$@"\n' "$real_grep" > "$broken_bin/grep"
chmod +x "$broken_bin/grep"

commit_case block "listed term in content" "$terms" notes.txt "uses $term" "Add notes"
commit_case block "listed term in a file name" "$terms" "$term.txt" "clean" "Add notes"
commit_case block "listed term in the message" "$terms" notes.txt "clean" "Mention $term"
commit_case block "secret pattern in content" "$terms" notes.txt "key $aws" "Add notes"
commit_case block "private 10/8 address" "$terms" notes.txt "host $ip10" "Add notes"
commit_case block "carrier-grade NAT address" "$terms" notes.txt "host $ip_cgnat" "Add notes"
commit_case block "absolute home path" "$terms" notes.txt "see $home_path" "Add notes"
commit_case block "list variable unset (fail closed)" "" notes.txt "clean" "Add notes"
commit_case block "list file missing (fail closed)" "$scratch/missing.txt" notes.txt "clean" "Add notes"
commit_case block "list holds no terms (fail closed)" "$empty" notes.txt "clean" "Add notes"
d="$(new_repo)"; printf 'clean\n' > "$d/notes.txt"; git -C "$d" add notes.txt
PATH="$broken_bin:$PATH" PORTFOLIO_DENYLIST="$terms" git -C "$d" commit -q -m "Add notes" < /dev/null >/dev/null 2>&1
record block "scan that cannot run (broken grep, fail closed)" $?
commit_case allow "clean content and message" "$terms" notes.txt "nothing private" "Add notes"
commit_case allow "address just below 100.64/10" "$terms" notes.txt "host $ip_below" "Add notes"
commit_case allow "relative and tilde paths" "$terms" notes.txt "see ./data and ~/project" "Add notes"

echo "block_ok=$block_ok allow_ok=$allow_ok failures=$failures"
[ "$failures" -eq 0 ] || exit 1
exit 0
