#!/usr/bin/env bash
# Tests for git-hooks/git-guard.sh and git-hooks/install.sh.
#
# Every case runs in a throwaway repository under mktemp -d. No network is
# used: pre-push is tested by calling the guard with a URL argument. Fake
# secrets are joined from parts at run time, so no literal secret sits in
# this file.
#
# GIT_GUARD_UNDER_TEST may name a stand-in script, which the mutation check
# uses to prove these tests can fail.
#
# Prints: block_ok=X allow_ok=Y failures=Z, and exits 1 if Z > 0.
set -u

here="$(cd "$(dirname "$0")" && pwd)"
repo_root="$(dirname "$here")"
guard="${GIT_GUARD_UNDER_TEST:-$repo_root/git-hooks/git-guard.sh}"
installer="$repo_root/git-hooks/install.sh"

# Isolate from the user's own git config (signing, hooksPath, templates).
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_NOSYSTEM=1
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE

scratch="$(mktemp -d "${TMPDIR:-/tmp}/git-guard-tests.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT

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
  printf '%s\n' "$d"
}

# record <expect: block|allow> <name> <exit code>
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

# stage_case <expect> <name> <file name> <line of content>
stage_case() {
  local expect="$1" name="$2" file="$3" content="$4" d code
  d="$(new_repo)"
  mkdir -p "$d/$(dirname "$file")"
  printf '%s\n' "$content" > "$d/$file"
  git -C "$d" add -- "$file"
  (cd "$d" && bash "$guard" pre-commit) >/dev/null 2>&1
  code=$?
  record "$expect" "$name" "$code"
}

msg_case() {
  local expect="$1" name="$2" text="$3" d code
  d="$(new_repo)"
  printf '%s\n' "$text" > "$d/MSG"
  (cd "$d" && bash "$guard" commit-msg MSG) >/dev/null 2>&1
  code=$?
  record "$expect" "$name" "$code"
}

# push_case <expect> <name> <url> <git config commands...>
push_case() {
  local expect="$1" name="$2" url="$3" d code
  shift 3
  d="$(new_repo)"
  git -C "$d" remote add origin "https://example.invalid/owner/project.git"
  while [ "$#" -gt 0 ]; do
    git -C "$d" config $1
    shift
  done
  (cd "$d" && bash "$guard" pre-push origin "$url" < /dev/null) >/dev/null 2>&1
  code=$?
  record "$expect" "$name" "$code"
}

# Fake secrets, joined from parts.
aws="AK""IA""ABCDEFGHIJKLMNOP"
gh_token="gh""p_""$(printf 'a%.0s' $(seq 1 36))"
key_header="-----BEGIN"" RSA PRIVATE"" KEY-----"
llm_key="sk-""ant-""$(printf 'b%.0s' $(seq 1 30))"
chat_token="xo""xb-""1234567890-abcdefghij"
term_list="$scratch/terms.txt"
printf '# synthetic private terms for tests\nexample-internal-codename\n' > "$term_list"
codename="example-internal-""codename"

# A grep that fails whenever it is asked for line numbers (-n), as the scan
# does, and passes every other call to the real grep. It shows that a scan
# that cannot run refuses instead of allowing.
real_grep="$(command -v grep)"
broken_bin="$scratch/broken-grep"
mkdir -p "$broken_bin"
printf '#!/bin/sh\nfor a in "$@"; do [ "$a" = -n ] && exit 2; done\nexec "%s" "$@"\n' "$real_grep" > "$broken_bin/grep"
chmod +x "$broken_bin/grep"

echo "== pre-commit, must block"
stage_case block "cloud access key id in a line" config.txt "key = $aws"
stage_case block "VCS token in a line" notes.txt "token: $gh_token"
stage_case block "private key header" key.txt "$key_header"
stage_case block "model API key" app.cfg "API=$llm_key"
stage_case block "chat token" bot.txt "$chat_token"
stage_case block "id_rsa file name" .ssh/id_rsa "not a real key"
stage_case block ".env file name" .env "DEBUG=1"
stage_case block ".pem file name" certs/server.pem "not a real cert"
stage_case block "credentials file name" aws-credentials.json "{}"

d="$(new_repo)"; git -C "$d" config agent-hook-guards.denylist "$term_list"
printf 'we use %s here\n' "$codename" > "$d/doc.md"; git -C "$d" add doc.md
(cd "$d" && bash "$guard" pre-commit) >/dev/null 2>&1; record block "denylist term in a line" $?

d="$(new_repo)"; git -C "$d" config agent-hook-guards.denylist "$scratch/missing.txt"
printf 'clean\n' > "$d/doc.md"; git -C "$d" add doc.md
(cd "$d" && bash "$guard" pre-commit) >/dev/null 2>&1; record block "configured denylist missing (fail closed)" $?

d="$(new_repo)"; printf 'clean\n' > "$d/doc.md"; git -C "$d" add doc.md
(cd "$d" && PATH="$broken_bin:$PATH" bash "$guard" pre-commit) >/dev/null 2>&1; record block "scan that cannot run (broken grep, fail closed)" $?

echo "== pre-commit, must allow"
stage_case allow "clean file" README.md "A small, clean readme."
stage_case allow "public key file" .ssh/id_rsa.pub "ssh-ed25519 AAAA example"
stage_case allow ".env.example file" .env.example "DEBUG=0"
for word in risk-assessment disk-space-reclaim task-runner ask-for-help desk-booking whisk-together; do
  stage_case allow "innocent hyphenated word $word" words.txt "Please see the $word notes."
done

d="$(new_repo)"; git -C "$d" config agent-hook-guards.denylist "$term_list"
printf 'nothing private\n' > "$d/doc.md"; git -C "$d" add doc.md
(cd "$d" && bash "$guard" pre-commit) >/dev/null 2>&1; record allow "denylist configured, clean content" $?

echo "== commit-msg"
msg_case block "token in commit message" "Add config with $gh_token"
msg_case allow "clean commit message" "Fix the risk-assessment table"
d="$(new_repo)"; printf 'Fix the table\n' > "$d/MSG"
(cd "$d" && PATH="$broken_bin:$PATH" bash "$guard" commit-msg MSG) >/dev/null 2>&1; record block "message scan that cannot run (broken grep, fail closed)" $?

echo "== pre-push"
push_case block "nothing configured (fail closed)" "https://example.invalid/owner/project.git"
push_case block "URL not on the allowlist" "https://example.invalid/someone-else/project.git" \
  "agent-hook-guards.allowedRemote https://example.invalid/owner/project.git"
push_case block "own origin, owner regex does not match" "https://example.invalid/owner/project.git" \
  "agent-hook-guards.allowOwnOrigin true" "agent-hook-guards.ownerRegex ^https://example[.]invalid/other/"
push_case block "own origin allowed but no owner regex (fail closed)" "https://example.invalid/owner/project.git" \
  "agent-hook-guards.allowOwnOrigin true"
push_case allow "URL on the allowlist" "https://example.invalid/owner/project.git" \
  "agent-hook-guards.allowedRemote https://example.invalid/owner/project.git"
push_case allow "own origin matching the owner regex" "https://example.invalid/owner/project.git" \
  "agent-hook-guards.allowOwnOrigin true" "agent-hook-guards.ownerRegex ^https://example[.]invalid/owner/"

if [ -z "${GIT_GUARD_UNDER_TEST:-}" ]; then
  echo "== install.sh and real git commits"
  d="$(new_repo)"
  bash "$installer" "$d" >/dev/null 2>&1; record allow "install into a fresh repository" $?
  printf 'clean\n' > "$d/ok.txt"; git -C "$d" add ok.txt
  git -C "$d" commit -q -m "Add a clean file" >/dev/null 2>&1; record allow "installed hook allows a clean commit" $?
  printf 'key = %s\n' "$aws" > "$d/bad.txt"; git -C "$d" add bad.txt
  git -C "$d" commit -q -m "Add a bad file" >/dev/null 2>&1; record block "installed hook blocks a staged secret" $?
  bash "$installer" "$d" >/dev/null 2>&1; record block "install refuses to overwrite existing hooks" $?
  d="$(new_repo)"; git -C "$d" config core.hooksPath custom-hooks
  bash "$installer" "$d" >/dev/null 2>&1; record block "install refuses when core.hooksPath is set" $?
  d="$(new_repo)"; git -C "$d" commit -q --allow-empty -m "Initial commit"
  w="$(mktemp -d "$scratch/worktree.XXXXXX")"
  git -C "$d" worktree add -q "$w" -b side >/dev/null 2>&1
  bash "$installer" "$w" >/dev/null 2>&1; record allow "install from a linked worktree" $?
  printf 'key = %s\n' "$aws" > "$w/bad.txt"; git -C "$w" add bad.txt
  git -C "$w" commit -q -m "Add a bad file" >/dev/null 2>&1; record block "hook installed from a worktree blocks a staged secret there" $?
fi

echo "block_ok=$block_ok allow_ok=$allow_ok failures=$failures"
[ "$failures" -eq 0 ] || exit 1
exit 0
