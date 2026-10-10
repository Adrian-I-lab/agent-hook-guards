#!/usr/bin/env bash
# agent-hook-guards: git guard.
#
# Modes:
#   git-guard.sh pre-commit                   scan staged file names and added lines
#   git-guard.sh commit-msg <message-file>    scan the commit message
#   git-guard.sh pre-push <remote> <url>      allow pushes only to configured remotes
#
# Configuration lives in git config, so no remote URL is ever written into a
# repository:
#   agent-hook-guards.denylist        optional file of private terms, one per line
#   agent-hook-guards.allowedRemote   multi-valued, exact URLs pushes may go to
#   agent-hook-guards.allowOwnOrigin  true to allow this repo's own origin URL ...
#   agent-hook-guards.ownerRegex      ... if it also matches this extended regex
#
# Exit 0 allows. Any other exit refuses. Anything unexpected refuses (fail
# closed). Matched text is never printed, only where it was found.
#
# Written for bash 3.2 or later, git, and BSD or GNU grep.

set -u

say() { printf '[agent-hook-guards] %s\n' "$*" >&2; }
refuse() { say "REFUSED: $*"; exit 1; }

# High-confidence secret signatures. Each needs a fixed prefix, so ordinary
# words (risk-assessment, disk-space-reclaim) never match.
secret_patterns() {
  cat <<'PATTERNS'
-----BEGIN ([A-Z0-9]+ )*PRIVATE KEY-----
AKIA[0-9A-Z]{16}
ASIA[0-9A-Z]{16}
gh[pousr]_[A-Za-z0-9]{36}
github_pat_[A-Za-z0-9_]{22,}
glpat-[A-Za-z0-9_-]{20,}
sk-(ant|proj|svcacct|admin)-[A-Za-z0-9_-]{20,}
hf_[A-Za-z0-9]{30,}
xox[abposr]-[A-Za-z0-9-]{10,}
AIza[0-9A-Za-z_-]{35}
PATTERNS
}

# File names that usually hold secrets. Matched against the base name,
# ignoring case.
secret_file_name() {
  local base
  base="$(basename "$1" | tr '[:upper:]' '[:lower:]')"
  case "$base" in
    .env.example|.env.sample|.env.template|*.pub) return 1 ;;
    .env|.env.*|*.pem|*.key|*.p12|*.pfx|*.keystore|*.jks) return 0 ;;
    id_rsa|id_dsa|id_ecdsa|id_ed25519|.netrc|.pgpass) return 0 ;;
    *credential*) return 0 ;;
  esac
  return 1
}

# Write the cleaned denylist to $1. Return 1 if none is configured, 2 if one
# is configured but cannot be used.
load_denylist() {
  local path
  path="$(git config --get agent-hook-guards.denylist 2>/dev/null)" || return 1
  [ -n "$path" ] || return 1
  case "$path" in
    "~/"*) path="$HOME/${path#\~/}" ;;
  esac
  if [ ! -f "$path" ] || [ ! -r "$path" ]; then
    say "agent-hook-guards.denylist is set but the file is missing or unreadable."
    return 2
  fi
  tr -d '\r' < "$path" | grep -v '^[[:space:]]*#' | grep -v '^[[:space:]]*$' > "$1"
  if [ ! -s "$1" ]; then
    say "agent-hook-guards.denylist names a file with no terms."
    return 2
  fi
  return 0
}

# scan <content-file> <label-file> <workdir>. Prints a line per hit, returns
# 1 if anything matched, 2 if the scan itself could not run.
scan() {
  local content="$1" labels="$2" work="$3" found=0 status line n
  secret_patterns > "$work/patterns"
  # grep exits 0 on a match, 1 on none, and 2 or more on an error. An error
  # must refuse, or a broken grep would let everything through.
  grep -n -E -f "$work/patterns" "$content" > "$work/hits" 2>/dev/null
  if [ "$?" -gt 1 ]; then
    say "grep failed while scanning for secrets."
    return 2
  fi
  load_denylist "$work/terms"
  status=$?
  if [ "$status" -eq 2 ]; then
    return 2
  fi
  if [ "$status" -eq 0 ]; then
    grep -n -i -F -f "$work/terms" "$content" >> "$work/hits" 2>/dev/null
    if [ "$?" -gt 1 ]; then
      say "grep failed while scanning for listed terms."
      return 2
    fi
  fi
  while IFS= read -r line; do
    n="${line%%:*}"
    say "match at $(sed -n "${n}p" "$labels") (content not shown)"
    found=1
  done < "$work/hits"
  return "$found"
}

mode_pre_commit() {
  local work name rc=0
  work="$(mktemp -d "${TMPDIR:-/tmp}/git-guard.XXXXXX")" || refuse "cannot create a temp dir"
  trap 'rm -rf "$work"' EXIT
  : > "$work/content"
  : > "$work/labels"

  git -c core.quotepath=off diff --cached --name-only --diff-filter=ACMR > "$work/names" ||
    refuse "git diff failed"
  while IFS= read -r name; do
    if secret_file_name "$name"; then
      say "secret-looking file name staged: $name"
      rc=1
    fi
    printf '%s\n' "$name" >> "$work/content"
    printf 'file name %s\n' "$name" >> "$work/labels"
  done < "$work/names"

  git -c core.quotepath=off diff --cached --no-color --no-ext-diff --no-prefix -U0 \
    --diff-filter=ACMR > "$work/diff" || refuse "git diff failed"
  awk -v C="$work/content" -v L="$work/labels" '
    /^diff --git / { inhunk = 0; next }
    !inhunk && /^\+\+\+ / { path = substr($0, 5); next }
    /^@@ / { inhunk = 1; split($3, a, ","); n = substr(a[1], 2) + 0; next }
    inhunk && /^\+/ { print substr($0, 2) >> C; print path ":" n >> L; n++; next }
  ' "$work/diff" || refuse "could not parse the staged diff"

  scan "$work/content" "$work/labels" "$work"
  case $? in
    0) ;;
    2) refuse "the scan could not run, or the denylist is unusable (fail closed)" ;;
    *) rc=1 ;;
  esac
  [ "$rc" -eq 0 ] || refuse "staged content looks like a secret or a private term. Remove it from the commit."
  exit 0
}

mode_commit_msg() {
  local msg="${1:-}" work
  [ -n "$msg" ] && [ -r "$msg" ] || refuse "no readable commit message file"
  work="$(mktemp -d "${TMPDIR:-/tmp}/git-guard.XXXXXX")" || refuse "cannot create a temp dir"
  trap 'rm -rf "$work"' EXIT
  grep -v '^#' "$msg" > "$work/content"
  awk '{ print "commit message line " NR }' "$work/content" > "$work/labels"
  scan "$work/content" "$work/labels" "$work"
  case $? in
    0) exit 0 ;;
    2) refuse "the scan could not run, or the denylist is unusable (fail closed)" ;;
    *) refuse "the commit message looks like it holds a secret or a private term." ;;
  esac
}

mode_pre_push() {
  local remote="${1:-}" url="${2:-}" allowed origin regex own
  [ -n "$url" ] || refuse "no remote URL given (fail closed)"
  while IFS= read -r allowed; do
    if [ -n "$allowed" ] && [ "$url" = "$allowed" ]; then
      exit 0
    fi
  done <<EOF
$(git config --get-all agent-hook-guards.allowedRemote 2>/dev/null)
EOF
  own="$(git config --bool --get agent-hook-guards.allowOwnOrigin 2>/dev/null)"
  if [ "$own" = "true" ]; then
    origin="$(git remote get-url origin 2>/dev/null)"
    regex="$(git config --get agent-hook-guards.ownerRegex 2>/dev/null)"
    if [ -z "$regex" ]; then
      refuse "allowOwnOrigin is true but agent-hook-guards.ownerRegex is not set (fail closed)"
    fi
    if [ -n "$origin" ] && [ "$url" = "$origin" ] && printf '%s\n' "$url" | grep -E -q -- "$regex"; then
      exit 0
    fi
  fi
  refuse "push to '$remote' is not allowed. Add the exact URL with: git config --add agent-hook-guards.allowedRemote <url>"
}

case "${1:-}" in
  pre-commit) mode_pre_commit ;;
  commit-msg) shift; mode_commit_msg "$@" ;;
  pre-push) shift; mode_pre_push "$@" ;;
  *) refuse "unknown mode '${1:-}'. Use pre-commit, commit-msg, or pre-push." ;;
esac
