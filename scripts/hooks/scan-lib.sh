# shellcheck shell=bash
# Shared scanner for this repository's own pre-commit and commit-msg hooks.
#
# These hooks protect this repository's history. They are separate from the
# git guard shipped in git-hooks/, so the hygiene check never depends on the
# code it protects.
#
# Term list: read ONLY from the file named by $PORTFOLIO_DENYLIST. One term per
# line, case-insensitive fixed strings, lines starting with # are comments.
# The hooks fail closed: if the variable is unset, the file is unreadable, or
# it holds no terms, every commit is refused.
#
# Matches are never printed. A report names the file, the line number, and the
# rule that fired, so the hook cannot leak what it is protecting.
#
# Written for bash 3.2 or later and BSD or GNU grep.

SCAN_FAILED=0

scan_fail() {
  printf 'BLOCKED: %s\n' "$1" >&2
  SCAN_FAILED=1
}

# scan_load_terms <out-file>
# Writes a cleaned copy of the term list (no comments, no blank lines, no
# carriage returns) to out-file. Returns non-zero, with a message, if the list
# cannot be used.
scan_load_terms() {
  local out="$1"
  if [ -z "${PORTFOLIO_DENYLIST:-}" ]; then
    printf 'BLOCKED: PORTFOLIO_DENYLIST is not set. Refusing to commit (fail closed).\n' >&2
    return 1
  fi
  if [ ! -f "$PORTFOLIO_DENYLIST" ] || [ ! -r "$PORTFOLIO_DENYLIST" ]; then
    printf 'BLOCKED: the file named by PORTFOLIO_DENYLIST is missing or unreadable. Refusing to commit (fail closed).\n' >&2
    return 1
  fi
  tr -d '\r' < "$PORTFOLIO_DENYLIST" | grep -v '^[[:space:]]*#' | grep -v '^[[:space:]]*$' > "$out"
  if [ ! -s "$out" ]; then
    printf 'BLOCKED: the term list holds no terms. Refusing to commit (fail closed).\n' >&2
    return 1
  fi
  return 0
}

# Extended regular expressions for generic secrets. Each one needs a fixed,
# distinctive prefix so ordinary prose does not match. Case-sensitive.
scan_secret_patterns() {
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

# A quoted literal of 12 or more characters assigned to a secret-like name.
# Matched case-insensitively.
scan_assignment_patterns() {
  cat <<'PATTERNS'
(password|passwd|secret|api_?key|access_?token|auth_?token)["']?[[:space:]]*[:=][[:space:]]*["'][^"'[:space:]]{12,}["']
PATTERNS
}

# Private and shared address ranges: 10/8, 172.16/12, 192.168/16, and the
# carrier-grade NAT range 100.64/10 (used by several mesh VPNs).
scan_ip_patterns() {
  cat <<'PATTERNS'
(^|[^0-9.])10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}([^0-9]|$)
(^|[^0-9.])172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}([^0-9]|$)
(^|[^0-9.])192\.168\.[0-9]{1,3}\.[0-9]{1,3}([^0-9]|$)
(^|[^0-9.])100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.[0-9]{1,3}\.[0-9]{1,3}([^0-9]|$)
PATTERNS
}

# Absolute paths inside a named home directory, on Linux or macOS.
scan_home_patterns() {
  cat <<'PATTERNS'
(^|[^A-Za-z0-9_.~-])/(home|Users)/[A-Za-z0-9._-]+
PATTERNS
}

# _scan_report <rule-name> <grep -n output file> <label-file> <terms-file>
# Only the line number of each hit is used. The matched text is discarded.
# A label that itself holds a listed term (a flagged file name) is hidden too.
_scan_report() {
  local rule="$1" hits="$2" labels="$3" terms="$4" line n label
  while IFS= read -r line; do
    n="${line%%:*}"
    label="$(sed -n "${n}p" "$labels")"
    if printf '%s\n' "$label" | grep -q -i -F -f "$terms"; then
      label="line ${n} of the scan (its path is itself flagged, so it is not shown)"
    fi
    scan_fail "${label}: matched rule '${rule}' (content not shown)"
  done < "$hits"
}

# scan_file <content-file> <label-file> <terms-file>
# content-file holds one line of text per line. label-file holds, on the same
# line number, a human label such as "path/to/file:12". Every rule is applied
# and each hit is reported by label and rule name only.
scan_file() {
  local content="$1" labels="$2" terms="$3" pat hits

  pat="$(mktemp "${TMPDIR:-/tmp}/scanpat.XXXXXX")" || { scan_fail "cannot create a temp file"; return; }
  hits="$(mktemp "${TMPDIR:-/tmp}/scanhit.XXXXXX")" || { rm -f "$pat"; scan_fail "cannot create a temp file"; return; }

  grep -n -i -F -f "$terms" "$content" > "$hits" 2>/dev/null
  _scan_report "private term list" "$hits" "$labels" "$terms"

  scan_secret_patterns > "$pat"
  grep -n -E -f "$pat" "$content" > "$hits" 2>/dev/null
  _scan_report "secret pattern" "$hits" "$labels" "$terms"

  scan_assignment_patterns > "$pat"
  grep -n -E -i -f "$pat" "$content" > "$hits" 2>/dev/null
  _scan_report "secret assignment" "$hits" "$labels" "$terms"

  scan_ip_patterns > "$pat"
  grep -n -E -f "$pat" "$content" > "$hits" 2>/dev/null
  _scan_report "private IP address" "$hits" "$labels" "$terms"

  scan_home_patterns > "$pat"
  grep -n -E -f "$pat" "$content" > "$hits" 2>/dev/null
  _scan_report "absolute home path" "$hits" "$labels" "$terms"

  rm -f "$pat" "$hits"
}
