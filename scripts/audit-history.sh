#!/usr/bin/env bash
# Audit git history before it is made public. Prints counts only, never the
# matched text, so the audit cannot leak what it looks for.
#
#   PORTFOLIO_DENYLIST=<term file> bash scripts/audit-history.sh [--repo DIR] <revisions...>
#
# <revisions> are passed to git log and git rev-list, for example `main..topic`,
# `topic`, or `--all`. Rules, applied to every patch, commit message, and file
# name in range:
#
#   denylist   the private term list (same file as the pre-commit hook)
#   secrets    generic secret signatures and secret-like assignments
#   ips        private and carrier-grade NAT IPv4 ranges
#   home       absolute paths inside a named home directory
#   identity   author, committer, and Co-Authored-By addresses other than
#              <x>@users.noreply.github.com and noreply@anthropic.com
#   emails     any other address in the text, unless it is one of those two or
#              uses a reserved placeholder domain (RFC 2606: .invalid, .example,
#              .test, example.com, example.org, example.net)
#   blobs      blobs larger than 1 MiB
#
# Exit 0 and AUDIT CLEAN only if at least one commit was examined and every
# count is 0. Exit 1 otherwise. Fails closed if the term list is unusable.
set -u

here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=hooks/scan-lib.sh
. "$here/hooks/scan-lib.sh" || { echo "cannot load scan-lib.sh" >&2; exit 1; }

repo="."
if [ "${1:-}" = "--repo" ]; then
  repo="$2"
  shift 2
fi
[ "$#" -ge 1 ] || { echo "usage: audit-history.sh [--repo DIR] <revisions...>" >&2; exit 2; }

work="$(mktemp -d "${TMPDIR:-/tmp}/audit.XXXXXX")" || exit 1
trap 'rm -rf "$work"' EXIT

scan_load_terms "$work/terms" || exit 1

commits="$(git -C "$repo" rev-list --count "$@")" || { echo "git rev-list failed" >&2; exit 1; }
git -C "$repo" -c core.quotepath=off log -p --no-color --no-ext-diff --format='%H%n%an <%ae>%n%cn <%ce>%n%B' "$@" > "$work/log" \
  || { echo "git log failed" >&2; exit 1; }

count() {  # count <grep options...>; prints the number of matching lines, fails closed on error
  local n rc
  n="$(grep -c "$@" "$work/log")"
  rc=$?
  if [ "$rc" -gt 1 ]; then echo "grep failed (fail closed)" >&2; exit 1; fi
  printf '%s' "$n"
}

scan_secret_patterns > "$work/secret"
scan_assignment_patterns > "$work/assign"
scan_ip_patterns > "$work/ip"
scan_home_patterns > "$work/home"

deny="$(count -i -F -f "$work/terms")"
sec1="$(count -E -f "$work/secret")"
sec2="$(count -E -i -f "$work/assign")"
ips="$(count -E -f "$work/ip")"
home="$(count -E -f "$work/home")"

grep -Eo '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' "$work/log" > "$work/emails"
[ "$?" -le 1 ] || { echo "grep failed (fail closed)" >&2; exit 1; }
allowed_id='^([A-Za-z0-9._+-]+@users\.noreply\.github\.com|noreply@anthropic\.com)$'
reserved='@([A-Za-z0-9-]+\.)*(invalid|example|test)$|@([A-Za-z0-9-]+\.)*example\.(com|org|net)$'
emails="$(grep -v -E -e "$allowed_id" -e "$reserved" "$work/emails" | grep -c .)"
{ git -C "$repo" log --format='%ae%n%ce' "$@" \
  && git -C "$repo" log --format='%B' "$@" | grep -i '^co-authored-by:' | sed -n 's/.*<\(.*\)>.*/\1/p'; } > "$work/ids" \
  || { echo "git log failed" >&2; exit 1; }
identity="$(grep -v -E -e "$allowed_id" "$work/ids" | grep -c .)"
distinct_ids="$(sort -u "$work/ids" | grep -c .)"

blobs="$(git -C "$repo" rev-list --objects "$@" | cut -d ' ' -f 1 \
  | git -C "$repo" cat-file --batch-check='%(objecttype) %(objectsize)' \
  | awk '$1 == "blob" && $2 > 1048576 { n++ } END { print n + 0 }')" || { echo "blob scan failed" >&2; exit 1; }

secrets=$((sec1 + sec2))
printf 'commits=%s denylist=%s secrets=%s ips=%s home=%s identity_not_noreply=%s distinct_identities=%s other_emails=%s blobs_over_1MiB=%s\n' \
  "$commits" "$deny" "$secrets" "$ips" "$home" "$identity" "$distinct_ids" "$emails" "$blobs"

if [ "$commits" -gt 0 ] && [ "$deny" -eq 0 ] && [ "$secrets" -eq 0 ] && [ "$ips" -eq 0 ] \
   && [ "$home" -eq 0 ] && [ "$identity" -eq 0 ] && [ "$emails" -eq 0 ] && [ "$blobs" -eq 0 ]; then
  echo "AUDIT CLEAN"
  exit 0
fi
echo "AUDIT FOUND ISSUES"
exit 1
