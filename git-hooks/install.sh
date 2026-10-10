#!/usr/bin/env bash
# Install the agent-hook-guards git guard into one repository.
#
# Usage: git-hooks/install.sh [path-to-repository]   (default: current directory)
#
# Copies git-guard.sh into the repository's .git/hooks folder and writes
# pre-commit, commit-msg, and pre-push hooks that call it. Existing hooks are
# never overwritten. Global git config is never read for a target or changed.
set -eu

src="$(cd "$(dirname "$0")" && pwd)/git-guard.sh"
target="${1:-.}"

[ -f "$src" ] || { echo "install: cannot find $src" >&2; exit 1; }
git -C "$target" rev-parse --git-dir >/dev/null 2>&1 || { echo "install: $target is not a git repository" >&2; exit 1; }

if [ -n "$(git -C "$target" config --get core.hooksPath 2>/dev/null || true)" ]; then
  echo "install: core.hooksPath is set for this repository, so .git/hooks would be ignored." >&2
  echo "install: install by hand into that folder, or unset core.hooksPath first." >&2
  exit 1
fi

# The common directory, not --git-dir: in a linked worktree --git-dir points
# at .git/worktrees/<name>, whose hooks folder git never reads.
gitdir="$(cd "$target" && cd "$(git rev-parse --git-common-dir)" && pwd)"
hooks="$gitdir/hooks"
mkdir -p "$hooks"

for hook in pre-commit commit-msg pre-push; do
  if [ -e "$hooks/$hook" ]; then
    echo "install: $hooks/$hook already exists. Not overwriting. Merge it by hand." >&2
    exit 1
  fi
done

cp "$src" "$hooks/agent-hook-guards-git-guard.sh"
chmod +x "$hooks/agent-hook-guards-git-guard.sh"
for hook in pre-commit commit-msg pre-push; do
  cat > "$hooks/$hook" <<EOF
#!/usr/bin/env bash
# Installed by agent-hook-guards. Fails closed if the guard is missing.
guard="\$(dirname "\$0")/agent-hook-guards-git-guard.sh"
[ -f "\$guard" ] || { echo "[agent-hook-guards] guard missing, refusing" >&2; exit 1; }
exec bash "\$guard" $hook "\$@"
EOF
  chmod +x "$hooks/$hook"
  echo "install: wrote $hooks/$hook"
done
echo "install: copied the guard to $hooks/agent-hook-guards-git-guard.sh"
echo "install: pushes are refused until you set agent-hook-guards.allowedRemote or allowOwnOrigin."
