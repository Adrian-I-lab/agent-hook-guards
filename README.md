# agent-hook-guards

Small, tested guards that stop an AI coding agent from touching protected paths, committing secrets, or pushing to the wrong remote. Every guard ships with cases that show it blocking a bad action and allowing a safe one, plus a mutation check that proves the tests can fail.

> **Threat model in one line.** These guards are coordination for a cooperative but fallible agent. They are **not a sandbox** and **not a security boundary**. See [Threat model](#threat-model).

## Why

Agent permission rules are usually scoped to tools. A rule that denies the Read tool on a folder does not stop `cat`, a redirect, a glob, a symlink, or `grep -R` reaching the same files through the shell. A `PreToolUse` hook sees every tool call before it runs, so one guard can apply one rule to all of them.

Git is the other common leak. An agent that is told "commit your work" will commit whatever is staged. A git hook is the last check before content enters history.

## What is in v0.1

| Part | What it does |
|---|---|
| `agent_hook_guards/protected_paths.py` | A Claude Code `PreToolUse` hook. Blocks file tools and shell commands whose path operands reach a protected area. |
| `git-hooks/git-guard.sh` | pre-commit, commit-msg, and pre-push hooks. Blocks secret-shaped content and file names, optional private terms, and pushes to unlisted remotes. |
| `agent_hook_guards/_hook.py`, `_config.py`, `_shell.py` | Shared runtime, config loader, and shell tokeniser. Standard library only. |

Python 3.9 or later. No third-party packages. The git guard needs only bash, git, and grep.

## Quick start

```sh
git clone <this repository> /opt/agent-hook-guards
mkdir -p ~/.config/agent-hook-guards
cp /opt/agent-hook-guards/examples/config.example.json ~/.config/agent-hook-guards/config.json
# edit the config, then try it:
printf '%s' '{"tool_name":"Read","tool_input":{"file_path":"/mnt/protected-share/a.txt"}}' \
  | PYTHONPATH=/opt/agent-hook-guards python3 -m agent_hook_guards.protected_paths
echo "exit $?"   # 2 means blocked
```

`/opt/agent-hook-guards` is a placeholder. Use wherever you cloned the repository.

## Configuration

The protected-paths guard reads JSON from `$AGENT_GUARDS_CONFIG`, else `~/.config/agent-hook-guards/config.json`.

```json
{
  "protected_prefixes": ["/mnt/protected-share"],
  "protected_names": ["SharedData"]
}
```

| Key | Meaning |
|---|---|
| `protected_prefixes` | Absolute paths. Anything that resolves under one of them is protected. `~` is expanded. |
| `protected_names` | Plain names. A path component with this name is protected anywhere. Use it for symlinks into the protected area. |

A missing, unreadable, or invalid config blocks every call until it is fixed.

The git guard reads `git config` keys, so no remote URL is ever written into a repository.

| Key | Meaning |
|---|---|
| `agent-hook-guards.denylist` | Optional file of private terms, one per line, matched without case. Set but unreadable means commits are refused. |
| `agent-hook-guards.allowedRemote` | Multi-valued. Exact URLs that pushes may go to. |
| `agent-hook-guards.allowOwnOrigin` | `true` allows pushes to this repository's own `origin` URL, if it also matches `ownerRegex`. |
| `agent-hook-guards.ownerRegex` | Extended regular expression that the `origin` URL must match. |

With nothing configured, every push is refused.

## Wiring into Claude Code

Add a `PreToolUse` hook to a settings file. The full example is [`examples/settings.example.json`](examples/settings.example.json).

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "sh -c 'G=/opt/agent-hook-guards; [ -f \"$G/agent_hook_guards/protected_paths.py\" ] || { echo \"agent-hook-guards: guard missing, refusing\" >&2; exit 2; }; PYTHONPATH=\"$G\" python3 -m agent_hook_guards.protected_paths; [ $? -eq 0 ] || exit 2'"
          }
        ]
      }
    ]
  }
}
```

The `sh -c` wrapper matters. If the guard file is missing, or Python cannot start, the wrapper still exits 2, so a broken install blocks instead of silently allowing. A test runs this exact wrapper.

Hook contract the guards rely on:

- The hook gets one JSON object on stdin with `hook_event_name`, `tool_name`, and `tool_input`.
- Exit 0 allows. Exit 2 blocks, and stderr is shown to the model.
- [Likely] Other exit codes are non-blocking errors, so the guards never use them.
- [Likely] Hooks also fire for subagent tool calls.
- [Likely] The payload includes `cwd`. If it does not, the guard uses its own working directory.

Lines marked [Likely] come from documentation, not from a live check. Re-check them against the current Claude Code docs. [`docs/design.md`](docs/design.md) has the details.

### Installing the git guard

```sh
/opt/agent-hook-guards/git-hooks/install.sh path/to/repo
git -C path/to/repo config --add agent-hook-guards.allowedRemote <exact push URL>
```

The installer copies the guard into that repository's `.git/hooks`. It never overwrites an existing hook and never changes global git config. It refuses if `core.hooksPath` is set, because `.git/hooks` would then be ignored.

## What the protected-paths guard checks

**Mention is not access.** The guard blocks a path in operand position, not a string that happens to appear. Otherwise it would block its own documentation and every note about the protected area, and people would switch it off.

Blocked:

- A path operand that resolves, after `realpath`, under a protected prefix. This covers symlinks, `..`, and relative paths.
- A path with a component equal to a protected name.
- A redirect target in either direction, and values in `--option=value` form.
- A glob that could reach a protected prefix, or that expands now onto a protected path or name.
- A symlink-following command (`grep -R`, `find -L`, `rg --follow`, `du -L`, `tree -l`, and similar) aimed at a directory that holds a symlink into the protected area.
- A recursive command (`find`, `du`, `rg`, `grep -r`, `ls -R`, `cp -r`, and similar) aimed at a directory that contains a protected prefix.
- The same rules inside `$(...)`, backticks, `<(...)`, `sh -c` and `bash -c` strings, `eval`, and heredocs fed to a shell.
- The real command word is found past `VAR=value`, `env`, `nice`, `timeout`, `sudo`, and similar wrappers. A `cd` moves the base for later segments.

Allowed, because it is authorship:

- Heredoc bodies written to a file, comments, and `echo` or `printf` text.
- Write and Edit content.
- Search patterns, such as the first argument to `grep`, and `find -name` patterns.
- `git commit -m` messages.

Comparisons ignore case, because the default macOS filesystem does.

## Threat model

These guards are **coordination for a cooperative but fallible agent**. They catch the honest mistake: the agent that reaches for `cat` after the Read tool was refused, or stages a `.env` file. They are not a sandbox, not a security boundary against a malicious process, and they do not see what a program does after it starts.

| Guard | Stops | Does not stop |
|---|---|---|
| protected_paths | File tools and shell commands whose path operands reach a protected area through absolute or relative paths, symlinks, redirects, globs, substitutions, `sh -c` strings, symlink-following flags, or recursive walks | A script written to disk and then run; an interpreter that builds a path at run time (`python3 -c` with string joins); an obfuscated command (base64, variables set in an earlier call); tools that do not pass through the hook; other processes on the machine; an agent that edits the hook config or settings |
| git guard | Secret-shaped strings and listed terms in staged lines, staged file names, and commit messages; secret-looking file names; pushes to remotes that are not listed | `git commit --no-verify`; secrets with no recognisable shape; anything already in history; a fresh clone where the hooks were never installed (hooks are per clone) |

Each row says what the guard stops and what it does not stop. If you need a boundary, use operating system permissions, a container, or a separate account. Use these guards on top of that, not instead of it.

## Testing

Run everything with:

```sh
bash run_tests.sh
```

It stops at the first failing step. Measured output of that command on Linux with Python 3.13:

| Step | Result |
|---|---|
| unittest | 49 tests, OK |
| protected_paths case file | `cases=52 blocked_ok=31 allowed_ok=21 mismatches=0` |
| git guard tests | `block_ok=19 allow_ok=15 failures=0`, including six innocent hyphenated words such as `risk-assessment` |
| repository hygiene hook tests | `block_ok=10 allow_ok=3 failures=0` |
| mutation check | 86 cases, real guards 0 mismatches, always-allow stand-ins 31 and 16 mismatches, always-block stand-ins 21 and 13 mismatches |

How the tests are built:

- **Positive controls.** Cases that must block. A guard that allows them fails.
- **Negative controls.** Cases that must be allowed, such as a doc that names the protected path or a word like `disk-space-reclaim`. A guard that blocks them fails.
- **Mutation check.** `tests/mutation_check.py` reruns every guard's tests against an always-allow and an always-block stand-in. Each stand-in must fail some cases, or the tests are not measuring anything. `AGH_FORCE_STANDIN=always_allow python3 tests/mutation_check.py` puts a stand-in in place of the real guard and exits 1.
- **Fixtures at run time.** Protected folders, symlinks, configs, and git repositories are built in temporary directories.
- **Literals at run time.** Fake secrets are joined from parts, so no secret-shaped literal sits in a tracked file.

CI runs the same command on Ubuntu and macOS with Python 3.9, 3.11, and 3.13.

## Limitations

- The shell tokeniser is deliberately small. It handles the common shapes above, not every bash feature. Anything it cannot parse is blocked.
- Variables are expanded from the hook's own environment, which may differ from the shell the agent runs.
- A symlink-following walk stops after a fixed number of entries and then blocks, so `grep -R` over a very large tree is refused. Use `grep -r`.
- The git guard's secret patterns are high-confidence signatures with fixed prefixes. A secret with no known prefix will pass.

## This repository's own hooks

`scripts/hooks/` holds the pre-commit and commit-msg hooks used while developing this project. They scan for a private term list named by `$PORTFOLIO_DENYLIST`, generic secrets, private IP ranges, and absolute home paths, and they refuse every commit if the list is missing. Enable them with `git config core.hooksPath scripts/hooks`. They are kept separate from the shipped git guard, so the hygiene check never depends on the code it protects.

## Licence

MIT. See [LICENSE](LICENSE).
