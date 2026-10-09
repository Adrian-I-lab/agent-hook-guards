# Design

This note explains how the guards work and why. The README is the short version.

## 1. Hook contract

A guard is a Claude Code `PreToolUse` command hook. Claude Code runs it before each tool call and reads its exit code.

### Observed in a working local hook

These points were observed in a working hook setup before this project was written. The live smoke test in the README re-checks them.

- The hook reads one JSON object on stdin. It has the keys `hook_event_name`, `tool_name`, and `tool_input`.
- `tool_input` carries `command` for the Bash tool. File tools carry `file_path`, `path`, or `pattern`.
- Exit 0 allows the call.
- Exit 2 blocks the call. Text written to stderr is shown to the model as the reason.
- Settings register the hook under `hooks.PreToolUse`, as a list entry with a `matcher` and a `{"type": "command", "command": "..."}` hook.

### Assumed, re-check against current Claude Code docs

- [Likely] Exit codes other than 0 and 2 are non-blocking errors. The guards never use them, so a crash cannot turn into an allow.
- [Likely] A JSON decision on stdout (`hookSpecificOutput.permissionDecision`) also exists. The guards use exit codes only.
- [Likely] Hooks also fire for tool calls made by subagents.
- [Likely] The payload carries a `cwd` key. The guards use it when present and fall back to their own working directory.
- [Likely] `NotebookEdit` carries `notebook_path`, and `Glob` carries `pattern` with an optional base `path`.

## 2. Configuration

- Format is JSON, parsed with the standard library. Python 3.9 or later. No third-party package.
- The file is found at `$AGENT_GUARDS_CONFIG`, else `~/.config/agent-hook-guards/config.json`.
- TOML was rejected because `tomllib` only exists from Python 3.11. A config parser that is missing on some interpreters would make a fail-closed guard refuse every call.
- The git guard reads `git config` keys under `agent-hook-guards.*` instead. Git config is the natural store for git hooks, and it keeps remote URLs out of the repository.

### Schema for the protected-paths guard

```json
{
  "protected_prefixes": ["/mnt/protected-share"],
  "protected_names": ["SharedData"]
}
```

| Key | Type | Meaning |
|---|---|---|
| `protected_prefixes` | list of absolute paths | Any path that resolves under one of these is protected. `~` is expanded. |
| `protected_names` | list of plain names | A path component with this name is protected wherever it appears. Use it for symlinks that point into a protected area. |

At least one entry is required across the two lists. Unknown top-level keys are ignored, so other guards can share the file.

### Git guard keys

| Key | Meaning |
|---|---|
| `agent-hook-guards.denylist` | Optional path to a private term list. One case-insensitive term per line. If set but unreadable, commits are refused. |
| `agent-hook-guards.allowedRemote` | Multi-valued. Exact remote URLs that pushes may go to. |
| `agent-hook-guards.allowOwnOrigin` | `true` to allow pushes to this repository's own `origin` URL, if it also matches `ownerRegex`. |
| `agent-hook-guards.ownerRegex` | Extended regular expression the `origin` URL must match. |

Nothing configured means every push is refused.

## 3. Fail closed

A guard that fails open is not a guard. Each of these exits 2:

- Empty stdin, or stdin that is not a JSON object.
- `tool_input` that is not an object.
- A missing, unreadable, or invalid config file.
- Any unexpected exception inside a guard.

Events other than `PreToolUse` are ignored with exit 0, so a guard wired to the wrong event does not break a session.

## 4. Mention is not access

A guard blocks a path in **operand position**, not a string that happens to appear in the command. Without this rule a guard blocks its own documentation, its own bug fixes, and every note about the protected area. People then switch it off.

These are authorship, not access, and are allowed:

- Heredoc bodies. The header line is kept, so a redirect target on that line is still checked.
- Shell comments.
- Arguments to `echo` and `printf`.
- The `content`, `old_string`, and `new_string` of a Write or Edit call.
- Search patterns. The first positional argument of `grep`, `rg`, `sed`, and `awk` is a pattern or a program, unless `-e` or `-f` supplies one.
- Commit messages given with `git commit -m`.

These are access, and are checked:

- Operands of any other command, including values after `--option=`.
- Redirect targets, in both directions.
- The body of `$(...)`, backticks, and `sh -c` or `bash -c` strings, each parsed as its own command.
- The real command word, found past `VAR=value` assignments and wrappers such as `env`, `command`, `nice`, `nohup`, `time`, `timeout`, and `sudo`.
- A `cd` changes the directory used to resolve later segments of the same command.

## 5. Module layout

| File | Role |
|---|---|
| `agent_hook_guards/_hook.py` | Reads stdin, filters events, calls a guard, maps the result to an exit code. Fails closed. |
| `agent_hook_guards/_config.py` | Finds, loads, and validates the JSON config. |
| `agent_hook_guards/_shell.py` | Tokeniser. Strips heredoc bodies and comments, splits segments, finds the command word, extracts redirects and substitutions. |
| `agent_hook_guards/protected_paths.py` | The protected-paths guard. |
| `git-hooks/git-guard.sh` | The git guard. Pure bash, git, and grep. |
| `git-hooks/install.sh` | Installs the git guard into one repository's hooks folder. |

### Protected-paths rules

A tool call is blocked when any of these is true.

1. A path operand resolves, after `realpath`, under a protected prefix. Symlinks and `..` are resolved first.
2. A path operand has a component equal to a protected name.
3. A glob operand could expand onto a protected path or name. Each wildcard component is compared with `fnmatch`, and `**` matches any depth.
4. A command that follows symlinks (`grep -R`, `find -L`, `find -follow`, `du -L`, `ls -L`, `tree -l`, `rg -L`, and similar) is aimed at a directory that holds a symlink into the protected area.
5. A recursive command (`find`, `du`, `tree`, `rg`, `grep -r`, `ls -R`, `cp -r`, `rm -r`, and similar) is aimed at a directory that contains a protected prefix.

## 6. Threat model

These guards are **coordination for a cooperative but fallible agent**. They are not a sandbox and not a security boundary.

| Guard | Stops | Does not stop |
|---|---|---|
| protected_paths | File tools and shell commands whose path operands reach a protected area through symlinks, relative paths, redirects, globs, substitutions, or symlink-following flags | A script written to disk and then run; an interpreter that builds a path at run time; tools that do not pass through the hook; other processes; an agent that edits the hook config |
| git guard | Secret-shaped strings and listed terms in staged lines, staged file names, and commit messages; pushes to remotes that are not listed | `git commit --no-verify`; secrets with no recognisable shape; anything already in history; a fresh clone where the hooks were never installed |

## 7. Test strategy

- **Positive controls.** Each guard has cases that must block. A guard that allows them fails.
- **Negative controls.** Each guard has cases that must be allowed, including plain mentions of a protected name and innocent hyphenated words. A guard that blocks them fails.
- **Mutation check.** Every case file is also run against two broken stand-ins, one that always allows and one that always blocks. Each stand-in must produce mismatches. If it does not, the suite measures nothing.
- **Fixtures at run time.** Protected folders, symlinks, and configs are built in a temporary directory for each run.
- **Literals at run time.** Fake secrets in tests are joined from parts, so the literal never sits in a tracked file.
- **Interpreters.** Unit tests run on every Python found from 3.9 up. CI covers 3.9, 3.11, and 3.13 on Linux and macOS.
