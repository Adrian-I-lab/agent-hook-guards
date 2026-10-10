# Design

This note explains how the guards work and why. The README is the short version.

## 1. Hook contract

A guard is a Claude Code `PreToolUse` command hook. Claude Code runs it before each tool call and reads its exit code.

### Observed in a working local hook

These points were observed in a working hook setup before this project was written. The README's local wiring check re-checks the stdin and exit-code half by piping JSON through the shipped wrapper. A live Claude Code session check is described there but has not been recorded for this release.

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
| `agent_hook_guards/readonly_remote.py` | The read-only remote guard (v0.2 prototype). |
| `agent_hook_guards/injection_corpus.py` | Corpus loader, validator, seeded split, and scorer (v0.3 prototype). |
| `agent_hook_guards/injection_tripwire.py` | The injection tripwire (v0.3 prototype). Flags, never blocks. |
| `git-hooks/git-guard.sh` | The git guard. Pure bash, git, and grep. |
| `git-hooks/install.sh` | Installs the git guard into one repository's hooks folder. |

### Protected-paths rules

A tool call is blocked when any of these is true.

1. A path operand resolves, after `realpath`, under a protected prefix. Symlinks and `..` are resolved first.
2. A path operand has a component equal to a protected name.
3. A glob operand could reach a protected prefix, compared part by part with `fnmatch` where `**` matches any depth. A glob is also expanded, and blocked if any result is protected by rule 1 or 2.
4. A command that follows symlinks (`grep -R`, `find -L`, `find -follow`, `du -L`, `ls -L`, `tree -l`, `rg -L`, and similar) is aimed at a directory that holds a symlink into the protected area. The search has no depth cap. It stops after 20000 entries and then blocks.
5. A recursive command (`find`, `du`, `tree`, `rg`, `grep -r`, `ls -R`, `cp -r`, `rm -r`, and similar) is aimed at a directory that contains a protected prefix.

All comparisons are case-folded, because the default macOS filesystem ignores case. Rules 4 and 5, and the case folding, are the three choices most likely to block something harmless. The README lists them under Design choices.

### Read-only remote rules (v0.2 prototype)

Config lives in the `readonly_remote` object of the same JSON file. `hosts` is required. A missing or invalid section blocks every tool call this hook sees (fail closed), so register this hook only where the section exists.

For each local segment, past wrappers and inside substitutions, `sh -c` strings, `eval`, and heredocs fed to a shell:

1. `ssh` to a configured host. Options are parsed before and after the destination, as OpenSSH does. Any option outside the allowed set blocks. No remote command blocks. Otherwise the remote arguments are joined with spaces, exactly as ssh sends them, and parsed again with the shared tokeniser.
2. `ssh` to another host is allowed, unless an option value (`-J`, `-o HostName=`, `-o ProxyJump=`) names a configured host.
3. A copy or ssh-based tool (`scp`, `rsync`, `sftp`, `sshfs`, `mosh`, `lftp`, `autossh`) naming a configured host blocks. For other commands, an operand of the form `host:path` or `scheme://host` on a configured host blocks. A bare host name in text, a search pattern, or `echo` is mention, not access.

For each remote segment:

1. Substitutions and heredocs block. Redirects block unless the target is `/dev/null` or the redirect reads a file. Wrappers and `VAR=value` prefixes block.
2. The command word must be on the read allowlist. A fixed set of shells, interpreters, editors, pagers, and writers can never be added by config.
3. Per-command flag checks reject options that write, run a program, or never return.
4. Symlink-following flags block, because remote symlinks cannot be inspected.
5. Path operands are normalised lexically (`posixpath.normpath`), with `remote_home` for `~` and relative paths and `cd` tracked between segments. A path inside a forbidden prefix, a component equal to a forbidden name, or a glob that could reach either, blocks. A recursive command aimed at an ancestor of a forbidden prefix blocks, and one aimed at an unresolvable relative path blocks while forbidden prefixes are set.

To read these segments the shared tokeniser now also records `VAR=value` words before the command word (`Segment.assignments`). Existing guards ignore the new attribute.

### Injection tripwire (v0.3 prototype)

- The corpus is data, not code. `injection_corpus validate` checks every field, label, technique, channel, duplicate, and the stored split against a seeded recomputation.
- The tripwire builds several views of the text: the NFKC-normalised text, decoded base64, base32, hex, percent and HTML encodings, invisible Unicode tag characters, text with zero-width characters removed, look-alike letters mapped to Latin, rot13, reversed, and digit-for-letter text.
- Rules are regular expressions grouped by technique. A strong rule flags. Two different weak rules together flag. A weak rule found in a view that exists only because the input carried an encoding counts as strong, because instruction-like text hidden in an encoding is suspicious in itself.
- rot13, reversed, digit-for-letter, and look-alike views are computed for every input, so weak rules found there stay weak.
- The rules were written on the train split and frozen in a commit before the single scoring run on the test split.

## 6. Threat model

These guards are **coordination for a cooperative but fallible agent**. They are not a sandbox and not a security boundary.

| Guard | Stops | Does not stop |
|---|---|---|
| protected_paths | File tools and shell commands whose path operands reach a protected area through symlinks, relative paths, redirects, globs, substitutions, `sh -c` strings, symlink-following flags, or recursive walks | A script written to disk and then run; an interpreter that builds a path at run time; an obfuscated command; tools that do not pass through the hook; other processes; an agent that edits the hook config |
| git guard | Secret-shaped strings and listed terms in staged lines, staged file names, and commit messages; pushes to remotes that are not listed | `git commit --no-verify`; secrets with no recognisable shape; anything already in history; a fresh clone where the hooks were never installed |
| readonly_remote (v0.2 prototype) | ssh to a configured host without an allowlisted read command; tunnels and alternate configs; copies; remote writes and forbidden paths | Unlisted ssh aliases; scripts or interpreters that open their own connection; a shared connection used outside the agent; harmful reads |
| injection_tripwire (v0.3 prototype) | Nothing. It flags text for a closer look | Novel phrasings, other languages, single-signal injections |

## 7. Test strategy

- **Positive controls.** Each guard has cases that must block. A guard that allows them fails.
- **Negative controls.** Each guard has cases that must be allowed, including plain mentions of a protected name and innocent hyphenated words. A guard that blocks them fails.
- **Mutation check.** Every case file is also run against two broken stand-ins, one that always allows and one that always blocks. Each stand-in must produce mismatches. If it does not, the suite measures nothing.
- **Fixtures at run time.** Protected folders, symlinks, and configs are built in a temporary directory for each run.
- **Literals at run time.** Fake secrets in tests are joined from parts, so the literal never sits in a tracked file.
- **Interpreters.** `run_tests.sh` runs the unit tests on `/usr/bin/python3` and on the first `python3` on `PATH`, when they differ. CI covers 3.9, 3.11, and 3.13 on Linux and macOS.
