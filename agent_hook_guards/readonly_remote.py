"""Read-only remote guard (v0.2, prototype).

Lets an agent look at a configured remote host over ssh, and nothing else.
See docs/design.md for the rules. In short, for a Bash call:

1. ``ssh`` to a configured host is allowed only with a remote command, and
   only with a small set of harmless ssh options. A bare ``ssh host`` is an
   interactive shell and is refused, as are tunnels, jump hosts, alternate
   configs, and forced terminals.
2. Every segment of the remote command must be on the read allowlist, pass
   its per-command flag checks, and carry no file redirect, substitution,
   heredoc, wrapper (``sudo``, ``env``, ``xargs``, ``nohup``, ...), or
   ``VAR=value`` prefix.
3. Remote path operands may not reach a configured forbidden prefix or
   forbidden name, including by a glob that could expand onto one, and
   symlink-following flags are refused outright, because the guard cannot
   see the remote filesystem.
4. Copy tools and other ssh-based tools (``scp``, ``rsync``, ``sftp``,
   ``sshfs``, ``mosh``, ...) that name a configured host are refused in either
   direction. So is any other local command whose operand is a
   ``host:path`` or ``scheme://host`` address on a configured host.

The same rules apply inside ``$(...)``, backticks, ``sh -c`` and ``bash -c``
strings, ``eval``, and heredocs fed to a local shell. Anything that cannot be
parsed is refused. Over-blocking is the accepted failure mode.

Run as a Claude Code PreToolUse hook:

    python3 -m agent_hook_guards.readonly_remote
"""

import fnmatch
import posixpath
import re

from . import _shell
from ._config import ConfigError, string_list
from ._hook import run
from .protected_paths import _glob_could_reach, _operands

GUARD = "readonly_remote"
SECTION = "readonly_remote"
MAX_DEPTH = 8

# Commands that only read, with per-command flag checks below.
DEFAULT_READ_COMMANDS = frozenset([
    "basename", "cat", "cd", "cksum", "cmp", "column", "comm", "cut", "date", "df",
    "diff", "dirname", "du", "echo", "egrep", "fgrep", "file", "find", "free", "git",
    "grep", "head", "hostname", "id", "ls", "md5sum", "nl", "nproc", "printenv",
    "printf", "ps", "pwd", "readlink", "realpath", "rev", "sha1sum", "sha256sum",
    "sort", "stat", "tail", "tr", "tree", "true", "uname", "uniq", "uptime", "wc",
    "which", "whoami", "zcat",
])

# Never allowed on the remote side, even if the config lists them. Each one
# runs other code, writes files, or changes state.
NEVER_ALLOWED = frozenset([
    "sh", "bash", "zsh", "dash", "ksh", "fish", "csh", "tcsh", "eval", "exec", "source",
    ".", "sudo", "su", "doas", "env", "xargs", "nohup", "setsid", "nice", "timeout",
    "time", "command", "builtin", "at", "batch", "crontab", "tee", "dd", "sed", "awk",
    "gawk", "perl", "python", "python3", "ruby", "node", "rm", "mv", "cp", "ln",
    "chmod", "chown", "chgrp", "mkdir", "rmdir", "touch", "truncate", "install",
    "scp", "rsync", "ssh", "sftp", "kill", "pkill", "killall", "less", "more", "vi",
    "vim", "nano", "emacs", "tar", "zip", "unzip", "gzip", "gunzip",
])

TEXT_COMMANDS = frozenset(["echo", "printf", "true"])
# autossh and the copy tools are refused outright when they name a host.
COPY_TOOLS = frozenset(["scp", "sftp", "rsync", "sshfs", "mosh", "lftp", "autossh"])
BARE_HOST_TOOLS = frozenset(["sftp", "sshfs", "mosh", "lftp", "autossh"])

# ssh options. Allowed flags take no value. Allowed valued options take one.
SSH_VALUE_OPTIONS = frozenset("BbcDEeFIiJLlmOoPpQRSWw")
SSH_ALLOWED_FLAGS = frozenset("46CnqTvx")
SSH_ALLOWED_VALUED = frozenset("lpi")
SSH_ALLOWED_O_KEYS = frozenset(["batchmode", "connecttimeout", "serveraliveinterval",
                                "serveralivecountmax", "loglevel"])

# Symlink-following flags, refused on the remote side because the guard
# cannot look for symlinks there.
FOLLOW_FLAGS = {
    "grep": frozenset(["-R", "--dereference-recursive"]),
    "egrep": frozenset(["-R", "--dereference-recursive"]),
    "fgrep": frozenset(["-R", "--dereference-recursive"]),
    "find": frozenset(["-L", "-follow", "-H"]),
    "du": frozenset(["-L", "--dereference", "-H", "-D"]),
    "ls": frozenset(["-L", "--dereference", "-H"]),
    "tree": frozenset(["-l"]),
    "stat": frozenset(["-L", "--dereference"]),
    "file": frozenset(["-L", "--dereference"]),
}
RECURSIVE_ALWAYS = frozenset(["find", "du", "tree"])
RECURSIVE_FLAGS = {
    "grep": frozenset(["-r", "-R", "--recursive", "--dereference-recursive"]),
    "egrep": frozenset(["-r", "-R", "--recursive", "--dereference-recursive"]),
    "fgrep": frozenset(["-r", "-R", "--recursive", "--dereference-recursive"]),
    "ls": frozenset(["-R", "--recursive"]),
}
EXACT_FLAG_COMMANDS = frozenset(["find"])

FIND_FORBIDDEN = frozenset(["-exec", "-execdir", "-ok", "-okdir", "-delete", "-fprint",
                            "-fprint0", "-fprintf", "-fls"])
GIT_SUBCOMMANDS = frozenset(["log", "show", "status", "diff", "rev-parse", "ls-files",
                             "describe", "blame", "shortlog", "branch", "remote", "tag"])
GIT_LIST_ONLY = {
    "branch": frozenset(["-a", "-r", "-v", "-vv", "--list", "--all", "--remotes",
                         "--show-current", "--no-color"]),
    "remote": frozenset(["-v", "--verbose"]),
    "tag": frozenset(["-l", "--list"]),
}

GLOB_CHARS = frozenset("*?[")
_URL = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://(?:[^@/]*@)?(\[[^\]]*\]|[^:/]*)")


class Settings(object):
    def __init__(self, hosts, commands, prefixes, names, home):
        self.hosts = hosts  # case-folded fnmatch patterns
        self.commands = commands  # allowed remote command words
        self.prefixes = prefixes  # case-folded normalised absolute remote paths
        self.names = names  # case-folded names
        self.home = home  # remote home directory, or None


def prepare(cfg):
    """Validate the readonly_remote section and return Settings."""
    section = cfg.get(SECTION)
    if not isinstance(section, dict):
        raise ConfigError("config key '{}' must be an object".format(SECTION))
    hosts = [h.casefold() for h in string_list(section, "hosts", required=True)]
    if not hosts:
        raise ConfigError("{}.hosts is empty".format(SECTION))
    for host in hosts:
        if host.strip("*?") == "" or any(c in host for c in " /@:"):
            raise ConfigError("{}.hosts entry is not a host name or pattern: {}".format(
                SECTION, host))
    extra = string_list(section, "extra_read_commands")
    for word in extra:
        if word in NEVER_ALLOWED or "/" in word:
            raise ConfigError("{}.extra_read_commands may not include '{}'".format(
                SECTION, word))
    prefixes = []
    for item in string_list(section, "forbidden_prefixes"):
        if not item.startswith("/"):
            raise ConfigError("forbidden prefix is not absolute: {}".format(item))
        norm = posixpath.normpath(item)
        if norm == "/":
            raise ConfigError("forbidding the remote root is not supported")
        prefixes.append(norm.casefold())
    names = set()
    for item in string_list(section, "forbidden_names"):
        if "/" in item or item in (".", ".."):
            raise ConfigError("forbidden name must be a plain name: {}".format(item))
        names.add(item.casefold())
    home = section.get("remote_home")
    if home is not None:
        if not isinstance(home, str) or not home.startswith("/"):
            raise ConfigError("{}.remote_home must be an absolute path".format(SECTION))
        home = posixpath.normpath(home)
    return Settings(hosts, DEFAULT_READ_COMMANDS | frozenset(extra), prefixes, names, home)


# ------------------------------------------------------------------ hosts

def _host_matches(host, settings):
    if not host:
        return False
    host = host.casefold().strip("[]")
    return any(fnmatch.fnmatchcase(host, pattern) for pattern in settings.hosts)


def _address_host(token, bare):
    """Host part of an scp-style or URL address, or of a bare host if allowed."""
    match = _URL.match(token)
    if match:
        return match.group(1)
    if token.startswith("-") or token.startswith("/") or token.startswith("."):
        return None
    if ":" in token:
        head = token.split(":", 1)[0]
        if "/" in head:
            return None
        return head.rsplit("@", 1)[-1]
    if bare:
        return token.rsplit("@", 1)[-1]
    return None


def _mentions_host(value, settings):
    """True if a free-form option value names a configured host."""
    for word in re.split(r"[^A-Za-z0-9._*?\[\]-]+", value):
        if _host_matches(word, settings):
            return True
    return False


# ------------------------------------------------------------------ ssh

class SshCall(object):
    def __init__(self, host, options, remote, refused):
        self.host = host
        self.options = options  # list of (letter, value or None)
        self.remote = remote  # remote command string, or None
        self.refused = refused  # first refused option, or None


def _parse_ssh(args):
    """Split ssh arguments into destination, options, and remote command."""
    options = []
    host = None
    i = 0
    rest = []
    while i < len(args):
        arg = args[i]
        if arg == "--" and host is None:
            i += 1
            if i < len(args):
                host = args[i]
                i += 1
            continue
        if arg.startswith("-") and len(arg) > 1:
            j = 1
            while j < len(arg):
                letter = arg[j]
                if letter in SSH_VALUE_OPTIONS:
                    value = arg[j + 1:]
                    if not value:
                        i += 1
                        value = args[i] if i < len(args) else ""
                    options.append((letter, value))
                    break
                options.append((letter, None))
                j += 1
            i += 1
            continue
        if host is None:
            host = arg
            i += 1
            continue
        rest = args[i:]
        break
    if host is not None:
        match = _URL.match(host)
        if match and host.lower().startswith("ssh://"):
            host = match.group(1)
        else:
            host = host.rsplit("@", 1)[-1]
    refused = None
    for letter, value in options:
        if value is None and letter in SSH_ALLOWED_FLAGS:
            continue
        if value is not None and letter in SSH_ALLOWED_VALUED:
            continue
        if letter == "o" and value is not None:
            key = re.split(r"[=\s]", value.strip(), 1)[0].casefold()
            if key in SSH_ALLOWED_O_KEYS:
                continue
        refused = "-" + letter + ("" if value is None else " " + value)
        break
    remote = " ".join(rest) if rest else None
    return SshCall(host, options, remote, refused)


def _check_ssh(args, settings, depth):
    call = _parse_ssh(args)
    if not _host_matches(call.host, settings):
        for letter, value in call.options:
            if value is not None and _mentions_host(value, settings):
                return ("ssh option -{} names a configured read-only host. Connect to it "
                        "directly with a read command instead.").format(letter)
        return None
    if call.refused:
        return ("ssh option '{}' is not allowed for read-only host '{}'. Allowed: "
                "-4 -6 -C -n -q -T -v -x, -l, -p, -i, and -o BatchMode, ConnectTimeout, "
                "ServerAliveInterval, ServerAliveCountMax, LogLevel.").format(
                    call.refused, call.host)
    if call.remote is None or not call.remote.strip():
        return ("bare 'ssh {}' opens an interactive shell on a read-only host. Give a "
                "read command, for example: ssh {} ls").format(call.host, call.host)
    reason = _check_remote(call.remote, settings, depth)
    if reason:
        return "remote command on '{}': {}".format(call.host, reason)
    return None


# ------------------------------------------------------------------ remote side

def _fold(text):
    return text.casefold()


def _under(path, prefix):
    return path == prefix or path.startswith(prefix.rstrip("/") + "/")


def _resolve(token, cwd, settings):
    """Lexically normalised absolute remote path, or None if unknown."""
    if token.startswith("~"):
        if settings.home is None or not (token == "~" or token.startswith("~/")):
            return None
        token = settings.home + token[1:]
    if "$" in token:
        return None
    if not token.startswith("/"):
        if cwd is None:
            return None
        token = posixpath.join(cwd, token)
    return posixpath.normpath(token)


def _remote_path_reason(token, cwd, settings):
    if not token or token == _shell.SUBST_PLACEHOLDER:
        return None
    parts = [p for p in _fold(token).split("/") if p]
    is_glob = any(c in GLOB_CHARS for c in token)
    for part in parts:
        if part in settings.names:
            return "'{}' goes through a forbidden name.".format(token)
        if is_glob and any(c in GLOB_CHARS for c in part):
            for name in settings.names:
                if fnmatch.fnmatchcase(name, part):
                    return "glob '{}' could expand onto a forbidden name.".format(token)
    resolved = _resolve(token, cwd, settings)
    if resolved is None:
        return None
    folded = _fold(resolved)
    for prefix in settings.prefixes:
        if is_glob:
            gparts = [p for p in folded.split("/") if p]
            if _glob_could_reach(gparts, [p for p in prefix.split("/") if p]):
                return "glob '{}' could expand into a forbidden path.".format(token)
        elif _under(folded, prefix):
            return "'{}' is inside a forbidden path.".format(token)
    for part in [p for p in folded.split("/") if p]:
        if part in settings.names:
            return "'{}' goes through a forbidden name.".format(token)
    return None


def _has_flag(command, args, flags):
    for arg in args:
        if arg == "--":
            break
        if arg in flags or arg.split("=", 1)[0] in flags:
            return True
        if command in EXACT_FLAG_COMMANDS:
            continue
        if arg.startswith("-") and not arg.startswith("--") and len(arg) > 2:
            for letter in arg[1:]:
                if "-" + letter in flags:
                    return True
    return False


def _short_cluster_has(arg, letters, value_letters=""):
    """True if a short option cluster such as -rno holds one of `letters`.

    Scanning stops at a letter in `value_letters`, because the rest of the
    cluster is that option's value.
    """
    if not arg.startswith("-") or arg.startswith("--") or len(arg) < 2:
        return False
    for letter in arg[1:]:
        if letter in value_letters:
            return False
        if letter in letters:
            return True
    return False


def _git_reason(args):
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in ("--no-pager", "-P"):
            i += 1
            continue
        if arg == "-C":
            i += 2
            continue
        break
    if i >= len(args):
        return "git with no read subcommand is refused."
    if args[i].startswith("-"):
        return "git global option '{}' is refused.".format(args[i])
    sub = args[i]
    if sub not in GIT_SUBCOMMANDS:
        return "git {} is not a read subcommand.".format(sub)
    rest = args[i + 1:]
    for arg in rest:
        base = arg.split("=", 1)[0]
        if base in ("--output", "--ext-diff", "--textconv", "-o"):
            return "git {} {} can write or run a program.".format(sub, base)
    if sub in GIT_LIST_ONLY:
        for arg in rest:
            if arg not in GIT_LIST_ONLY[sub]:
                return "git {} is allowed only to list (got '{}').".format(sub, arg)
    return None


def _flag_reason(command, args):
    """Per-command checks for options that write, run code, or never return."""
    if command == "find":
        for arg in args:
            if arg in FIND_FORBIDDEN:
                return "find {} can run a program, delete, or write.".format(arg)
    elif command == "sort":
        for arg in args:
            if arg.startswith("--output") or arg.startswith("--compress-program"):
                return "sort {} can write or run a program.".format(arg.split("=", 1)[0])
            if _short_cluster_has(arg, "o", "ktST"):
                return "sort -o writes a file."
    elif command == "tail":
        for arg in args:
            if arg.startswith("--follow") or arg in ("--retry",):
                return "tail {} never returns.".format(arg)
            if _short_cluster_has(arg, "fF", "ncs"):
                return "tail -f never returns."
    elif command == "tree":
        for arg in args:
            if arg == "-o" or arg.startswith("-o"):
                return "tree -o writes a file."
    elif command == "date":
        for arg in args:
            if arg.startswith("--set") or _short_cluster_has(arg, "s", "dfr"):
                return "date -s sets the clock."
    elif command == "hostname":
        for arg in args:
            if not arg.startswith("-"):
                return "hostname with an argument sets the host name."
    elif command == "uniq":
        positional = [a for a in args if not a.startswith("-") or a == "-"]
        if len(positional) > 1:
            return "uniq with a second file argument writes that file."
    elif command == "file":
        for arg in args:
            if _short_cluster_has(arg, "C", "efFmP"):
                return "file -C writes a compiled magic file."
    elif command == "git":
        return _git_reason(args)
    return None


def _check_remote_segment(segment, cwd, settings):
    """Return (reason or None, new remote cwd)."""
    for op, target in segment.redirects:
        if op in ("<",):
            reason = _remote_path_reason(target, cwd, settings)
            if reason:
                return "input redirect: " + reason, cwd
            continue
        if target == "/dev/null":
            continue
        return "redirect '{} {}' writes a file.".format(op, target), cwd
    if segment.wrappers:
        return "wrapper '{}' is refused.".format(segment.wrappers[0]), cwd
    if segment.assignments:
        return "variable assignment '{}' is refused.".format(
            segment.assignments[0].split("=", 1)[0] + "=..."), cwd
    command = segment.command
    if command is None:
        return None, cwd
    if command in NEVER_ALLOWED or command not in settings.commands:
        return "'{}' is not on the read allowlist.".format(command), cwd
    if command in TEXT_COMMANDS:
        return None, cwd

    reason = _flag_reason(command, segment.args)
    if reason:
        return reason, cwd
    if command in FOLLOW_FLAGS and _has_flag(command, segment.args, FOLLOW_FLAGS[command]):
        return ("{} with a symlink-following flag is refused, because the guard cannot "
                "check remote symlinks. Drop the flag.").format(command), cwd

    operands, nested = _operands(segment)
    if nested:
        return "nested shell strings are refused.", cwd
    for operand in operands:
        reason = _remote_path_reason(operand, cwd, settings)
        if reason:
            return "{}: {}".format(command, reason), cwd

    recursive = command in RECURSIVE_ALWAYS or (
        command in RECURSIVE_FLAGS and _has_flag(command, segment.args, RECURSIVE_FLAGS[command]))
    if recursive and settings.prefixes:
        targets = [o for o in operands if not any(c in GLOB_CHARS for c in o)] or ["."]
        for target in targets:
            resolved = _resolve(target, cwd, settings)
            if resolved is None:
                return ("{} would walk '{}', which cannot be resolved on the remote host. "
                        "Use an absolute path, or set remote_home.").format(command, target), cwd
            folded = _fold(resolved)
            for prefix in settings.prefixes:
                if prefix != folded and _under(prefix, folded):
                    return "{} would walk '{}', which contains a forbidden path.".format(
                        command, target), cwd

    if command == "cd":
        target = operands[0] if operands else "~"
        cwd = _resolve(target, cwd, settings)
    return None, cwd


def _check_remote(remote, settings, depth):
    if depth > MAX_DEPTH:
        return "command nests too deeply to check (fail closed)."
    try:
        parsed = _shell.parse(remote)
    except _shell.ShellParseError as exc:
        return "could not parse the remote command safely: {} (fail closed).".format(exc)
    if parsed.substitutions:
        return "command or process substitution is refused."
    if parsed.heredocs:
        return "a heredoc is refused."
    if not parsed.segments:
        return "empty remote command."
    cwd = settings.home
    for segment in parsed.segments:
        reason, cwd = _check_remote_segment(segment, cwd, settings)
        if reason:
            return reason
    return None


# ------------------------------------------------------------------ local side

def _check_local_segment(segment, settings, depth):
    command = segment.command
    if command is None or command in TEXT_COMMANDS:
        return None
    if command == "ssh":
        return _check_ssh(segment.args, settings, depth)
    if command in COPY_TOOLS:
        for arg in segment.args:
            if _host_matches(_address_host(arg, command in BARE_HOST_TOOLS), settings):
                return ("{} to or from a read-only host is refused. Use plain ssh with a "
                        "read command, for example ssh <host> cat <file>.").format(command)
            if arg.startswith("-") and _mentions_host(arg, settings):
                return "{} option names a read-only host.".format(command)
        return None
    operands, nested = _operands(segment)
    for text in nested:
        reason = _check_local(text, settings, depth + 1)
        if reason:
            return reason
    for operand in operands:
        if _host_matches(_address_host(operand, False), settings):
            return ("{} addresses read-only host '{}'. Only ssh with a read command may "
                    "reach it.").format(command, _address_host(operand, False))
    return None


def _check_local(command, settings, depth=0):
    if depth > MAX_DEPTH:
        return "command nests too deeply to check (fail closed)."
    try:
        parsed = _shell.parse(command)
    except _shell.ShellParseError as exc:
        return "could not parse the command safely: {} (fail closed).".format(exc)

    for heredoc in parsed.heredocs:
        try:
            header = _shell.split_segments(
                _shell.extract_substitutions(_shell.strip_comments(heredoc.header))[0])
        except _shell.ShellParseError:
            return "could not parse a heredoc header safely (fail closed)."
        if any(seg.command in _shell.SHELLS for seg in header):
            reason = _check_local(heredoc.body, settings, depth + 1)
            if reason:
                return "heredoc fed to a shell: " + reason

    for body in parsed.substitutions:
        reason = _check_local(body, settings, depth + 1)
        if reason:
            return "substitution: " + reason

    for segment in parsed.segments:
        reason = _check_local_segment(segment, settings, depth)
        if reason:
            return reason
    return None


def check(tool_name, tool_input, context):
    """Return a reason string to block the call, or None to allow it."""
    if tool_name != "Bash":
        return None
    command = tool_input.get("command")
    if not isinstance(command, str):
        return "Bash call has no command string (fail closed)."
    reason = _check_local(command, context.settings)
    if reason:
        return reason + _HINT
    return None


_HINT = (" This host is read-only for agents (agent-hook-guards readonly_remote). Prepare the"
         " change locally and hand the exact commands to a person.")


def main():
    run(GUARD, prepare, check)


if __name__ == "__main__":
    main()
