"""Protected-paths guard.

Blocks a tool call when a path it would touch resolves into a protected area.
See docs/design.md for the rules. In short:

1. A path operand resolves (realpath) under a protected prefix.
2. A path operand has a component equal to a protected name.
3. A glob operand expands, or could expand, onto a protected path or name.
4. A symlink-following command is aimed at a directory holding a symlink
   into the protected area.
5. A recursive command is aimed at a directory that contains a protected
   prefix.

Mention is not access. Heredoc bodies, comments, echo and printf text, Write
and Edit content, search patterns, and commit messages are not checked.

Run as a Claude Code PreToolUse hook:

    python3 -m agent_hook_guards.protected_paths
"""

import fnmatch
import glob
import os

from . import _shell
from ._config import ConfigError, string_list
from ._hook import run

GUARD = "protected_paths"

MAX_DEPTH = 8  # nested substitutions and sh -c strings
GLOB_LIMIT = 5000  # glob results examined before giving up (fail closed)
WALK_LIMIT = 20000  # directory entries examined for symlinks before giving up
WALK_DEPTH = 6

PATH_KEYS = ("file_path", "notebook_path", "path")
LIST_KEYS = ("paths", "file_paths")

# Arguments of these commands are text, not paths.
TEXT_COMMANDS = frozenset(["echo", "printf", "true", "false", ":"])

# Commands whose first positional argument is a pattern or program, unless an
# option in the paired set supplies it instead.
PATTERN_FIRST = {
    "grep": frozenset(["-e", "--regexp", "-f", "--file"]),
    "egrep": frozenset(["-e", "--regexp", "-f", "--file"]),
    "fgrep": frozenset(["-e", "--regexp", "-f", "--file"]),
    "rg": frozenset(["-e", "--regexp", "-f", "--file"]),
    "ag": frozenset(),
    "ack": frozenset(),
    "sed": frozenset(["-e", "--expression", "-f", "--file"]),
    "awk": frozenset(["-f", "--file"]),
    "gawk": frozenset(["-f", "--file"]),
    "mawk": frozenset(["-f"]),
    "nawk": frozenset(["-f"]),
    "jq": frozenset(["-f", "--from-file"]),
}

# Options whose separate value is text, not a path. Values of other options
# are checked like any operand.
TEXT_OPTION_VALUES = {
    "grep": frozenset(["-e", "--regexp", "-A", "-B", "-C", "-m", "--max-count",
                       "--include", "--exclude", "--exclude-dir", "--label", "--color"]),
    "rg": frozenset(["-e", "--regexp", "-A", "-B", "-C", "-m", "-g", "--glob", "--iglob",
                     "-t", "--type", "-T", "--type-not", "-j", "--threads", "-M",
                     "--max-columns", "-d", "--max-depth", "-r", "--replace"]),
    "sed": frozenset(["-e", "--expression", "-l"]),
    "awk": frozenset(["-v", "-F"]),
    "gawk": frozenset(["-v", "-F"]),
    "find": frozenset(["-name", "-iname", "-path", "-ipath", "-wholename", "-iwholename",
                       "-regex", "-iregex", "-type", "-maxdepth", "-mindepth", "-size",
                       "-mtime", "-mmin", "-atime", "-ctime", "-user", "-group", "-perm",
                       "-printf", "-fprintf"]),
    "git": frozenset(["-m", "--message", "--grep", "--author", "--committer", "-S", "-G",
                      "--format", "--pretty"]),
    "jq": frozenset(["--arg", "--argjson"]),
}
for _alias in ("egrep", "fgrep"):
    TEXT_OPTION_VALUES[_alias] = TEXT_OPTION_VALUES["grep"]

# Flags that make a command follow symlinks while it walks a tree. Commands in
# EXACT_FLAG_COMMANDS use single-dash long options, so flags match exactly.
FOLLOW_FLAGS = {
    "grep": frozenset(["-R", "--dereference-recursive"]),
    "egrep": frozenset(["-R", "--dereference-recursive"]),
    "fgrep": frozenset(["-R", "--dereference-recursive"]),
    "find": frozenset(["-L", "-follow"]),
    "du": frozenset(["-L", "--dereference"]),
    "ls": frozenset(["-L", "--dereference"]),
    "tree": frozenset(["-l"]),
    "rg": frozenset(["-L", "--follow"]),
    "ag": frozenset(["-f", "--follow"]),
    "cp": frozenset(["-L", "--dereference"]),
    "rsync": frozenset(["-L", "--copy-links"]),
    "tar": frozenset(["-h", "--dereference"]),
    "chmod": frozenset(["-L"]),
    "chown": frozenset(["-L"]),
}
EXACT_FLAG_COMMANDS = frozenset(["find"])

# Commands that always walk a tree, and commands that walk only with a flag.
RECURSIVE_ALWAYS = frozenset(["find", "du", "tree", "rg", "ag", "ack"])
RECURSIVE_FLAGS = {
    "grep": frozenset(["-r", "-R", "--recursive", "--dereference-recursive"]),
    "egrep": frozenset(["-r", "-R", "--recursive", "--dereference-recursive"]),
    "fgrep": frozenset(["-r", "-R", "--recursive", "--dereference-recursive"]),
    "ls": frozenset(["-R", "--recursive"]),
    "cp": frozenset(["-r", "-R", "-a", "--recursive", "--archive"]),
    "rm": frozenset(["-r", "-R", "--recursive"]),
    "chmod": frozenset(["-R", "--recursive"]),
    "chown": frozenset(["-R", "--recursive"]),
    "chgrp": frozenset(["-R", "--recursive"]),
    "rsync": frozenset(["-r", "-a", "--recursive", "--archive"]),
    "zip": frozenset(["-r", "--recurse-paths"]),
    "scp": frozenset(["-r"]),
}
# Recursive commands that walk the working directory when given no path.
DEFAULT_TO_CWD = frozenset(["find", "du", "tree", "rg", "ag", "ack", "grep", "egrep",
                            "fgrep", "ls"])

GLOB_CHARS = frozenset("*?[")


class Settings(object):
    def __init__(self, prefixes, names):
        self.prefixes = prefixes  # list of (normalised, realpath) pairs, case-folded
        self.names = names  # set of case-folded names


def prepare(cfg):
    """Validate the config and return Settings. Raise ConfigError if invalid."""
    raw_prefixes = string_list(cfg, "protected_prefixes")
    raw_names = string_list(cfg, "protected_names")
    if not raw_prefixes and not raw_names:
        raise ConfigError("protected_prefixes and protected_names are both empty")
    prefixes = []
    for item in raw_prefixes:
        expanded = os.path.expanduser(item)
        if not os.path.isabs(expanded):
            raise ConfigError("protected prefix is not absolute: {}".format(item))
        norm = os.path.normpath(expanded)
        if norm == os.sep:
            raise ConfigError("protecting the filesystem root is not supported")
        prefixes.append((_fold(norm), _fold(os.path.realpath(norm))))
    names = set()
    for item in raw_names:
        if os.sep in item or item in (".", ".."):
            raise ConfigError("protected name must be a plain name: {}".format(item))
        names.add(_fold(item))
    return Settings(prefixes, names)


def _fold(text):
    # Compare case-insensitively. The default macOS filesystem ignores case,
    # so a case-sensitive guard there could be bypassed by changing case.
    return text.casefold()


def _under(path, prefix):
    return path == prefix or path.startswith(prefix.rstrip(os.sep) + os.sep)


def _forms(path, cwd):
    """Return (normalised, realpath) of a path token, both case-folded."""
    expanded = os.path.expanduser(os.path.expandvars(path))
    absolute = os.path.normpath(os.path.join(cwd, expanded))
    return _fold(absolute), _fold(os.path.realpath(absolute))


def _components(path):
    return [c for c in _fold(path).split(os.sep) if c]


def _path_reason(token, cwd, settings):
    """Reason string if a single path token touches the protected area."""
    if not token or token == _shell.SUBST_PLACEHOLDER:
        return None
    if any(c in GLOB_CHARS for c in token):
        return _glob_reason(token, cwd, settings)
    return _concrete_reason(token, cwd, settings)


def _concrete_reason(token, cwd, settings):
    """Reason string if a path with no glob characters touches the protected area."""
    norm, real = _forms(token, cwd)
    for pnorm, preal in settings.prefixes:
        for candidate in (norm, real):
            if _under(candidate, pnorm) or _under(candidate, preal):
                return "'{}' resolves into a protected path.".format(token)
    for part in _components(token) + _components(norm):
        if part in settings.names:
            return "'{}' goes through a protected name.".format(token)
    return None


def _glob_could_reach(glob_parts, prefix_parts):
    """True if a glob, compared part by part, could name the prefix or below it."""
    for i, gpart in enumerate(glob_parts):
        if gpart == "**":
            return True
        if i >= len(prefix_parts):
            return True  # the glob already matched the whole prefix
        if not fnmatch.fnmatchcase(prefix_parts[i], gpart):
            return False
    return len(glob_parts) >= len(prefix_parts)


def _glob_reason(token, cwd, settings):
    expanded = os.path.expanduser(os.path.expandvars(token))
    absolute = os.path.normpath(os.path.join(cwd, expanded))
    gparts = _components(absolute)
    for pnorm, preal in settings.prefixes:
        for prefix in (pnorm, preal):
            if _glob_could_reach(gparts, _components(prefix)):
                return "glob '{}' could expand into a protected path.".format(token)
    count = 0
    for match in glob.iglob(absolute, recursive=True):
        count += 1
        if count > GLOB_LIMIT:
            return "glob '{}' expands to too many paths to check (fail closed).".format(token)
        if _concrete_reason(match, cwd, settings):
            return "glob '{}' expands into a protected path.".format(token)
    return None


def _is_ancestor_of_prefix(path, cwd, settings):
    norm, real = _forms(path, cwd)
    for pnorm, preal in settings.prefixes:
        for candidate in (norm, real):
            for prefix in (pnorm, preal):
                if prefix != candidate and _under(prefix, candidate):
                    return True
    return False


def _holds_protected_symlink(path, cwd, settings):
    """True if a walk below path finds a symlink into the protected area.

    Returns None if the walk is too large to finish (the caller blocks).
    """
    expanded = os.path.expanduser(os.path.expandvars(path))
    root = os.path.normpath(os.path.join(cwd, expanded))
    if not os.path.isdir(root):
        return False
    seen = 0
    base_depth = root.rstrip(os.sep).count(os.sep)
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        if dirpath.count(os.sep) - base_depth >= WALK_DEPTH:
            dirnames[:] = []
        for entry in dirnames + filenames:
            seen += 1
            if seen > WALK_LIMIT:
                return None
            full = os.path.join(dirpath, entry)
            if not os.path.islink(full):
                continue
            if _fold(entry) in settings.names:
                return True
            real = _fold(os.path.realpath(full))
            for pnorm, preal in settings.prefixes:
                if _under(real, pnorm) or _under(real, preal):
                    return True
    return False


def _has_flag(command, args, flags):
    for arg in args:
        if arg == "--":
            break
        if arg in flags:
            return True
        if command in EXACT_FLAG_COMMANDS:
            continue
        if arg.startswith("-") and not arg.startswith("--") and len(arg) > 2:
            for letter in arg[1:]:
                if "-" + letter in flags:
                    return True
    return False


def _operands(segment):
    """Split a segment's args into (path operands, nested shell strings)."""
    command = segment.command
    args = segment.args
    text_values = TEXT_OPTION_VALUES.get(command, frozenset())
    pattern_opts = PATTERN_FIRST.get(command)
    pattern_given = pattern_opts is not None and any(
        a.split("=", 1)[0] in pattern_opts for a in args
    )
    pattern_pending = pattern_opts is not None and not pattern_given
    operands = []
    nested = []

    if command in _shell.SHELLS or command == "eval":
        if command == "eval":
            nested.append(" ".join(args))
            return operands, nested
        for i, arg in enumerate(args):
            if arg.startswith("-") and not arg.startswith("--") and "c" in arg[1:]:
                if i + 1 < len(args):
                    nested.append(args[i + 1])
                return operands, nested

    i = 0
    end_of_options = False
    while i < len(args):
        arg = args[i]
        i += 1
        if not end_of_options and arg == "--":
            end_of_options = True
            continue
        if not end_of_options and arg.startswith("-") and len(arg) > 1:
            name, eq, value = arg.partition("=")
            if eq:
                if name not in text_values:
                    operands.append(value)
                continue
            if arg in text_values:
                i += 1  # skip the text value
            elif command in ("grep", "egrep", "fgrep", "rg") and arg in ("-f", "--file"):
                if i < len(args):
                    operands.append(args[i])
                i += 1
            elif command in ("awk", "gawk", "mawk", "nawk", "sed", "jq") and arg in (
                "-f", "--file", "--from-file"
            ):
                if i < len(args):
                    operands.append(args[i])
                i += 1
            continue
        if pattern_pending:
            pattern_pending = False
            continue
        operands.append(arg)
    return operands, nested


def _check_segment(segment, cwd, settings, depth):
    """Return (reason or None, new cwd)."""
    for op, target in segment.redirects:
        reason = _path_reason(target, cwd, settings)
        if reason:
            return "redirect {} {}".format(op, reason), cwd
    command = segment.command
    if command is None or command in TEXT_COMMANDS:
        return None, cwd

    operands, nested = _operands(segment)
    for text in nested:
        reason = _check_command(text, cwd, settings, depth + 1)
        if reason:
            return reason, cwd

    for operand in operands:
        reason = _path_reason(operand, cwd, settings)
        if reason:
            return "{}: {}".format(command, reason), cwd

    walk_targets = operands
    if not operands and command in DEFAULT_TO_CWD:
        walk_targets = ["."]
    follows = command in FOLLOW_FLAGS and _has_flag(command, segment.args, FOLLOW_FLAGS[command])
    recursive = command in RECURSIVE_ALWAYS or (
        command in RECURSIVE_FLAGS and _has_flag(command, segment.args, RECURSIVE_FLAGS[command])
    )
    if command == "ls" and not recursive and not follows:
        walk_targets = []
    for target in walk_targets if (follows or recursive) else []:
        if any(c in GLOB_CHARS for c in target):
            continue  # already checked as a glob above
        if recursive or follows:
            if _is_ancestor_of_prefix(target, cwd, settings):
                return "{} would walk '{}', which contains a protected path.".format(
                    command, target), cwd
        if follows:
            found = _holds_protected_symlink(target, cwd, settings)
            if found is None:
                return ("{} follows symlinks under '{}', which is too large to check "
                        "(fail closed). Drop the symlink-following flag.").format(
                            command, target), cwd
            if found:
                return ("{} follows symlinks under '{}', and one leads to a protected path. "
                        "Drop the symlink-following flag.").format(command, target), cwd

    if command in ("cd", "pushd") and operands:
        target = os.path.expanduser(os.path.expandvars(operands[0]))
        cwd = os.path.normpath(os.path.join(cwd, target))
    elif command == "cd" and not operands:
        cwd = os.path.expanduser("~")
    return None, cwd


def _check_command(command, cwd, settings, depth=0):
    if depth > MAX_DEPTH:
        return "command nests too deeply to check (fail closed)."
    try:
        parsed = _shell.parse(command)
    except _shell.ShellParseError as exc:
        return "could not parse the command safely: {} (fail closed).".format(exc)

    for heredoc in parsed.heredocs:
        try:
            header = _shell.split_segments(
                _shell.extract_substitutions(_shell.strip_comments(heredoc.header))[0]
            )
        except _shell.ShellParseError:
            header = []
        if any(seg.command in _shell.SHELLS for seg in header):
            reason = _check_command(heredoc.body, cwd, settings, depth + 1)
            if reason:
                return "heredoc fed to a shell: " + reason

    for body in parsed.substitutions:
        reason = _check_command(body, cwd, settings, depth + 1)
        if reason:
            return "substitution: " + reason

    for segment in parsed.segments:
        reason, cwd = _check_segment(segment, cwd, settings, depth)
        if reason:
            return reason
    return None


def check(tool_name, tool_input, context):
    """Return a reason string to block the call, or None to allow it."""
    settings = context.settings
    cwd = context.cwd

    if tool_name == "Bash":
        command = tool_input.get("command")
        if not isinstance(command, str):
            return "Bash call has no command string (fail closed)."
        reason = _check_command(command, cwd, settings)
        if reason:
            return reason + _HINT
        return None

    base = cwd
    for key in PATH_KEYS:
        value = tool_input.get(key)
        if value is None:
            continue
        if not isinstance(value, str):
            return "tool_input.{} is not a string (fail closed).".format(key)
        reason = _path_reason(value, cwd, settings)
        if reason:
            return "{} {}{}".format(tool_name, reason, _HINT)
        if key == "path":
            base = os.path.join(cwd, os.path.expanduser(value))
    for key in LIST_KEYS:
        values = tool_input.get(key)
        if values is None:
            continue
        if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
            return "tool_input.{} is not a list of strings (fail closed).".format(key)
        for value in values:
            reason = _path_reason(value, cwd, settings)
            if reason:
                return "{} {}{}".format(tool_name, reason, _HINT)

    if tool_name == "Glob":
        pattern = tool_input.get("pattern")
        if not isinstance(pattern, str):
            return "Glob call has no pattern string (fail closed)."
        reason = _glob_reason(os.path.join(base, pattern), cwd, settings)
        if reason:
            return "Glob " + reason + _HINT

    if tool_name == "Grep":
        target = tool_input.get("path") or "."
        if _is_ancestor_of_prefix(target, cwd, settings):
            return "Grep would search '{}', which contains a protected path.{}".format(
                target, _HINT)
    return None


_HINT = (" This area is protected by agent-hook-guards. Mentioning the path in text is fine;"
         " reading, writing, or walking into it is not.")


def main():
    run(GUARD, prepare, check)


if __name__ == "__main__":
    main()
