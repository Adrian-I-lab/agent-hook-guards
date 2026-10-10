"""A small, conservative shell tokeniser for guards.

It does not try to be a full shell parser. It does enough to find what a
command will touch:

* heredoc bodies are separated from the command (the header line is kept);
* comments are removed;
* ``$(...)``, backtick, and process substitutions are pulled out so each can
  be checked as its own command;
* the rest is split into segments on ``;``, ``&&``, ``||``, ``|``, ``&``,
  parentheses, and newlines;
* each segment yields its real command word (past ``VAR=x`` assignments and
  wrappers such as ``env``, ``nice``, ``timeout``, and ``sudo``), its
  arguments, and its redirect targets.

Anything that cannot be tokenised raises ShellParseError. Guards treat that
as a block (fail closed).
"""

import os
import re
import shlex

SUBST_PLACEHOLDER = "__agent_hook_guards_substitution__"

_PUNCT = "();<>|&\n"
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\+?=")
_HEREDOC = re.compile(r"(?<!<)<<(-?)[ \t]*(?:'([^'\n]*)'|\"([^\"\n]*)\"|\\?([A-Za-z0-9_.-]+))")

SHELLS = frozenset(["sh", "bash", "zsh", "dash", "ksh", "fish"])

# Wrapper commands and the options of each that take a separate value.
_WRAPPERS = {
    "env": frozenset(["-u", "--unset", "-C", "--chdir", "-S", "--split-string"]),
    "command": frozenset(),
    "builtin": frozenset(),
    "exec": frozenset(["-a"]),
    "nice": frozenset(["-n", "--adjustment"]),
    "nohup": frozenset(),
    "time": frozenset(["-f", "--format", "-o", "--output"]),
    "timeout": frozenset(["-s", "--signal", "-k", "--kill-after"]),
    "stdbuf": frozenset(["-i", "-o", "-e"]),
    "setsid": frozenset(),
    "ionice": frozenset(["-c", "-n", "-p"]),
    "sudo": frozenset(["-u", "-g", "-h", "-p", "-C", "-D", "-r", "-t", "-U", "-T"]),
    "doas": frozenset(["-u", "-C"]),
    "xargs": frozenset(["-I", "-i", "-n", "-L", "-l", "-P", "-d", "-E", "-e", "-s", "-a"]),
}
# Wrappers whose first positional argument is a value, not the command.
_WRAPPER_POSITIONAL = {"timeout": 1}


class ShellParseError(Exception):
    """The command could not be tokenised safely."""


class Heredoc(object):
    """A heredoc body together with the line that introduced it."""

    def __init__(self, header, body):
        self.header = header
        self.body = body


class Segment(object):
    """One simple command."""

    def __init__(self, command, args, redirects, wrappers, assignments=None):
        self.command = command  # basename of the real command word, or None
        self.args = args  # list of argument strings after the command word
        self.redirects = redirects  # list of (operator, target) pairs
        self.wrappers = wrappers  # wrapper command names that were skipped
        # VAR=value words before the command word, including those after env
        self.assignments = assignments if assignments is not None else []

    def __repr__(self):
        return "Segment(command={!r}, args={!r}, redirects={!r})".format(
            self.command, self.args, self.redirects
        )


def strip_heredocs(command):
    """Return (command_without_bodies, [Heredoc, ...]).

    The header line of each heredoc is kept, because its redirect targets and
    command word still matter. Only the body is removed.
    """
    lines = command.split("\n")
    kept = []
    heredocs = []
    i = 0
    while i < len(lines):
        line = lines[i]
        kept.append(line)
        i += 1
        pending = []
        for match in _HEREDOC.finditer(line):
            delim = match.group(2)
            if delim is None:
                delim = match.group(3)
            if delim is None:
                delim = match.group(4)
            pending.append((match.group(1) == "-", delim))
        for strip_tabs, delim in pending:
            body = []
            closed = False
            while i < len(lines):
                candidate = lines[i]
                i += 1
                check = candidate.lstrip("\t") if strip_tabs else candidate
                if check == delim:
                    closed = True
                    break
                body.append(candidate)
            heredocs.append(Heredoc(line, "\n".join(body)))
            if not closed:
                break
    return "\n".join(kept), heredocs


def strip_comments(command):
    """Remove shell comments, respecting quotes and backslash escapes."""
    out = []
    i = 0
    n = len(command)
    quote = None
    while i < n:
        ch = command[i]
        if quote == "'":
            out.append(ch)
            if ch == "'":
                quote = None
            i += 1
            continue
        if ch == "\\" and i + 1 < n:
            out.append(command[i:i + 2])
            i += 2
            continue
        if quote == '"':
            out.append(ch)
            if ch == '"':
                quote = None
            i += 1
            continue
        if ch in ("'", '"'):
            quote = ch
            out.append(ch)
            i += 1
            continue
        if ch == "#" and (i == 0 or command[i - 1] in " \t\n;&|()"):
            while i < n and command[i] != "\n":
                i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _matching_paren(text, start):
    """Index of the ')' that closes the '(' at text[start - 1]."""
    depth = 1
    i = start
    quote = None
    n = len(text)
    while i < n:
        ch = text[i]
        if quote == "'":
            if ch == "'":
                quote = None
        elif ch == "\\":
            i += 1
        elif quote == '"':
            if ch == '"':
                quote = None
        elif ch in ("'", '"'):
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    raise ShellParseError("unbalanced parentheses in substitution")


def extract_substitutions(command):
    """Return (command_with_placeholders, [inner command, ...]).

    Handles $(...), backticks, <(...), and >(...). Single-quoted text is left
    alone, because the shell does not expand it.
    """
    out = []
    bodies = []
    i = 0
    n = len(command)
    quote = None
    while i < n:
        ch = command[i]
        if quote == "'":
            out.append(ch)
            if ch == "'":
                quote = None
            i += 1
            continue
        if ch == "\\" and i + 1 < n:
            out.append(command[i:i + 2])
            i += 2
            continue
        if ch == "'" and quote is None:
            quote = "'"
            out.append(ch)
            i += 1
            continue
        if ch == '"':
            quote = None if quote == '"' else '"'
            out.append(ch)
            i += 1
            continue
        opener = command[i:i + 2]
        if opener in ("$(", "<(", ">(") and not (opener != "$(" and quote == '"'):
            end = _matching_paren(command, i + 2)
            inner = command[i + 2:end]
            if opener == "$(" and inner.startswith("(") and inner.endswith(")"):
                inner = inner[1:-1]  # arithmetic $((...)), checked as a command
            bodies.append(inner)
            if opener != "$(":
                out.append(opener[0] + " ")
            out.append(SUBST_PLACEHOLDER)
            i = end + 1
            continue
        if ch == "`":
            end = command.find("`", i + 1)
            if end < 0:
                raise ShellParseError("unterminated backtick substitution")
            bodies.append(command[i + 1:end])
            out.append(SUBST_PLACEHOLDER)
            i = end + 1
            continue
        out.append(ch)
        i += 1
    if quote is not None:
        raise ShellParseError("unterminated quote")
    return "".join(out), bodies


def tokenise(command):
    """Split into shell words and operator tokens. Newlines become ';'."""
    command = command.replace("\\\n", "")
    lexer = shlex.shlex(command, posix=True, punctuation_chars=_PUNCT)
    lexer.whitespace = " \t\r"
    lexer.whitespace_split = True
    lexer.commenters = ""
    try:
        return list(lexer)
    except ValueError as exc:
        raise ShellParseError(str(exc))


def _is_operator(token):
    return token != "" and all(c in _PUNCT for c in token)


def _skip_wrapper(name, words, i):
    """Return the index of the first word after wrapper `name` and its options."""
    takes_value = _WRAPPERS[name]
    positional = _WRAPPER_POSITIONAL.get(name, 0)
    while i < len(words):
        word = words[i]
        if word == "--":
            i += 1
            break
        if word.startswith("-") and len(word) > 1:
            base = word.split("=", 1)[0]
            i += 1
            if base in takes_value and "=" not in word:
                i += 1
            elif name == "nice" and word[1:].isdigit():
                pass
            continue
        if name == "env" and _ASSIGNMENT.match(word):
            i += 1
            continue
        if positional:
            positional -= 1
            i += 1
            continue
        break
    return i


def _parse_simple(tokens):
    words = []
    redirects = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if _is_operator(tok) and ("<" in tok or ">" in tok):
            target = tokens[i + 1] if i + 1 < len(tokens) else None
            if target is None or _is_operator(target):
                raise ShellParseError("redirect without a target")
            if tok in ("<<", "<<-", "<<<"):
                pass  # heredoc delimiter or here-string text, not a file
            elif tok in (">&", "<&") and (target.isdigit() or target == "-"):
                pass  # file descriptor duplication
            else:
                redirects.append((tok, target))
            # Drop a preceding file descriptor number such as the 2 in 2>file.
            if words and words[-1].isdigit() and i > 0 and tokens[i - 1] == words[-1]:
                words.pop()
            i += 2
            continue
        words.append(tok)
        i += 1

    wrappers = []
    assignments = []
    j = 0
    while j < len(words) and (_ASSIGNMENT.match(words[j]) or words[j] in ("{", "}", "!")):
        if _ASSIGNMENT.match(words[j]):
            assignments.append(words[j])
        j += 1
    while j < len(words):
        name = os.path.basename(words[j])
        if name in _WRAPPERS:
            wrappers.append(name)
            start = j + 1
            j = _skip_wrapper(name, words, start)
            if name == "env":
                assignments.extend(w for w in words[start:j] if _ASSIGNMENT.match(w))
            while j < len(words) and _ASSIGNMENT.match(words[j]):
                assignments.append(words[j])
                j += 1
            continue
        break
    if j >= len(words):
        return Segment(None, [], redirects, wrappers, assignments)
    return Segment(os.path.basename(words[j]), words[j + 1:], redirects, wrappers, assignments)


def split_segments(command):
    """Tokenise an already-stripped command into a list of Segment objects."""
    segments = []
    current = []
    for tok in tokenise(command):
        if _is_operator(tok) and "<" not in tok and ">" not in tok:
            if current:
                segments.append(_parse_simple(current))
                current = []
            continue
        current.append(tok)
    if current:
        segments.append(_parse_simple(current))
    return segments


class ParsedCommand(object):
    """The full result of parsing one Bash command string."""

    def __init__(self, segments, substitutions, heredocs):
        self.segments = segments
        self.substitutions = substitutions  # inner command strings
        self.heredocs = heredocs  # Heredoc objects


def parse(command):
    """Parse a Bash command string. Raises ShellParseError if unsafe to read."""
    if not isinstance(command, str):
        raise ShellParseError("command is not a string")
    stripped, heredocs = strip_heredocs(command)
    stripped = strip_comments(stripped)
    stripped, substitutions = extract_substitutions(stripped)
    return ParsedCommand(split_segments(stripped), substitutions, heredocs)
