"""Shared PreToolUse hook runtime.

A guard supplies two callables:

* ``prepare(cfg)`` validates the raw config dict and returns whatever the
  guard needs. It raises ConfigError on a bad config.
* ``check(tool_name, tool_input, context)`` returns None to allow, or a
  reason string to block. ``context`` holds the prepared config and the
  working directory of the call.

``run`` turns the result into an exit code. 0 allows. 2 blocks, with the
reason on stderr. Any error at all also exits 2 (fail closed).
"""

import json
import os
import sys

from ._config import ConfigError, load_config

ALLOW = 0
BLOCK = 2


class Context(object):
    """What a guard's check() needs besides the tool call itself."""

    def __init__(self, settings, cwd, payload):
        self.settings = settings
        self.cwd = cwd
        self.payload = payload


def _block(guard_name, reason, stream):
    stream.write("[{}] BLOCKED: {}\n".format(guard_name, reason))
    return BLOCK


def evaluate(guard_name, prepare, check, raw, stream=None):
    """Evaluate one raw stdin string. Return the exit code. Never raises."""
    if stream is None:
        stream = sys.stderr
    try:
        if not raw or not raw.strip():
            return _block(guard_name, "empty hook input (fail closed).", stream)
        try:
            payload = json.loads(raw)
        except ValueError:
            return _block(guard_name, "hook input is not valid JSON (fail closed).", stream)
        if not isinstance(payload, dict):
            return _block(guard_name, "hook input is not a JSON object (fail closed).", stream)

        event = payload.get("hook_event_name", "PreToolUse")
        if event != "PreToolUse":
            return ALLOW

        tool_name = payload.get("tool_name")
        if not isinstance(tool_name, str) or not tool_name:
            return _block(guard_name, "hook input has no tool_name (fail closed).", stream)
        tool_input = payload.get("tool_input", {})
        if not isinstance(tool_input, dict):
            return _block(guard_name, "tool_input is not an object (fail closed).", stream)

        try:
            settings = prepare(load_config())
        except ConfigError as exc:
            return _block(
                guard_name,
                "configuration problem: {}. Every call is refused until the config is fixed "
                "(fail closed).".format(exc),
                stream,
            )

        cwd = payload.get("cwd")
        if not isinstance(cwd, str) or not cwd:
            cwd = os.getcwd()

        reason = check(tool_name, tool_input, Context(settings, cwd, payload))
        if reason:
            return _block(guard_name, reason, stream)
        return ALLOW
    except Exception as exc:  # noqa: BLE001 - any failure must block
        try:
            return _block(
                guard_name,
                "internal error {}: {} (fail closed).".format(type(exc).__name__, exc),
                stream,
            )
        except Exception:  # noqa: BLE001
            return BLOCK


def run(guard_name, prepare, check):
    """Entry point for ``python3 -m agent_hook_guards.<guard>``."""
    try:
        raw = sys.stdin.read()
    except Exception:  # noqa: BLE001
        raw = ""
    code = evaluate(guard_name, prepare, check, raw)
    sys.stderr.flush()
    sys.exit(code)
