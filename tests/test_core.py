"""Unit tests for the shared runtime, config loader, and tokeniser."""

import io
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, REPO)

from agent_hook_guards import _config, _hook, _shell  # noqa: E402


def _allow_all(tool_name, tool_input, context):
    return None


def _block_all(tool_name, tool_input, context):
    return "blocked for the test"


def _explode(tool_name, tool_input, context):
    raise RuntimeError("boom")


def _prepare(cfg):
    return cfg


class ConfigEnv(object):
    """Point AGENT_GUARDS_CONFIG at a temp file holding `text`, or at nothing."""

    def __init__(self, text=None):
        self.text = text

    def __enter__(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old = os.environ.get(_config.ENV_VAR)
        path = os.path.join(self.tmp.name, "config.json")
        if self.text is not None:
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(self.text)
        os.environ[_config.ENV_VAR] = path
        return path

    def __exit__(self, *exc):
        if self.old is None:
            os.environ.pop(_config.ENV_VAR, None)
        else:
            os.environ[_config.ENV_VAR] = self.old
        self.tmp.cleanup()


def _payload(**extra):
    data = {"hook_event_name": "PreToolUse", "tool_name": "Read",
            "tool_input": {"file_path": "x"}}
    data.update(extra)
    return json.dumps(data)


class HookRuntimeTests(unittest.TestCase):
    def evaluate(self, raw, check=_allow_all, prepare=_prepare):
        stream = io.StringIO()
        code = _hook.evaluate("test", prepare, check, raw, stream)
        return code, stream.getvalue()

    def test_allow_exits_0(self):
        with ConfigEnv("{}"):
            self.assertEqual(self.evaluate(_payload())[0], 0)

    def test_block_exits_2_with_reason(self):
        with ConfigEnv("{}"):
            code, err = self.evaluate(_payload(), check=_block_all)
        self.assertEqual(code, 2)
        self.assertIn("blocked for the test", err)

    def test_bad_json_blocks(self):
        with ConfigEnv("{}"):
            self.assertEqual(self.evaluate("not json")[0], 2)

    def test_empty_stdin_blocks(self):
        with ConfigEnv("{}"):
            self.assertEqual(self.evaluate("")[0], 2)
            self.assertEqual(self.evaluate("   \n")[0], 2)

    def test_non_object_json_blocks(self):
        with ConfigEnv("{}"):
            self.assertEqual(self.evaluate("[1, 2]")[0], 2)

    def test_tool_input_not_object_blocks(self):
        with ConfigEnv("{}"):
            self.assertEqual(self.evaluate(_payload(tool_input="cat x"))[0], 2)

    def test_missing_tool_name_blocks(self):
        with ConfigEnv("{}"):
            raw = json.dumps({"hook_event_name": "PreToolUse", "tool_input": {}})
            self.assertEqual(self.evaluate(raw)[0], 2)

    def test_missing_config_blocks(self):
        with ConfigEnv(None):
            code, err = self.evaluate(_payload())
        self.assertEqual(code, 2)
        self.assertIn("not found", err)

    def test_invalid_config_json_blocks(self):
        with ConfigEnv("{not json"):
            self.assertEqual(self.evaluate(_payload())[0], 2)

    def test_config_not_object_blocks(self):
        with ConfigEnv("[]"):
            self.assertEqual(self.evaluate(_payload())[0], 2)

    def test_empty_config_env_var_blocks(self):
        old = os.environ.get(_config.ENV_VAR)
        os.environ[_config.ENV_VAR] = "  "
        try:
            self.assertEqual(self.evaluate(_payload())[0], 2)
        finally:
            if old is None:
                os.environ.pop(_config.ENV_VAR, None)
            else:
                os.environ[_config.ENV_VAR] = old

    def test_exception_in_check_blocks(self):
        with ConfigEnv("{}"):
            code, err = self.evaluate(_payload(), check=_explode)
        self.assertEqual(code, 2)
        self.assertIn("internal error", err)

    def test_other_events_are_ignored(self):
        with ConfigEnv(None):
            raw = _payload(hook_event_name="PostToolUse")
            self.assertEqual(self.evaluate(raw, check=_block_all)[0], 0)

    def test_string_list_validation(self):
        self.assertEqual(_config.string_list({"k": ["a"]}, "k"), ["a"])
        self.assertEqual(_config.string_list({}, "k"), [])
        for bad in ("a", [1], [""], {"a": 1}):
            with self.assertRaises(_config.ConfigError):
                _config.string_list({"k": bad}, "k")
        with self.assertRaises(_config.ConfigError):
            _config.string_list({}, "k", required=True)


class ModuleEntryPointTests(unittest.TestCase):
    """Run the real guard module as a subprocess, as Claude Code would."""

    def run_module(self, stdin, config_text):
        with tempfile.TemporaryDirectory() as tmp:
            env = dict(os.environ)
            env["PYTHONPATH"] = REPO
            path = os.path.join(tmp, "config.json")
            if config_text is not None:
                with open(path, "w", encoding="utf-8") as handle:
                    handle.write(config_text)
            env[_config.ENV_VAR] = path
            proc = subprocess.run(
                [sys.executable, "-m", "agent_hook_guards.protected_paths"],
                input=stdin, env=env, cwd=tmp,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
            )
            return proc.returncode

    def test_broken_payload_exits_2(self):
        self.assertEqual(self.run_module("not json", '{"protected_names": ["x"]}'), 2)

    def test_missing_config_exits_2(self):
        self.assertEqual(self.run_module(_payload(), None), 2)

    def test_clean_call_exits_0(self):
        self.assertEqual(self.run_module(_payload(), '{"protected_names": ["elsewhere"]}'), 0)


class ShellTests(unittest.TestCase):
    def segments(self, command):
        return _shell.parse(command).segments

    def test_heredoc_body_removed_header_kept(self):
        parsed = _shell.parse("cat > out.md <<'EOF'\nsecret words\nEOF\nls")
        self.assertEqual([s.command for s in parsed.segments], ["cat", "ls"])
        self.assertEqual(parsed.segments[0].redirects, [(">", "out.md")])
        self.assertEqual(parsed.heredocs[0].body, "secret words")

    def test_heredoc_dash_strips_tabs(self):
        parsed = _shell.parse("cat <<-END\n\tbody\n\tEND\necho done")
        self.assertEqual([s.command for s in parsed.segments], ["cat", "echo"])
        self.assertEqual(parsed.heredocs[0].body, "\tbody")

    def test_here_string_is_not_a_heredoc(self):
        parsed = _shell.parse("grep x <<< 'a b'")
        self.assertEqual(parsed.heredocs, [])
        self.assertEqual(parsed.segments[0].redirects, [])

    def test_comments_removed_but_not_in_quotes(self):
        self.assertEqual(self.segments("ls # cat x")[0].args, [])
        self.assertEqual(self.segments("echo 'a # b'")[0].args, ["a # b"])
        self.assertEqual(self.segments("echo a#b")[0].args, ["a#b"])

    def test_comment_does_not_swallow_next_line(self):
        segs = self.segments("ls # note\ncat y")
        self.assertEqual([s.command for s in segs], ["ls", "cat"])

    def test_split_on_operators(self):
        segs = self.segments("a 1; b 2 && c 3 || d 4 | e 5 & f 6")
        self.assertEqual([s.command for s in segs], ["a", "b", "c", "d", "e", "f"])

    def test_wrappers_and_assignments_skipped(self):
        seg = self.segments("A=1 B=2 env -u C nice -n 5 timeout -s KILL 10 sudo -u x cat f")[0]
        self.assertEqual(seg.command, "cat")
        self.assertEqual(seg.args, ["f"])
        self.assertEqual(seg.wrappers, ["env", "nice", "timeout", "sudo"])

    def test_command_word_is_basename(self):
        self.assertEqual(self.segments("/bin/cat f")[0].command, "cat")

    def test_redirect_targets(self):
        seg = self.segments("cmd <in.txt >out.txt 2>err.txt >>log.txt &>all.txt 2>&1")[0]
        self.assertEqual(seg.redirects, [("<", "in.txt"), (">", "out.txt"), (">", "err.txt"),
                                         (">>", "log.txt"), ("&>", "all.txt")])
        self.assertEqual(seg.args, [])

    def test_substitutions_extracted(self):
        parsed = _shell.parse('wc "$(cat a)" `ls b` <(sort c)')
        self.assertEqual(parsed.substitutions, ["cat a", "ls b", "sort c"])

    def test_single_quoted_substitution_is_text(self):
        parsed = _shell.parse("echo '$(cat a)'")
        self.assertEqual(parsed.substitutions, [])

    def test_nested_substitution(self):
        parsed = _shell.parse("echo $(dirname $(pwd))")
        self.assertEqual(parsed.substitutions, ["dirname $(pwd)"])

    def test_line_continuation(self):
        seg = self.segments("cat \\\n  file")[0]
        self.assertEqual(seg.args, ["file"])

    def test_unterminated_quote_raises(self):
        with self.assertRaises(_shell.ShellParseError):
            _shell.parse("echo 'oops")

    def test_unbalanced_substitution_raises(self):
        with self.assertRaises(_shell.ShellParseError):
            _shell.parse("echo $(cat a")

    def test_redirect_without_target_raises(self):
        with self.assertRaises(_shell.ShellParseError):
            _shell.parse("echo >")

    def test_non_string_raises(self):
        with self.assertRaises(_shell.ShellParseError):
            _shell.parse(None)


if __name__ == "__main__":
    unittest.main()
