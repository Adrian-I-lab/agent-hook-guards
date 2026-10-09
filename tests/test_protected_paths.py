"""Unit tests for the protected-paths guard."""

import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, REPO)
sys.path.insert(0, HERE)

from agent_hook_guards import protected_paths as pp  # noqa: E402
from agent_hook_guards._config import ConfigError  # noqa: E402
from agent_hook_guards._hook import Context  # noqa: E402
import run_cases  # noqa: E402


class PrepareTests(unittest.TestCase):
    def test_both_lists_empty_is_an_error(self):
        with self.assertRaises(ConfigError):
            pp.prepare({})
        with self.assertRaises(ConfigError):
            pp.prepare({"protected_prefixes": [], "protected_names": []})

    def test_relative_prefix_is_an_error(self):
        with self.assertRaises(ConfigError):
            pp.prepare({"protected_prefixes": ["relative/dir"]})

    def test_root_prefix_is_an_error(self):
        with self.assertRaises(ConfigError):
            pp.prepare({"protected_prefixes": ["/"]})

    def test_name_with_separator_is_an_error(self):
        with self.assertRaises(ConfigError):
            pp.prepare({"protected_names": ["a/b"]})

    def test_wrong_types_are_errors(self):
        for cfg in ({"protected_prefixes": "/mnt/protected-share"},
                    {"protected_names": [3]}):
            with self.assertRaises(ConfigError):
                pp.prepare(cfg)

    def test_tilde_prefix_is_expanded(self):
        settings = pp.prepare({"protected_prefixes": ["~/protected-share"]})
        self.assertTrue(os.path.isabs(settings.prefixes[0][0]))


class CheckTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = os.path.realpath(self.tmp.name)
        sys.path.insert(0, os.path.join(HERE, "fixtures"))
        import protected_paths as fixture  # the fixture module, not the guard
        sys.path.pop(0)
        self.settings = pp.prepare(fixture.build(self.root))
        self.cwd = os.path.join(self.root, "work")

    def tearDown(self):
        self.tmp.cleanup()

    def check(self, tool, **tool_input):
        return pp.check(tool, tool_input, Context(self.settings, self.cwd, {}))

    def test_bash_without_command_blocks(self):
        self.assertTrue(self.check("Bash"))
        self.assertTrue(self.check("Bash", command=["ls"]))

    def test_non_string_path_blocks(self):
        self.assertTrue(self.check("Read", file_path=7))

    def test_list_of_paths_is_checked(self):
        inside = os.path.join(self.root, "protected-share", "secret.txt")
        self.assertTrue(self.check("SomeTool", paths=["notes.txt", inside]))
        self.assertIsNone(self.check("SomeTool", paths=["notes.txt"]))

    def test_unknown_tool_without_paths_is_allowed(self):
        self.assertIsNone(self.check("WebSearch", query="SharedData"))

    def test_reason_mentions_the_operand(self):
        reason = self.check("Bash", command="cat ../protected-share/secret.txt")
        self.assertIn("../protected-share/secret.txt", reason)

    def test_deep_nesting_fails_closed(self):
        depth = pp.MAX_DEPTH + 3
        command = "echo " + "$(" * depth + "x" + ")" * depth
        self.assertIn("nests too deeply", self.check("Bash", command=command))


class CaseFileTests(unittest.TestCase):
    def test_case_file_has_no_mismatches(self):
        case_file = os.path.join(HERE, "cases", "protected_paths.jsonl")
        counts = run_cases.run_cases("protected_paths", case_file, verbose=True)
        self.assertGreaterEqual(counts["blocked_ok"], 15)
        self.assertGreaterEqual(counts["allowed_ok"], 15)
        self.assertEqual(counts["mismatches"], 0)


if __name__ == "__main__":
    unittest.main()
