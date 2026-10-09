"""The shipped examples must parse, and the settings wrapper must fail closed."""

import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, REPO)

PLACEHOLDER = "/opt/agent-hook-guards"


def _load(name):
    with open(os.path.join(REPO, "examples", name), "r", encoding="utf-8") as handle:
        return json.load(handle)


class ExampleTests(unittest.TestCase):
    def test_config_example_is_valid(self):
        from agent_hook_guards import protected_paths
        settings = protected_paths.prepare(_load("config.example.json"))
        self.assertTrue(settings.prefixes)
        self.assertTrue(settings.names)

    def wrapper(self, install_dir):
        hook = _load("settings.example.json")["hooks"]["PreToolUse"][0]
        self.assertEqual(hook["matcher"], "*")
        command = hook["hooks"][0]["command"]
        self.assertEqual(hook["hooks"][0]["type"], "command")
        self.assertIn(PLACEHOLDER, command)
        return command.replace(PLACEHOLDER, install_dir)

    def run_wrapper(self, install_dir, payload, config):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "config.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(config, handle)
            env = dict(os.environ)
            env["AGENT_GUARDS_CONFIG"] = path
            proc = subprocess.run(
                ["sh", "-c", self.wrapper(install_dir)], input=json.dumps(payload), env=env,
                cwd=tmp, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
            )
            return proc.returncode

    def test_wrapper_allows_blocks_and_fails_closed(self):
        config = {"protected_prefixes": ["/mnt/protected-share"]}
        safe = {"hook_event_name": "PreToolUse", "tool_name": "Read",
                "tool_input": {"file_path": "/tmp/notes.txt"}}
        bad = {"hook_event_name": "PreToolUse", "tool_name": "Read",
               "tool_input": {"file_path": "/mnt/protected-share/a.txt"}}
        self.assertEqual(self.run_wrapper(REPO, safe, config), 0)
        self.assertEqual(self.run_wrapper(REPO, bad, config), 2)
        self.assertEqual(self.run_wrapper("/nonexistent/agent-hook-guards", safe, config), 2)


if __name__ == "__main__":
    unittest.main()
