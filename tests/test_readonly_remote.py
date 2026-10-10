"""Unit tests for the read-only remote guard."""

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, REPO)

from agent_hook_guards import readonly_remote as rr  # noqa: E402
from agent_hook_guards._config import ConfigError  # noqa: E402
from agent_hook_guards._hook import Context  # noqa: E402


def _cfg(**section):
    base = {"hosts": ["example-cluster"]}
    base.update(section)
    return {"readonly_remote": base}


class PrepareTests(unittest.TestCase):
    def test_missing_section_is_an_error(self):
        with self.assertRaises(ConfigError):
            rr.prepare({"protected_prefixes": ["/mnt/protected-share"]})

    def test_empty_hosts_is_an_error(self):
        with self.assertRaises(ConfigError):
            rr.prepare({"readonly_remote": {"hosts": []}})

    def test_host_with_user_or_path_is_an_error(self):
        for host in ("agent@example-cluster", "example-cluster:/x", "*"):
            with self.assertRaises(ConfigError):
                rr.prepare(_cfg(hosts=[host]))

    def test_never_allowed_command_cannot_be_configured(self):
        for word in ("bash", "rm", "sed", "xargs"):
            with self.assertRaises(ConfigError):
                rr.prepare(_cfg(extra_read_commands=[word]))

    def test_relative_prefix_and_root_are_errors(self):
        for prefix in ("relative/dir", "/"):
            with self.assertRaises(ConfigError):
                rr.prepare(_cfg(forbidden_prefixes=[prefix]))

    def test_relative_home_is_an_error(self):
        with self.assertRaises(ConfigError):
            rr.prepare(_cfg(remote_home="home/agent"))

    def test_extra_commands_extend_the_allowlist(self):
        settings = rr.prepare(_cfg(extra_read_commands=["squeue"]))
        self.assertIn("squeue", settings.commands)
        self.assertIn("ls", settings.commands)


class CheckTests(unittest.TestCase):
    def setUp(self):
        self.settings = rr.prepare(_cfg(forbidden_prefixes=["/mnt/protected-share"],
                                        forbidden_names=["SharedData"]))

    def check(self, command, tool="Bash"):
        return rr.check(tool, {"command": command}, Context(self.settings, "/tmp", {}))

    def test_read_is_allowed_and_write_is_blocked(self):
        self.assertIsNone(self.check("ssh example-cluster ls /scratch"))
        self.assertIn("allowlist", self.check("ssh example-cluster rm /scratch/x"))

    def test_bare_ssh_is_blocked(self):
        self.assertIn("interactive", self.check("ssh example-cluster"))

    def test_other_tools_are_ignored(self):
        self.assertIsNone(rr.check("Read", {"file_path": "/x"}, Context(self.settings, "/", {})))

    def test_non_string_command_blocks(self):
        reason = rr.check("Bash", {"command": 3}, Context(self.settings, "/", {}))
        self.assertIn("fail closed", reason)

    def test_unknown_relative_walk_blocks_without_home(self):
        self.assertIn("remote_home", self.check("ssh example-cluster find . -name x"))

    def test_relative_walk_allowed_without_forbidden_prefixes(self):
        settings = rr.prepare(_cfg())
        reason = rr.check("Bash", {"command": "ssh example-cluster find . -name x"},
                          Context(settings, "/", {}))
        self.assertIsNone(reason)

    def test_parse_ssh_reads_options_after_host(self):
        call = rr._parse_ssh(["-p", "22", "example-cluster", "-v", "ls", "-l"])
        self.assertEqual(call.host, "example-cluster")
        self.assertEqual(call.remote, "ls -l")
        self.assertIsNone(call.refused)

    def test_address_host(self):
        self.assertEqual(rr._address_host("agent@example-cluster:/x", False), "example-cluster")
        self.assertEqual(rr._address_host("rsync://example-cluster/m", False), "example-cluster")
        self.assertIsNone(rr._address_host("./local:file", False))
        self.assertIsNone(rr._address_host("example-cluster", False))
        self.assertEqual(rr._address_host("example-cluster", True), "example-cluster")


if __name__ == "__main__":
    unittest.main()
