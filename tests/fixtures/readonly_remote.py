"""Fixture for the readonly_remote case file.

The guard never touches the remote host, so the fixture only writes a config.
Host names are placeholders: example-cluster (an ssh alias) and any host
under cluster.example.
"""


def build(root):
    return {
        "readonly_remote": {
            "hosts": ["example-cluster", "*.cluster.example"],
            "extra_read_commands": ["squeue", "sinfo"],
            "forbidden_prefixes": ["/mnt/protected-share", "/srv/agent/archive"],
            "forbidden_names": ["SharedData"],
            "remote_home": "/srv/agent",
        }
    }


CWD = ""
