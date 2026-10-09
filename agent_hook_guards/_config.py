"""Find, load, and validate the JSON config file.

The file is found at $AGENT_GUARDS_CONFIG, else
~/.config/agent-hook-guards/config.json. Any problem raises ConfigError, and
the hook runtime turns that into a block (fail closed).
"""

import json
import os

ENV_VAR = "AGENT_GUARDS_CONFIG"
DEFAULT_PATH = os.path.join("~", ".config", "agent-hook-guards", "config.json")


class ConfigError(Exception):
    """The config is missing, unreadable, or invalid."""


def config_path():
    """Return the config path that would be used, with ~ expanded."""
    value = os.environ.get(ENV_VAR)
    if value is not None:
        if not value.strip():
            raise ConfigError("{} is set but empty".format(ENV_VAR))
        return os.path.expanduser(value)
    return os.path.expanduser(DEFAULT_PATH)


def load_config(path=None):
    """Load the config file as a dict. Raise ConfigError on any problem."""
    if path is None:
        path = config_path()
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except FileNotFoundError:
        raise ConfigError("config file not found: {}".format(path))
    except (OSError, UnicodeDecodeError) as exc:
        raise ConfigError("config file unreadable: {} ({})".format(path, exc))
    except ValueError as exc:
        raise ConfigError("config file is not valid JSON: {} ({})".format(path, exc))
    if not isinstance(data, dict):
        raise ConfigError("config file must hold a JSON object: {}".format(path))
    return data


def string_list(cfg, key, required=False):
    """Return cfg[key] as a list of non-empty strings, or raise ConfigError."""
    if key not in cfg:
        if required:
            raise ConfigError("config key '{}' is required".format(key))
        return []
    value = cfg[key]
    if not isinstance(value, list):
        raise ConfigError("config key '{}' must be a list of strings".format(key))
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise ConfigError("config key '{}' must hold only non-empty strings".format(key))
    return list(value)
