"""Central configuration loader with environment-variable expansion.

Deployment-specific values (inference endpoints, log paths, API credentials)
must never be baked into the committed configuration: this repository may be
public, and hardcoding a private IP or a secret would leak it. Instead,
``config/app_config.json`` uses ``${VAR:-default}`` placeholders that are
resolved at load time from the process environment, falling back to a safe
local-development default when the variable is unset.

This keeps real infrastructure addresses and secrets out of the repo while the
defaults still let the pipeline run out-of-the-box in local simulation. Set the
real values via environment variables (shell ``export``, a gitignored ``.env``
sourced into the shell, or a systemd ``EnvironmentFile=``); see ``.env.example``.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Dict

# Matches ${VAR} and ${VAR:-default}. The default may be empty (``${VAR:-}``),
# which resolves to an empty string when the variable is unset.
_ENV_PLACEHOLDER = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


def _expand(value: Any) -> Any:
    """Recursively resolve ``${VAR:-default}`` placeholders in every string leaf."""
    if isinstance(value, str):
        def _sub(match: "re.Match[str]") -> str:
            var_name, default = match.group(1), match.group(2)
            env_value = os.environ.get(var_name)
            if env_value is not None:
                return env_value
            if default is not None:
                return default
            # Unknown variable with no default: leave the placeholder intact so
            # the misconfiguration surfaces loudly instead of silently emptying.
            return match.group(0)

        return _ENV_PLACEHOLDER.sub(_sub, value)
    if isinstance(value, dict):
        return {key: _expand(val) for key, val in value.items()}
    if isinstance(value, list):
        return [_expand(item) for item in value]
    return value


def load_config(config_path: str | os.PathLike[str]) -> Dict[str, Any]:
    """Load a JSON config file and resolve ``${VAR:-default}`` placeholders.

    Args:
        config_path: Path to the JSON configuration file.

    Returns:
        The parsed configuration with every environment placeholder expanded.

    Raises:
        FileNotFoundError: if the configuration file does not exist.
    """
    path = Path(config_path)
    if not path.is_file():
        raise FileNotFoundError(f"Configuration file not found: {path.resolve()}")
    with path.open("r", encoding="utf-8") as handle:
        raw = json.load(handle)
    return _expand(raw)
