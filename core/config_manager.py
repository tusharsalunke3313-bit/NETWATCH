"""
NETWATCH configuration management.
"""

import json
from pathlib import Path
from typing import Any


class ConfigManager:
    """
    Loads and provides access to NETWATCH configuration.
    """

    def __init__(self, config_path: str | Path):
        self.config_path = Path(config_path)
        self._config: dict[str, Any] = {}

    def load(self) -> dict[str, Any]:
        """
        Load configuration from the JSON configuration file.
        """

        if not self.config_path.exists():
            raise FileNotFoundError(
                f"Configuration file not found: {self.config_path}"
            )

        try:
            with self.config_path.open(
                "r",
                encoding="utf-8",
            ) as config_file:
                self._config = json.load(config_file)

        except json.JSONDecodeError as exc:
            raise ValueError(
                f"Invalid JSON configuration: {self.config_path}"
            ) from exc

        return self._config

    def get(
        self,
        key: str,
        default: Any = None,
    ) -> Any:
        """
        Get a top-level configuration value.
        """

        return self._config.get(key, default)

    @property
    def config(self) -> dict[str, Any]:
        """Return the currently loaded configuration."""

        return self._config.copy()