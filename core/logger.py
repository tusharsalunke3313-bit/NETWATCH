"""
NETWATCH logging configuration.
"""

import logging
from pathlib import Path


def setup_logger(
    name: str = "netwatch",
    log_level: int = logging.INFO,
) -> logging.Logger:
    """
    Create and configure the NETWATCH application logger.
    """

    logger = logging.getLogger(name)

    if logger.handlers:
        return logger

    logger.setLevel(log_level)

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    console_handler.setFormatter(formatter)

    logger.addHandler(console_handler)

    logs_directory = Path("logs")
    logs_directory.mkdir(exist_ok=True)

    file_handler = logging.FileHandler(
        logs_directory / "netwatch.log",
        encoding="utf-8",
    )

    file_handler.setLevel(log_level)
    file_handler.setFormatter(formatter)

    logger.addHandler(file_handler)

    logger.propagate = False

    return logger