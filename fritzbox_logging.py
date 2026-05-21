from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import re
from typing import Any


LOGGER_NAME = "fritzforensic"
DEFAULT_LOG_FILE = Path("logs") / "fritzforensic.log"
DEFAULT_LOG_LEVEL = "INFO"
DEFAULT_MAX_BYTES = 5_000_000
DEFAULT_BACKUP_COUNT = 5
SECRET_PATTERNS = (
    re.compile(r"(?i)(sid=)[0-9a-f]{16}"),
    re.compile(r"(?i)((?:password|passwd|pass|pwd|secret|token|key)=)[^&\\s]+"),
    re.compile(r"(?i)(FRITZBOX_(?:PASSWORD|ADMIN_PASS|API_TOKEN)=)\\S+"),
)

_CONFIGURED = False


class RedactingFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return redact(super().format(record))


def get_logger(name: str) -> logging.Logger:
    configure_logging()
    return logging.getLogger(f"{LOGGER_NAME}.{name}")


def configure_logging(force: bool = False) -> None:
    global _CONFIGURED
    if _CONFIGURED and not force:
        return

    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(log_level())
    logger.propagate = False
    if force:
        for handler in list(logger.handlers):
            logger.removeHandler(handler)
            handler.close()
    if not logger.handlers:
        log_path = Path(os.getenv("FRITZBOX_LOG_FILE") or DEFAULT_LOG_FILE)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        handler = RotatingFileHandler(
            log_path,
            maxBytes=log_max_bytes(),
            backupCount=log_backup_count(),
            encoding="utf-8",
        )
        handler.setLevel(log_level())
        handler.setFormatter(
            RedactingFormatter(
                "%(asctime)s %(levelname)s %(name)s [%(process)d:%(threadName)s] %(message)s"
            )
        )
        logger.addHandler(handler)
    _CONFIGURED = True


def log_level() -> int:
    level_name = (os.getenv("FRITZBOX_LOG_LEVEL") or DEFAULT_LOG_LEVEL).upper()
    return getattr(logging, level_name, logging.INFO)


def log_max_bytes() -> int:
    try:
        return max(100_000, int(os.getenv("FRITZBOX_LOG_MAX_BYTES", str(DEFAULT_MAX_BYTES))))
    except ValueError:
        return DEFAULT_MAX_BYTES


def log_backup_count() -> int:
    try:
        return max(1, int(os.getenv("FRITZBOX_LOG_BACKUP_COUNT", str(DEFAULT_BACKUP_COUNT))))
    except ValueError:
        return DEFAULT_BACKUP_COUNT


def redact(value: Any) -> str:
    text = str(value)
    for pattern in SECRET_PATTERNS:
        text = pattern.sub(r"\1<redacted>", text)
    return text


def reset_logging_for_tests() -> None:
    global _CONFIGURED
    logger = logging.getLogger(LOGGER_NAME)
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()
    _CONFIGURED = False
