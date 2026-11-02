"""Process-wide logging for OpenProxy and Uvicorn, without changing root logging."""

import json
import logging
import logging.config
import os
from typing import Any

from openproxy.core.config import LoggingConfig

LEVEL_ENV = "OPENPROXY_LOG_LEVEL"


class TextFormatter(logging.Formatter):
    """Render standard logging messages without serializing arbitrary record fields.

    Callers own message privacy. OpenProxy diagnostics must not pass config
    contents or raw exceptions as messages or arguments. This is not a sanitizer.
    """

    def format(self, record: logging.LogRecord) -> str:
        message = record.getMessage()
        timestamp = self.formatTime(record, "%Y-%m-%d %H:%M:%S")
        return f"{timestamp} | {record.levelname} | {record.name} | {message}"


class JsonFormatter(TextFormatter):
    def format(self, record: logging.LogRecord) -> str:
        return json.dumps(
            {
                "time": self.formatTime(record, "%Y-%m-%d %H:%M:%S"),
                "level": record.levelname,
                "component": record.name,
                "message": record.getMessage(),
            }
        )


def logging_config(settings: LoggingConfig) -> dict[str, Any]:
    level = os.environ.get(LEVEL_ENV, settings.level)
    if level not in {"DEBUG", "INFO", "WARNING", "ERROR"}:
        level = settings.level
    formatter = JsonFormatter if settings.format == "json" else TextFormatter
    return {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {"safe": {"()": formatter}},
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "stream": "ext://sys.stderr",
                "formatter": "safe",
            }
        },
        "loggers": {
            name: {"handlers": ["console"], "level": level, "propagate": False}
            for name in ("openproxy", "uvicorn", "uvicorn.error", "uvicorn.access")
        },
    }


def configure_logging(settings: LoggingConfig) -> None:
    logging.config.dictConfig(logging_config(settings))
