"""Structured JSON logging with central redaction."""
from __future__ import annotations

import json
import logging
import sys
from typing import Any, Dict

from ..security.redaction import redact_text


class RedactingJsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: Dict[str, Any] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%SZ"),
            "level": record.levelname,
            "logger": record.name,
            "msg": redact_text(record.getMessage())[:2000],
        }
        for key in ("request_id", "user_id", "org_id", "scan_id", "action"):
            value = getattr(record, key, None)
            if value:
                payload[key] = str(value)[:128]
        if record.exc_info:
            payload["error_type"] = record.exc_info[0].__name__ if record.exc_info[0] else "Exception"
        return json.dumps(payload, separators=(",", ":"))


def configure_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler(stream=sys.stdout)
    handler.setFormatter(RedactingJsonFormatter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    for noisy in ("uvicorn.access",):
        logging.getLogger(noisy).handlers = []
        logging.getLogger(noisy).propagate = False


def log_event(logger: logging.Logger, message: str, **fields: Any) -> None:
    logger.info(message, extra={k: v for k, v in fields.items() if v is not None})
