"""Logging and telemetry setup for the portal."""

import json
import logging
import os
import sys
from datetime import datetime, timezone


class JsonFormatter(logging.Formatter):
    """Minimal JSON log formatter."""

    def format(self, record):
        # type: (logging.LogRecord) -> str
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for field in ("request_id", "path", "method", "status_code", "duration_ms", "runtime_environment"):
            value = getattr(record, field, None)
            if value not in (None, ""):
                payload[field] = value
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, separators=(",", ":"))


def configure_logging():
    # type: () -> None
    """Configure application logging once."""
    root = logging.getLogger()
    if getattr(configure_logging, "_configured", False):
        return
    level_name = os.getenv("LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root.handlers = [handler]
    root.setLevel(level)
    configure_logging._configured = True  # type: ignore[attr-defined]


def configure_observability(service_name):
    # type: (str) -> None
    """Enable Azure Monitor auto-instrumentation when configured."""
    connection_string = os.getenv("APPLICATIONINSIGHTS_CONNECTION_STRING", "")
    if not connection_string:
        return
    try:
        from azure.monitor.opentelemetry import configure_azure_monitor
    except ImportError:
        logging.getLogger(service_name).warning(
            "Azure Monitor instrumentation requested but package is unavailable"
        )
        return

    try:
        configure_azure_monitor(
            connection_string=connection_string,
            logger_name=service_name,
        )
        logging.getLogger(service_name).info("Azure Monitor instrumentation enabled")
    except Exception:  # pragma: no cover - defensive runtime logging
        logging.getLogger(service_name).exception("Failed to enable Azure Monitor instrumentation")
