"""
app/core/logger.py
==================
Logger centralizado de EVIDETH.

Emite registros JSON estructurados por stdout. En producción,
Azure Container Apps los recoge automáticamente en Log Analytics.

Niveles:
  DEBUG   — trazas de desarrollo (desactivado en producción)
  INFO    — eventos normales de negocio
  WARNING — situaciones anómalas recuperables (401, 403, hash inválido)
  ERROR   — fallos que impiden completar una operación
"""

import json
import logging
import sys
from datetime import datetime, timezone

from app.config import settings


class _JsonFormatter(logging.Formatter):
    """Formatea cada log record como una línea JSON."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts":      datetime.now(timezone.utc).isoformat(),
            "level":   record.levelname,
            "logger":  record.name,
            "event":   record.getMessage(),
        }
        # Campos extra pasados con extra={...} en la llamada al logger
        for key in ("camera_id", "user_id", "ip", "path", "method",
                    "status_code", "duration_ms", "detail"):
            if hasattr(record, key):
                payload[key] = getattr(record, key)

        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)

        return json.dumps(payload, ensure_ascii=False, default=str)


def _build_logger() -> logging.Logger:
    logger = logging.getLogger("evideth")

    # Evita añadir handlers duplicados si el módulo se importa varias veces
    if logger.handlers:
        return logger

    level = logging.DEBUG if getattr(settings, "DEBUG", False) else logging.INFO
    logger.setLevel(level)

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(_JsonFormatter())
    logger.addHandler(handler)
    logger.propagate = False

    return logger


# Instancia única — importar desde aquí en toda la app
log = _build_logger()
