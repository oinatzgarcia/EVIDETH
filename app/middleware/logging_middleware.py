"""
app/middleware/logging_middleware.py
=====================================
Middleware de logging HTTP para EVIDETH.

Captura automáticamente cada petición y emite:
  INFO    — respuestas 2xx / 3xx
  WARNING — respuestas 401, 403, 422 (problemas de autenticación/validación)
  ERROR   — respuestas 5xx (fallos internos)

No registra rutas de salud (/api/v1/health, /health) para no
ensuciar los logs con probes de Azure.
"""

import time
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from app.core.logger import log

_SKIP_PATHS = {"/api/v1/health", "/health", "/docs", "/openapi.json", "/redoc"}


class LoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Ignorar rutas de salud y documentación
        if request.url.path in _SKIP_PATHS:
            return await call_next(request)

        start = time.perf_counter()
        response = await call_next(request)
        duration_ms = round((time.perf_counter() - start) * 1000, 1)

        status = response.status_code
        extra = {
            "method":      request.method,
            "path":        request.url.path,
            "status_code": status,
            "duration_ms": duration_ms,
            "ip":          request.client.host if request.client else "-",
        }

        msg = f"{request.method} {request.url.path} → {status} ({duration_ms}ms)"

        if status >= 500:
            log.error(msg, extra=extra)
        elif status in (401, 403, 422):
            log.warning(msg, extra=extra)
        else:
            log.info(msg, extra=extra)

        return response
