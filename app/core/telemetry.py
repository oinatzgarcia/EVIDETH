"""
app/core/telemetry.py
---------------------
Integración con Azure Application Insights mediante OpenCensus.

Qué hace:
  - Reenvía los logs de Python (WARNING+) a App Insights como Traces.
  - Registra excepciones no controladas como Exceptions en App Insights.
  - Es un NO-OP silencioso si APPLICATIONINSIGHTS_CONNECTION_STRING está vacío
    (local, CI, tests) — nunca lanza excepciones ni bloquea el arranque.

Uso:
  from app.core.telemetry import setup_telemetry
  setup_telemetry()   # llamar una sola vez en lifespan startup
"""

import logging
from app.config import settings
from app.core.logger import log


def setup_telemetry() -> bool:
    """
    Inicializa el exporter de App Insights.
    Devuelve True si se activó, False si se omitió (sin connection string).
    """
    conn_str = settings.APPLICATIONINSIGHTS_CONNECTION_STRING.strip()
    if not conn_str:
        log.info(
            "app_insights_disabled",
            extra={
                "detail": "APPLICATIONINSIGHTS_CONNECTION_STRING not set — skipping"
            },
        )
        return False

    try:
        from opencensus.ext.azure.log_exporter import AzureLogHandler

        # ── Handler para logs WARNING+ ──────────────────────────────────────
        azure_handler = AzureLogHandler(connection_string=conn_str)
        azure_handler.setLevel(logging.WARNING)

        # Adjuntar al logger raíz para capturar también librerías externas
        root_logger = logging.getLogger()
        root_logger.addHandler(azure_handler)

        # Adjuntar también al logger propio de EVIDETH
        evideth_logger = logging.getLogger("evideth")
        evideth_logger.addHandler(azure_handler)

        log.info(
            "app_insights_enabled",
            extra={
                "detail": "AzureLogHandler registered — forwarding WARNING+ to App Insights"
            },
        )
        return True

    except ImportError:
        log.warning(
            "app_insights_import_error",
            extra={
                "detail": "opencensus-ext-azure not installed — pip install opencensus-ext-azure"
            },
        )
        return False
    except Exception as exc:
        log.warning("app_insights_setup_failed", extra={"detail": str(exc)})
        return False
