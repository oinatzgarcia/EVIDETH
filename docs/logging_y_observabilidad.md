# Logging y Observabilidad en EVIDETH

Documentación del sistema de logging técnico de EVIDETH.
Cubre la arquitectura, los niveles de log, el formato de salida,
los puntos de instrumentación y la integración con Azure Log Analytics.

---

## Índice

1. [Arquitectura general](#1-arquitectura-general)
2. [Componentes implementados](#2-componentes-implementados)
3. [Niveles de log](#3-niveles-de-log)
4. [Formato JSON estructurado](#4-formato-json-estructurado)
5. [Middleware HTTP automático](#5-middleware-http-automático)
6. [Puntos de log explícito](#6-puntos-de-log-explícito)
7. [Uso en el código](#7-uso-en-el-código)
8. [Integración con Azure Log Analytics](#8-integración-con-azure-log-analytics)
9. [Consultas KQL de referencia](#9-consultas-kql-de-referencia)
10. [Principio de diseño: 12-Factor App](#10-principio-de-diseño-12-factor-app)

---

## 1. Arquitectura general

EVIDETH implementa un sistema de logging en dos capas:

```
Petición HTTP entrante
        │
        ▼
┌───────────────────────┐
│  LoggingMiddleware    │  ← Capa automática: registra TODA petición/respuesta
│  (app/middleware/)    │
└───────────┬───────────┘
            │
            ▼
┌───────────────────────┐
│   Router FastAPI      │  ← Capa explícita: log.warning/error en puntos críticos
│   (app/api/v1/)       │    de seguridad (login fallido, hash inválido, etc.)
└───────────┬───────────┘
            │
            ▼
┌───────────────────────┐
│   app/core/logger.py  │  ← Instancia única `log`, formateador JSON
│   → stdout (JSON)     │
└───────────┬───────────┘
            │
            ▼
┌───────────────────────┐
│  Azure Container Apps │  ← Recoge stdout automáticamente
│  → Log Analytics WS   │    sin configuración adicional
└───────────────────────┘
```

La aplicación **no gestiona** el destino ni la retención de los logs.
Solo emite a `stdout` y la infraestructura Azure se encarga del resto.
Este diseño sigue el **Factor XI de la metodología 12-Factor App**.

---

## 2. Componentes implementados

| Fichero | Responsabilidad |
|---|---|
| `app/core/logger.py` | Instancia única `log`, formateador JSON, configuración de nivel |
| `app/middleware/logging_middleware.py` | Intercepta cada request HTTP y emite log automático |
| `app/middleware/__init__.py` | Paquete Python |
| `app/api/v1/auth.py` | Logs explícitos en login fallido, bloqueado y exitoso |

El logger se registra en `app/main.py` junto al resto del middleware:

```python
from app.middleware.logging_middleware import LoggingMiddleware
app.add_middleware(LoggingMiddleware)   # antes del middleware CORS
```

---

## 3. Niveles de log

EVIDETH usa los cuatro niveles estándar de Python `logging`:

| Nivel | Cuándo se usa | Ejemplos |
|---|---|---|
| `DEBUG` | Trazas de desarrollo detalladas. Desactivado en producción (`DEBUG=false`) | Valores intermedios en cálculos criptográficos |
| `INFO` | Eventos normales del sistema, flujo esperado | Login exitoso, segmento almacenado, DB iniciada |
| `WARNING` | Situaciones anómalas **recuperables** que merecen atención | Login fallido, 401/403/422, usuario inactivo |
| `ERROR` | Fallos que **impiden** completar una operación | Excepción no controlada, error 5xx, fallo de BD |

El nivel activo se controla con la variable de entorno `DEBUG`:

```bash
DEBUG=false   # producción → INFO, WARNING, ERROR
DEBUG=true    # desarrollo → DEBUG, INFO, WARNING, ERROR
```

---

## 4. Formato JSON estructurado

Cada línea de log es un objeto JSON independiente con los campos:

```json
{
  "ts":          "2026-05-26T18:41:03.412Z",
  "level":       "WARNING",
  "logger":      "evideth",
  "event":       "login_failed",
  "ip":          "93.184.216.34",
  "detail":      "email=atacante@evil.com"
}
```

### Campos obligatorios

| Campo | Tipo | Descripción |
|---|---|---|
| `ts` | ISO 8601 UTC | Timestamp del evento |
| `level` | string | `DEBUG` / `INFO` / `WARNING` / `ERROR` |
| `logger` | string | Siempre `evideth` para logs propios |
| `event` | string | Descripción corta del evento (snake_case) |

### Campos opcionales de contexto

| Campo | Cuándo aparece |
|---|---|
| `camera_id` | Eventos relacionados con una cámara concreta |
| `user_id` | Eventos autenticados (UUID del usuario) |
| `ip` | Dirección IP del cliente |
| `path` | Ruta HTTP (`/api/v1/cameras/`) |
| `method` | Método HTTP (`GET`, `POST`, etc.) |
| `status_code` | Código de respuesta HTTP |
| `duration_ms` | Duración de la petición en milisegundos |
| `detail` | Información adicional de contexto libre |
| `exc` | Traceback completo (solo en `ERROR` con excepción) |

### Ejemplos reales

```json
{"ts":"2026-05-26T18:40:01Z","level":"INFO","logger":"evideth","event":"POST /api/v1/auth/login → 200 (14.2ms)","method":"POST","path":"/api/v1/auth/login","status_code":200,"duration_ms":14.2,"ip":"10.0.0.5"}

{"ts":"2026-05-26T18:40:55Z","level":"WARNING","logger":"evideth","event":"login_failed","ip":"185.220.101.3","detail":"email=admin@evideth.com"}

{"ts":"2026-05-26T18:41:10Z","level":"WARNING","logger":"evideth","event":"POST /api/v1/cameras/segments → 422 (3.1ms)","method":"POST","path":"/api/v1/cameras/segments","status_code":422,"duration_ms":3.1,"ip":"10.0.0.8"}

{"ts":"2026-05-26T18:42:00Z","level":"ERROR","logger":"evideth","event":"GET /api/v1/verification/ → 500 (201.4ms)","method":"GET","path":"/api/v1/verification/","status_code":500,"duration_ms":201.4,"ip":"10.0.0.5"}
```

---

## 5. Middleware HTTP automático

El `LoggingMiddleware` (`app/middleware/logging_middleware.py`) se ejecuta
en **cada petición** sin necesidad de instrumentar los routers manualmente.

### Lógica de nivel por código HTTP

```
2xx / 3xx  →  INFO
401 / 403  →  WARNING  (problemas de autenticación/autorización)
422        →  WARNING  (validación fallida — posible input malformado)
5xx        →  ERROR    (fallo interno del servidor)
```

### Rutas excluidas

Las siguientes rutas **no generan logs** para evitar ruido con los
health checks de Azure Container Apps:

```python
_SKIP_PATHS = {"/api/v1/health", "/health", "/docs", "/openapi.json", "/redoc"}
```

### Campos emitidos automáticamente

- `method` — verbo HTTP
- `path` — ruta sin query string
- `status_code` — código de respuesta
- `duration_ms` — tiempo total de procesamiento
- `ip` — IP del cliente (o `-` si no disponible)

---

## 6. Puntos de log explícito

Además del middleware automático, determinados eventos de seguridad
emiten logs explícitos con contexto adicional:

### `app/api/v1/auth.py`

| Evento (`event`) | Nivel | Cuándo | Campos extra |
|---|---|---|---|
| `login_failed` | WARNING | Email o contraseña incorrectos | `ip`, `detail` (email) |
| `login_blocked_inactive` | WARNING | Usuario desactivado intenta login | `ip`, `user_id`, `detail` |
| `login_ok` | INFO | Login exitoso | `ip`, `user_id`, `detail` (role) |
| `token_refreshed` | INFO | JWT renovado vía `/auth/refresh` | `user_id` |

### `app/main.py` (lifespan)

| Evento | Nivel | Cuándo |
|---|---|---|
| `DB tables verified/created` | INFO | Startup correcto |
| `DB engine disposed` | INFO | Shutdown limpio |

### Patrón para añadir logs en otros routers

```python
from app.core.logger import log

# En cualquier endpoint
log.warning("camera_deactivated_unauthorized",
            extra={"camera_id": camera_id, "ip": ip, "user_id": str(current_user.id)})

log.error("segment_storage_failed",
          extra={"camera_id": camera_id, "detail": str(exc)})
```

---

## 7. Uso en el código

### Importar el logger

```python
from app.core.logger import log
```

### Llamadas por nivel

```python
# Evento informativo normal
log.info("video_recording_started",
         extra={"camera_id": "cam-01", "video_id": str(video.id)})

# Anomalía recuperable (no bloquea el sistema)
log.warning("hash_validation_failed",
            extra={"camera_id": "cam-01", "detail": f"len={len(h)}, expected=64"})

# Fallo que impide completar la operación
log.error("db_write_failed",
          extra={"camera_id": "cam-01", "detail": str(exc)},
          exc_info=True)   # incluye traceback completo

# Solo en desarrollo (DEBUG=true)
log.debug("ecdsa_signature_computed",
          extra={"detail": f"sig_len={len(sig)}"})
```

### No usar el logger de stdlib directamente

Los módulos internos de FastAPI/SQLAlchemy usan `logging.getLogger(__name__)`.
Para el código propio de EVIDETH, **usar siempre `from app.core.logger import log`**
para garantizar el formato JSON y el nivel centralizado.

---

## 8. Integración con Azure Log Analytics

### Flujo automático

Azure Container Apps recoge `stdout` del contenedor sin configuración adicional:

```
Container App (stdout JSON)
        │
        ▼
Log Analytics Workspace
        │
        ▼
Tabla: ContainerAppConsoleLogs_CL
```

No es necesario instalar agentes, SDKs de Azure Monitor ni configurar
`applicationInsights`. El formato JSON estructurado permite filtrar
directamente por campos sin parsear texto libre.

### Variable de entorno relevante

```bash
DEBUG=false   # INFO+ en producción (recomendado)
DEBUG=true    # DEBUG+ en desarrollo/staging
```

---

## 9. Consultas KQL de referencia

Desde **Azure Portal → Log Analytics Workspace → Logs**:

### Ver todos los errores de las últimas 24 horas

```kql
ContainerAppConsoleLogs_CL
| where TimeGenerated > ago(24h)
| where Log_s has "\"level\":\"ERROR\""
| project TimeGenerated,
          parse_json(Log_s).event,
          parse_json(Log_s).path,
          parse_json(Log_s).ip
| order by TimeGenerated desc
```

### Detectar intentos de login fallidos (posible fuerza bruta)

```kql
ContainerAppConsoleLogs_CL
| where TimeGenerated > ago(1h)
| where Log_s has "login_failed"
| extend parsed = parse_json(Log_s)
| summarize intentos = count() by ip = tostring(parsed.ip)
| where intentos > 5
| order by intentos desc
```

### Latencia media por endpoint (últimas 6 horas)

```kql
ContainerAppConsoleLogs_CL
| where TimeGenerated > ago(6h)
| where Log_s has "duration_ms"
| extend parsed      = parse_json(Log_s)
| extend path        = tostring(parsed.path)
| extend duration_ms = todouble(parsed.duration_ms)
| summarize avg_ms = avg(duration_ms), p95_ms = percentile(duration_ms, 95)
  by path
| order by p95_ms desc
```

### Peticiones rechazadas por validación (422) — posible tampering

```kql
ContainerAppConsoleLogs_CL
| where TimeGenerated > ago(24h)
| where Log_s has "\"status_code\":422"
| extend parsed = parse_json(Log_s)
| project TimeGenerated,
          tostring(parsed.path),
          tostring(parsed.ip),
          todouble(parsed.duration_ms)
| order by TimeGenerated desc
```

### Actividad de una cámara concreta

```kql
ContainerAppConsoleLogs_CL
| where Log_s has "cam-01"
| extend parsed = parse_json(Log_s)
| where tostring(parsed.camera_id) == "cam-01"
| project TimeGenerated,
          tostring(parsed.level),
          tostring(parsed.event),
          tostring(parsed.detail)
| order by TimeGenerated desc
```

---

## 10. Principio de diseño: 12-Factor App

El sistema de logging de EVIDETH sigue el **Factor XI** de la metodología
[12-Factor App](https://12factor.net/logs):

> *"Una aplicación twelve-factor nunca se preocupa del enrutado o almacenamiento
> de su flujo de salida. No debe intentar escribir o gestionar ficheros de log.
> En su lugar, cada proceso en ejecución escribe su flujo de eventos, sin buffer,
> a stdout."*

| Principio | Implementación en EVIDETH |
|---|---|
| Logs como flujo de eventos | `stdout` vía `logging.StreamHandler(sys.stdout)` |
| Sin gestión de ficheros | No hay `FileHandler`, no hay rotación |
| Formato estructurado | JSON con campos tipados — consultable directamente en KQL |
| Nivel configurable por entorno | Variable `DEBUG` en `.env` / Azure App Settings |
| Destino gestionado por la infraestructura | Azure Container Apps → Log Analytics automático |

Esta arquitectura facilita la **portabilidad**: el mismo contenedor emite
logs de la misma forma en local (`docker compose`), en CI (stdout de GitHub
Actions) y en producción (Azure Log Analytics), sin cambiar una línea de código.
