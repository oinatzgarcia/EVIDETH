# Azure Application Insights en EVIDETH

Documentación de la integración de Azure Application Insights en EVIDETH.
Cubre la arquitectura, los componentes implementados, el proceso de activación
en Azure y las consultas de referencia para monitorización en producción.

Este documento complementa [`logging_y_observabilidad.md`](./logging_y_observabilidad.md),
que describe el sistema de logging estructurado (JSON + stdout) sobre el que
se construye esta integración.

---

## Índice

1. [Qué es Application Insights y por qué se usa](#1-qué-es-application-insights-y-por-qué-se-usa)
2. [Arquitectura de integración](#2-arquitectura-de-integración)
3. [Componentes implementados](#3-componentes-implementados)
4. [Comportamiento por entorno](#4-comportamiento-por-entorno)
5. [Qué datos llegan a App Insights](#5-qué-datos-llegan-a-app-insights)
6. [Provisión del recurso en Azure](#6-provisión-del-recurso-en-azure)
7. [Configuración en el Container App](#7-configuración-en-el-container-app)
8. [Verificación del funcionamiento](#8-verificación-del-funcionamiento)
9. [Consultas KQL de referencia](#9-consultas-kql-de-referencia)
10. [Relación con Log Analytics Workspace](#10-relación-con-log-analytics-workspace)

---

## 1. Qué es Application Insights y por qué se usa

Azure Application Insights es el servicio de APM (*Application Performance
Monitoring*) de Azure. En EVIDETH se usa específicamente para:

- **Centralizar alertas de seguridad**: los eventos `WARNING` y `ERROR`
  (login fallido, errores 5xx, excepciones) se reenvían automáticamente
  a App Insights, donde pueden configurarse alertas y notificaciones.
- **Retención independiente**: App Insights mantiene 90 días de retención
  por defecto, frente a los 30 días del Log Analytics Workspace.
- **Panel de métricas en tiempo real**: el portal de Azure ofrece vistas
  de *Live Metrics*, tasas de error y latencia sin necesidad de escribir KQL.
- **Integración nativa con el ecosistema Azure**: Key Vault, Container Apps
  y Blob Storage pueden correlacionar sus eventos con los de la aplicación.

---

## 2. Arquitectura de integración

```
app/core/logger.py  (logger "evideth", nivel WARNING+)
        │
        ├──► stdout (JSON)  ──► Log Analytics Workspace
        │                       (ContainerAppConsoleLogs_CL)
        │
        └──► AzureLogHandler ──► Application Insights
             (opencensus-ext-azure)   (tabla: traces)
```

El `AzureLogHandler` de OpenCensus se adjunta al logger raíz de Python
y al logger `evideth` durante el arranque de la aplicación. Actúa como
un segundo destino: los logs siguen llegando a `stdout` (y por tanto a
Log Analytics) **y además** se reenvían a App Insights.

Esto significa que **no hay que elegir** entre uno u otro servicio:
ambos reciben los mismos eventos de forma simultánea.

---

## 3. Componentes implementados

| Fichero | Cambio | Descripción |
|---|---|---|
| `app/core/telemetry.py` | Nuevo | Lógica completa de inicialización de App Insights |
| `app/main.py` | Modificado | Llama a `setup_telemetry()` al inicio del lifespan |
| `app/config.py` | Modificado | Nueva variable `APPLICATIONINSIGHTS_CONNECTION_STRING` |
| `requirements.txt` | Modificado | Añadida dependencia `opencensus-ext-azure==1.1.13` |

### `app/core/telemetry.py`

```python
from app.core.telemetry import setup_telemetry
setup_telemetry()   # llamar una sola vez en lifespan startup
```

La función `setup_telemetry()` realiza las siguientes acciones:

1. Lee `APPLICATIONINSIGHTS_CONNECTION_STRING` de la configuración.
2. Si está vacío → emite `INFO app_insights_disabled` y retorna `False` (NO-OP).
3. Si está presente → crea un `AzureLogHandler` con nivel `WARNING`.
4. Adjunta el handler al logger raíz (`logging.getLogger()`) y al logger
   `evideth` para capturar tanto logs propios como de librerías externas.
5. Emite `INFO app_insights_enabled` y retorna `True`.
6. Cualquier excepción durante la inicialización es capturada y emitida
   como `WARNING` — nunca bloquea el arranque de la aplicación.

### `app/main.py` — integración en lifespan

```python
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Application Insights — antes de cualquier log de startup
    setup_telemetry()

    try:
        models.Base.metadata.create_all(bind=engine)
        log.info("DB tables verified/created")
    ...
```

`setup_telemetry()` se llama **antes** de cualquier otro log de startup
para garantizar que incluso los eventos de inicialización de la BD
queden registrados en App Insights si ocurre algún error.

---

## 4. Comportamiento por entorno

| Entorno | `APPLICATIONINSIGHTS_CONNECTION_STRING` | Comportamiento |
|---|---|---|
| **Local** (`docker compose`) | Vacío (no definido en `.env`) | NO-OP silencioso. Log `app_insights_disabled`. Solo stdout. |
| **CI/CD** (GitHub Actions) | No configurado como secret | NO-OP silencioso. Los tests no envían datos a Azure. |
| **Staging / Producción** (Container App) | Configurado como env var | `AzureLogHandler` activo. WARNING+ reenviados a App Insights. |

Este diseño garantiza que los tests unitarios y de integración no
dependan de conectividad con Azure ni consuman cuota del recurso.

---

## 5. Qué datos llegan a App Insights

Solo los eventos de nivel `WARNING` y `ERROR` se reenvían a App Insights.
Los eventos `INFO` y `DEBUG` permanecen únicamente en stdout / Log Analytics.

### Eventos de seguridad (logs explícitos)

| Evento | Nivel | Origen |
|---|---|---|
| `login_failed` | WARNING | `app/api/v1/auth.py` |
| `login_blocked_inactive` | WARNING | `app/api/v1/auth.py` |
| `app_insights_setup_failed` | WARNING | `app/core/telemetry.py` |
| Cualquier excepción no controlada | ERROR | FastAPI exception handler |

### Eventos de middleware (automáticos)

Todas las respuestas HTTP con código `401`, `403`, `422` o `5xx` generan
un log WARNING/ERROR en el `LoggingMiddleware` que también llega a App Insights.

### Formato en la tabla `traces` de App Insights

```
Timestamp         : 2026-05-27T15:43:01Z
message           : login_failed
severityLevel     : 2              ← WARNING
customDimensions  : {
  "ip": "93.184.216.34",
  "detail": "email=admin@evideth.com",
  "logger": "evideth"
}
```

| `severityLevel` | Nivel Python |
|---|---|
| 1 | INFO |
| 2 | WARNING |
| 3 | ERROR |
| 4 | CRITICAL |

---

## 6. Provisión del recurso en Azure

El recurso Application Insights se crea enlazado al Log Analytics Workspace
existente (`evideth-dev-logs`) para que ambos servicios compartan la misma
base de datos de telemetría.

### Recurso creado

| Campo | Valor |
|---|---|
| **Nombre** | `evideth-dev-appinsights` |
| **Resource Group** | `evideth-dev-rg` |
| **Región** | `spaincentral` |
| **Workspace** | `evideth-dev-logs` |
| **Tipo** | `web` |
| **Retención** | 90 días |
| **InstrumentationKey** | `4b911af6-4b18-4159-af5b-1ed12f1dd688` |

### Comando de creación

```bash
az monitor app-insights component create \
  --app evideth-dev-appinsights \
  --resource-group evideth-dev-rg \
  --location spaincentral \
  --workspace evideth-dev-logs \
  --kind web \
  --application-type web
```

### Obtener la Connection String

```bash
az monitor app-insights component show \
  --app evideth-dev-appinsights \
  --resource-group evideth-dev-rg \
  --query connectionString \
  --output tsv
```

---

## 7. Configuración en el Container App

La Connection String se configura como variable de entorno en el
Container App `evideth-dev-backend`.

### Comando de configuración

```bash
CONN_STR=$(az monitor app-insights component show \
  --app evideth-dev-appinsights \
  --resource-group evideth-dev-rg \
  --query connectionString \
  --output tsv)

az containerapp update \
  --name evideth-dev-backend \
  --resource-group evideth-dev-rg \
  --set-env-vars "APPLICATIONINSIGHTS_CONNECTION_STRING=$CONN_STR"
```

### Verificación

```bash
az containerapp show \
  --name evideth-dev-backend \
  --resource-group evideth-dev-rg \
  --query "properties.template.containers[0].env[?name=='APPLICATIONINSIGHTS_CONNECTION_STRING'].value" \
  --output tsv
```

Debe devolver la Connection String completa. La nueva revisión del
Container App se crea automáticamente al actualizar la variable.

### Variable en `.env.example`

```bash
# Azure Application Insights
# Dejar vacío en local/test para deshabilitar el exporter.
# En producción: obtener desde Azure Portal → App Insights → Overview → Connection String
APPLICATIONINSIGHTS_CONNECTION_STRING=""
```

---

## 8. Verificación del funcionamiento

### 1. Confirmar arranque correcto

Al iniciar el contenedor, los logs de startup deben incluir:

```json
{"level":"INFO","event":"app_insights_enabled","detail":"AzureLogHandler registered — forwarding WARNING+ to App Insights"}
```

Si aparece `app_insights_disabled`, la variable de entorno no está configurada.

### 2. Generar un evento de prueba

```bash
# Login fallido → genera WARNING login_failed en App Insights
curl -s -X POST \
  https://evideth-dev-backend.icywave-c2a647eb.spaincentral.azurecontainerapps.io/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"wrong"}'
```

### 3. Consultar en App Insights (~2 min de latencia)

En **Azure Portal → Application Insights `evideth-dev-appinsights` → Logs**:

```kql
traces
| where timestamp > ago(10m)
| project timestamp, severityLevel, message
| order by timestamp desc
```

Una fila con `severityLevel = 2` y `message = "login_failed"` confirma
que la integración está operativa.

---

## 9. Consultas KQL de referencia

Desde **Azure Portal → Application Insights → Logs**:

### Todos los warnings y errores recientes

```kql
traces
| where timestamp > ago(24h)
| where severityLevel >= 2
| project timestamp, severityLevel, message,
          tostring(customDimensions.ip),
          tostring(customDimensions.detail)
| order by timestamp desc
```

### Detectar fuerza bruta en login

```kql
traces
| where timestamp > ago(1h)
| where message == "login_failed"
| summarize intentos = count() by ip = tostring(customDimensions.ip)
| where intentos > 5
| order by intentos desc
```

### Errores 5xx (fallos internos del servidor)

```kql
traces
| where timestamp > ago(24h)
| where severityLevel == 3
| project timestamp,
          message,
          tostring(customDimensions.path),
          tostring(customDimensions.ip),
          tostring(customDimensions.detail)
| order by timestamp desc
```

### Tasa de errores por hora

```kql
traces
| where timestamp > ago(24h)
| where severityLevel >= 2
| summarize errores = count() by bin(timestamp, 1h)
| order by timestamp asc
```

### Actividad de un usuario concreto

```kql
traces
| where timestamp > ago(7d)
| where tostring(customDimensions.user_id) == "<UUID-del-usuario>"
| project timestamp, severityLevel, message,
          tostring(customDimensions.ip)
| order by timestamp desc
```

---

## 10. Relación con Log Analytics Workspace

Ambos servicios están enlazados al mismo workspace `evideth-dev-logs`,
lo que permite correlacionar eventos de distintas fuentes en una sola consulta:

```kql
// Correlación: logs de contenedor + traces de App Insights
let errores_ai = traces
  | where timestamp > ago(1h)
  | where severityLevel >= 2
  | project ts = timestamp, origen = "AppInsights", msg = message;

let errores_law = ContainerAppConsoleLogs_CL
  | where TimeGenerated > ago(1h)
  | where Log_s has "\"level\":\"ERROR\""
  | extend parsed = parse_json(Log_s)
  | project ts = TimeGenerated, origen = "LogAnalytics", msg = tostring(parsed.event);

union errores_ai, errores_law
| order by ts desc
```

### Cuándo usar cada servicio

| Necesidad | Servicio recomendado |
|---|---|
| Ver todos los logs (INFO, DEBUG) | Log Analytics → `ContainerAppConsoleLogs_CL` |
| Alertas de seguridad en tiempo real | Application Insights → `traces` |
| Métricas de latencia y tasa de error | Application Insights → *Performance* / *Failures* |
| Diagnóstico de arranque o CI | Log Analytics o `docker compose logs` |
| Retención a 90 días | Application Insights |
| Retención a 30 días | Log Analytics Workspace |
