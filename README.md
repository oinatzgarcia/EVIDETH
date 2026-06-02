# EVIDETH
🔐 EVIDETH - Sistema Forense de Verificación de Integridad de Vídeo mediante hashing criptográfico (SHA-256) y firmas ECDSA.

<div align="center">
  <img src="docs/Images/Logo.png" alt="Logo EVIDETH" width="360"/>
  
  # EVIDETH
  ### Sistema Forense de Verificación de Integridad de Vídeo
  
  **Hashing SHA-256 · Firmas ECDSA P-256 · Azure Cloud**
  
  <br/>
  
  <img src="docs/Images/Dashboard.png" alt="Dashboard EVIDETH" width="85%"/>
  
  <br/>
  
  <p>
    <img src="https://img.shields.io/badge/Python-3.11+-blue.svg"/>
    <img src="https://img.shields.io/badge/FastAPI-0.109+-green.svg"/>
    <img src="https://img.shields.io/badge/Azure-Cloud-0078D4.svg"/>
  </p>
</div>

---

## 🎯 Descripción General

EVIDETH es un sistema de verificación de integridad de vídeo de grado forense que garantiza la autenticidad e inalterabilidad de grabaciones de vigilancia mediante firmas criptográficas.

**Características principales:**
- 🔐 Verificación criptográfica SHA-256 + ECDSA P-256
- 📹 Segmentación de vídeo en bloques de 30 segundos para análisis granular
- ☁️ Integración con Azure Key Vault
- 🦉 Inspirado en la sabiduría y vigilancia de Atenea

---

## 📚 Documentación

### 🏗️ Infraestructura y Despliegue

| Documento | Descripción |
|---|---|
| [Pipeline CI/CD](docs/ci_cd_evideth.md) | Workflows de GitHub Actions: build, deploy, destroy y plan. Autenticación OIDC con Azure. |
| [Azure Key Vault](docs/azure_key_vault.md) | Gestión de la clave ECDSA P-256 y secretos desde Key Vault. Managed Identity. |
| [Application Insights](docs/application_insights.md) | Telemetría, trazas y métricas del backend en Azure Monitor. |
| [Logging y Observabilidad](docs/logging_y_observabilidad.md) | Estructura de logs, niveles, correlación de trazas y Log Analytics Workspace. |

### 🔐 Seguridad e Identidades

| Documento | Descripción |
|---|---|
| [Gestión de Identidades](docs/gestion_identidades.md) | JWT para usuarios, API Keys para cámaras, roles y control de acceso. |
| [Seguridad de Datos y Credenciales](docs/seguridad_datos_y_credenciales.md) | Cifrado en tránsito y en reposo, gestión de secretos y modelo de amenazas. |

### 🧪 Testing

| Documento | Descripción |
|---|---|
| [Tests Unitarios y Escenarios](docs/tests_unitarios_y_escenarios.md) | Cobertura de tests unitarios, fixtures y escenarios de prueba por módulo. |
| [Tests de Integración](docs/tests_integracion.md) | Tests end-to-end contra la API real, base de datos y servicios Azure. |

### 🎨 Diseños

| Recurso | Descripción |
|---|---|
| [Diagrama de Arquitectura (PDF)](docs/Designs/Schemes/InfraestructuraAzure.pdf) | Arquitectura completa de infraestructura Azure. |
| [Carpeta Designs](docs/Designs/) | Diagramas, esquemas y mockups del sistema. |

---

## ☁️ Infraestructura Azure

EVIDETH está desplegado en **Microsoft Azure** (Spain Central) con una arquitectura privada y orientada a la seguridad. Todos los recursos se encuentran en el grupo de recursos `evideth-dev-rg`.

### Visión General de la Arquitectura

| Capa | Recurso | Función |
|---|---|---|
| **Red** | `capp-svc-lb` + `capp-svc-lb-ip` | Balanceador de carga público e IP de entrada |
| **Red** | `evideth-dev-app-nsg` | Grupo de seguridad de red — reglas de tráfico |
| **Red** | `evideth-dev-vnet` | Red virtual con subnets de aplicación y datos |
| **Cómputo** | `evideth-dev-backend` (Container App) | Backend FastAPI + frontend estático |
| **Cómputo** | `evideth-dev-cae` | Entorno de Container Apps |
| **Registro** | `evidethdevacr94f04b.azurecr.io` | Registro de imágenes Docker (pipeline CI/CD) |
| **Base de datos** | `evideth-dev-pgserver` | PostgreSQL Flexible Server — **solo acceso privado por VNet** |
| **Base de datos** | `evideth.postgres.database.azure.com` | Zona DNS privada para PostgreSQL |
| **Seguridad** | `evideth-dev-kv-94f04b` | Key Vault — clave ECDSA P-256 + secreto JWT |
| **Almacenamiento** | `evidethdevst94f04b` | Blob Storage — vídeos subidos por analistas para verificación |
| **Observabilidad** | `evideth-dev-logs` | Área de trabajo de Log Analytics |

### Decisiones de Seguridad Clave

- **PostgreSQL sin endpoint público** — accesible únicamente dentro de la VNet mediante zona DNS privada.
- **Acceso a Key Vault mediante Managed Identity** — sin credenciales almacenadas en el código ni en variables de entorno.
- **CI/CD con OIDC** — GitHub Actions se autentica en Azure mediante Workload Identity Federation; sin secretos de larga duración en GitHub.
- **JWT para usuarios, API Keys para cámaras** — mecanismos de autenticación independientes según el tipo de cliente.

### Flujo CI/CD

```
GitHub Push → GitHub Actions (OIDC) → Terraform Apply (infra)
  → Build imagen Docker → Push al ACR → Container App actualizado
```

### Flujo de Petición

```
Cámara (API Key) ──► Balanceador de carga ──► Container App
                                                    │
                               ┌────────────────────┼────────────────────┐
                               ▼                    ▼                    ▼
                          Key Vault           PostgreSQL           Blob Storage
                        (clave ECDSA)     (hashes + firmas)    (MP4 de analistas)
```

📄 **[Diagrama de Arquitectura Completo (PDF)](docs/Designs/Schemes/InfraestructuraAzure.pdf)**

---

## 📷 Despliegue del Cliente (Live Viewer)

El cliente EVIDETH es un **simulador de cámara forense** que renderiza vídeo sintético en el navegador (via `<canvas>`), genera hashes SHA-256 por cada segmento temporal y los envía al backend para su registro criptográfico.

> 🚨 **Importante — Arquitectura de datos:**
> El cliente **NO graba ningún fichero de vídeo** (.mp4 ni similar). Solo genera y transmite **hashes + metadatos** de cada segmento.
> El backend **tampoco almacena el vídeo** procedente del cliente — únicamente persiste en PostgreSQL los hashes SHA-256, firmas ECDSA y metadatos temporales de cada segmento.
> Los ficheros MP4 reales solo llegan al sistema cuando un **analista los sube manualmente** desde el panel de verificación del dashboard, y se guardan temporalmente para procesarlos (generación de hashes y verificación) antes de eliminarse.

### Prerrequisitos

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) instalado y en ejecución
- Acceso al backend EVIDETH (Azure o local)
- **Camera ID** y **API Key** de una cámara registrada en el sistema

> 💡 Si no tienes una cámara registrada, un administrador debe crearla primero en el panel de administración o mediante `POST /api/v1/cameras/` con rol Admin.

---

### ⚙️ Paso 1 — Configurar credenciales

Edita el fichero `frontend/client.config.js` con los datos de tu cámara:

```js
// frontend/client.config.js
window.EVIDETH_CONFIG = {
  CAMERA_ID:      'CAM1',                          // ID de la cámara registrada
  CAMERA_API_KEY: 'evideth_cam_XXXXXXXXXXXX',       // API Key obtenida al registrar la cámara
  BACKEND_URL:    'https://evideth-dev-backend.icymushroom-b7fd3b26.spaincentral.azurecontainerapps.io',
  MAX_SEGMENTS:   0,                               // 0 = sin límite · N = para automáticamente al llegar a N
};
```

| Parámetro | Descripción | Ejemplo |
|---|---|---|
| `CAMERA_ID` | Identificador único de la cámara | `CAM1`, `CAM-LOBBY-01` |
| `CAMERA_API_KEY` | API Key generada al registrar la cámara | `evideth_cam_abc123...` |
| `BACKEND_URL` | URL base del backend (sin barra final) | URL de Azure o `http://localhost:8000` |
| `MAX_SEGMENTS` | Nº de segmentos a grabar antes de parar | `0` = infinito, `5` = para tras 5 segmentos |

---

### 🚀 Paso 2 — Levantar el cliente

Desde la raíz del repositorio:

```bash
git pull
docker compose -f docker-compose.client.yml up
```

> Si ya existe un contenedor previo con el mismo nombre:
> ```bash
> docker rm -f evideth-client
> docker compose -f docker-compose.client.yml up
> ```

---

### 🎬 Paso 3 — Abrir el Live Viewer

Una vez el contenedor esté en marcha, abre el navegador y accede directamente a:

```
http://localhost:8080/pages/viewer/viewer.html
```

> ⚠️ La raíz `http://localhost:8080` no redirige automáticamente. Usa siempre la ruta completa indicada arriba.

---

### 🛠️ Paso 4 — Usar el Live Viewer

1. **Verifica la configuración** — la barra superior mostrará ✅ `Config loaded from client.config.js` si las credenciales están correctamente cargadas.
2. **Ajusta los parámetros** si necesitas cambiarlos en tiempo real (sin reiniciar Docker):
   - *Camera ID* y *API Key*
   - *Segment Duration*: 10s, 30s o 60s
   - *Nº Segments*: número de segmentos a registrar (vacío = sin límite)
   - *Simulate Tampering*: activa para que algunos segmentos se envíen con un hash alterado (modo demo/testing de detección de manipulación)
3. **Pulsa START STREAMING** — el cliente:
   - Crea un registro de video en el backend (`POST /api/v1/cameras/videos`) — solo metadatos, sin fichero
   - Cada N segundos genera un hash SHA-256 del frame simulado y lo envía (`POST /api/v1/cameras/segments`)
   - Para automáticamente si se alcanza el límite de segmentos
   - Cierra el registro de video en el backend al parar (`PATCH /api/v1/cameras/videos/{id}/finish`)
4. **Consulta el Forensic Log** — panel derecho con todos los eventos timestampeados.
5. **Pulsa VERIFY ALL** (tras parar) para re-verificar los hashes almacenados contra los del backend.

---

### 🔗 Flujo de Comunicación con el Backend

```
[CLIENTE] START STREAMING
    │
    ├─► POST /api/v1/cameras/videos
    │       { filename: "camera_CAM1_2026-06-02T...mp4" }   ← solo nombre, sin fichero
    │   ◄── { id: "3f7a1c2d-..." }  ← video_id
    │
    │   (cada N segundos)
    ├─► POST /api/v1/cameras/segments
    │       { video_id, segment_index, start_time_secs,
    │         end_time_secs, sha256_hash }                  ← solo hash, sin vídeo
    │   ◄── { id, status: "PENDING" | "VALID" }
    │
    ├─► POST /api/v1/cameras/heartbeat   (al iniciar)
    │
[CLIENTE] STOP / límite alcanzado
    │
    └─► PATCH /api/v1/cameras/videos/{video_id}/finish
```

Todas las peticiones incluyen la cabecera `X-API-Key: <tu_api_key>` para autenticar la cámara. **Ningún fichero de vídeo se transmite en ningún punto de este flujo.**

---

### 🛠️ Conectar contra backend local (desarrollo)

Si tienes el backend corriendo en local (puerto 8000), cambia `BACKEND_URL` en `client.config.js`:

```js
BACKEND_URL: 'http://host.docker.internal:8000',
```

> En Linux usa `http://172.17.0.1:8000` si `host.docker.internal` no resuelve.

---

### ❗ Solución de Problemas Frecuentes

| Síntoma | Causa | Solución |
|---|---|---|
| Pantalla en blanco en `http://localhost:8080` | No hay redirección automática | Acceder directamente a `http://localhost:8080/pages/viewer/viewer.html` |
| `Config loaded but CAMERA_ID is empty` | `client.config.js` sin rellenar | Editar el fichero y refrescar el navegador |
| `Video creation failed: HTTP 401` | API Key incorrecta o caducada | Verificar la API Key en el panel de administración |
| `Video creation failed: HTTP 403` | Cámara inactiva | Activar la cámara desde el panel Admin |
| `Seg #N · Backend: 404` | `video_id` no válido o cámara no encontrada | Comprobar que la cámara existe y el `CAMERA_ID` es correcto |
| `Seg #N · Backend: 409` | Segmento duplicado (mismo índice ya registrado) | Pulsar **Reset** antes de iniciar una nueva sesión |
| `Heartbeat failed` | Backend no accesible desde Docker | Verificar `BACKEND_URL` y conectividad de red |
| Error de nombre de contenedor en uso | Contenedor previo sin eliminar | `docker rm -f evideth-client` |
