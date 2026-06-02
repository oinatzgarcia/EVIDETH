# Seguridad de Datos y Credenciales en EVIDETH

Documentación del modelo de seguridad aplicado al almacenamiento de datos
y la gestión de credenciales en EVIDETH. Cubre el cifrado en reposo,
la protección de secretos, la validación de credenciales y las decisiones
de diseño referenciadas a estándares OWASP ASVS y NIST.

---

## Índice

1. [Modelo de amenazas](#1-modelo-de-amenazas)
2. [Cifrado en reposo — Azure TDE](#2-cifrado-en-reposo--azure-tde)
3. [Protección de credenciales en BD](#3-protección-de-credenciales-en-bd)
4. [Gestión de secretos de aplicación](#4-gestión-de-secretos-de-aplicación)
5. [Validación de credenciales débiles](#5-validación-de-credenciales-débiles)
6. [Secretos en infraestructura Azure](#6-secretos-en-infraestructura-azure)
7. [Datos sensibles por tabla](#7-datos-sensibles-por-tabla)
8. [Decisiones de diseño y estándares](#8-decisiones-de-diseño-y-estándares)

---

## 1. Modelo de amenazas

Las amenazas relevantes para el almacenamiento de datos en EVIDETH son:

| Amenaza | Vector | Mitigación |
|---|---|---|
| Robo de ficheros de BD | Acceso físico / backup comprometido | Cifrado en reposo TDE (AES-256) |
| Volcado de tabla `users` | SQL injection / acceso directo BD | Contraseñas hasheadas con bcrypt |
| Reutilización de API Keys robadas | Dump de tabla `cameras` | API Keys almacenadas como SHA-256 |
| Secretos en código fuente | Acceso al repositorio | Variables de entorno + Azure Secrets |
| Despliegue con credenciales débiles | Error operacional | Validación en startup de la aplicación |
| Credenciales en logs | Misconfiguración de logging | Logger JSON nunca registra passwords |

---

## 2. Cifrado en reposo — Azure TDE

### Transparent Data Encryption (TDE)

Azure Database for PostgreSQL activa **TDE (AES-256) automáticamente**
en todos los servicios, sin configuración adicional por parte del desarrollador:

```
┌──────────────────────────┐
│    EVIDETH Backend      │
│    (Container App)     │
└────────────┬────────────┘
             │ TLS 1.2+
             ▼
┌──────────────────────────┐
│  Azure PostgreSQL       │
│  ┌──────────────────┐  │
│  │  Datos en claro    │  │  ← Sólo visible en memoria
│  └───────┬──────────┘  │
│          │ AES-256 TDE   │
│          ▼               │
│  ┌──────────────────┐  │
│  │  Datos cifrados    │  │  ← Lo que se escribe en disco
│  └──────────────────┘  │
└──────────────────────────┘
```

**Alcance de la protección TDE:**
- Ficheros de datos en disco (`.pgdata`)
- Ficheros de log de PostgreSQL
- Backups automáticos de Azure
- Snapshots y réplicas de lectura

**Qué NO cubre TDE:**
- Datos en memoria durante el procesamiento (por diseño — ninguna BD lo hace)
- Tráfico de red entre app y BD (cubierto por TLS 1.2+ independientemente)

### Cifrado en tránsito

Todas las conexiones a Azure PostgreSQL usan **TLS 1.2 mínimo** forzado
por la configuración del servidor. La `DATABASE_URL` en producción incluye
`?sslmode=require` para rechazar conexiones no cifradas.

---

## 3. Protección de credenciales en BD

### Contraseñas de usuario — bcrypt

```python
# app/core/security.py
import bcrypt

def hash_password(password: str) -> str:
    return bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt()       # salt único por contraseña
    ).decode("utf-8")
```

Lo que se almacena en `users.password`:

```
$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LedYQj4V2pW5A1Kmy
 └─┘└──────────────────────────────────┘
 alg  salt (22 chars)  +  hash (31 chars)
```

- El **salt es único** por cada contraseña — dos usuarios con la misma
  contraseña tienen hashes completamente distintos.
- **Imposible revertir** el hash para obtener la contraseña original.
- Si la tabla `users` queda expuesta, las contraseñas siguen protegidas.

### API Keys de cámaras — SHA-256

```python
# app/core/security.py
import hashlib

def hash_api_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode()).hexdigest()
```

Lo que se almacena en `cameras.api_key`:

```
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
└────────────────────────────────────────────────────────────────┘
                    64 chars hex (SHA-256)
```

La API Key en texto claro (`evideth_cam_AbCd...`) se entrega al administrador
**una única vez** al registrar la cámara. El sistema no la almacena ni la
puede recuperar después.

### Resumen de almacenamiento por campo sensible

| Tabla | Campo | Almacenamiento | Recuperable |
|---|---|---|---|
| `users` | `password` | bcrypt hash (salt único) | No |
| `cameras` | `api_key` | SHA-256 hex | No |
| `cameras` | `public_key_pem` | Texto claro (es pública) | Sí (intencional) |
| `segments` | `sha256_hash` | Hash SHA-256 (no es secreto) | Sí (intencional) |
| `segments` | `ecdsa_signature` | Texto claro (verificable públicamente) | Sí (intencional) |

---

## 4. Gestión de secretos de aplicación

### Principio: ninguna credencial en código fuente

Todos los secretos se gestionan como **variables de entorno**, nunca
hardcodeados en el código ni en ficheros versionados:

```python
# app/config.py — valores por defecto solo para desarrollo local
class Settings(BaseSettings):
    JWT_SECRET_KEY: str = "dev-fallback-change-in-production"
    DATABASE_URL: str = "postgresql://evideth:evideth@localhost:5432/evideth"
    AZURE_CLIENT_SECRET: str = ""
    # ...
    model_config = ConfigDict(env_file=".env", ...)
```

El fichero `.env` está en `.gitignore` — nunca se versiona.

### Jerarquía de secretos por entorno

| Entorno | Dónde se configuran los secretos |
|---|---|
| **Local / dev** | Fichero `.env` (no versionado) |
| **CI (GitHub Actions)** | GitHub Actions Secrets (`${{ secrets.* }}`) |
| **Producción (Azure)** | Azure Container Apps → Secrets + env vars referenciadas |

---

## 5. Validación de credenciales débiles

EVIDETH valida en **startup** que las credenciales no sean débiles
cuando `APP_ENV=production`. Si la validación falla, la aplicación
**no arranca** (`ValueError` en `Settings()`).

### Validación de `JWT_SECRET_KEY`

```python
# app/config.py
@field_validator("JWT_SECRET_KEY")
@classmethod
def validate_jwt_secret(cls, v: str) -> str:
    weak_defaults = {
        "dev-fallback-change-in-production",
        "secret", "changeme", "password",
    }
    if os.getenv("APP_ENV", "development") == "production":
        if v in weak_defaults:
            raise ValueError("JWT_SECRET_KEY usa un valor por defecto inseguro...")
        if len(v) < 32:
            raise ValueError(f"JWT_SECRET_KEY demasiado corta ({len(v)} chars)...")
    return v
```

Requisitos en producción (OWASP ASVS §3.5.2, NIST SP 800-107):
- No puede ser ninguno de los valores por defecto conocidos
- Mínimo **32 caracteres** (256 bits de clave HMAC)

### Validación de `DATABASE_URL`

```python
@field_validator("DATABASE_URL")
@classmethod
def validate_db_url(cls, v: str) -> str:
    weak_passwords = {
        ":evideth@", ":password@", ":changeme@",
        ":secret@", ":1234@", ":admin@",
    }
    if os.getenv("APP_ENV", "development") == "production":
        for weak in weak_passwords:
            if weak in v:
                raise ValueError(f"DATABASE_URL contiene contraseña débil...")
    return v
```

### Comportamiento por entorno

| `APP_ENV` | Validación activa | Efecto si falla |
|---|---|---|
| `development` (default) | No | Arranca con defaults — útil para desarrollo local |
| `test` | No | Arranca con SQLite in-memory para tests |
| `production` | Sí | La aplicación no arranca |

---

## 6. Secretos en infraestructura Azure

### Azure Container Apps — Secrets

En producción, los secretos se configuran como **Secrets** del Container App
(no como variables de entorno planas), y se referencian en la configuración:

```bash
# Crear secret en Azure Container App
az containerapp secret set \
  --name evideth-dev-backend \
  --resource-group evideth-dev-rg \
  --secrets jwt-secret-key="$(openssl rand -base64 48)"

# Referenciar el secret como env var
az containerapp update \
  --name evideth-dev-backend \
  --resource-group evideth-dev-rg \
  --set-env-vars JWT_SECRET_KEY=secretref:jwt-secret-key
```

Con este mecanismo:
- El valor del secret **no aparece** en los logs de deployment
- **No es visible** en el portal de Azure como texto plano
- Solo está disponible como variable de entorno en el contenedor en runtime

### GitHub Actions Secrets

Las credenciales usadas en CI/CD se configuran como GitHub Secrets
(`Settings > Secrets and variables > Actions`) y se referencian en el
workflow como `${{ secrets.NOMBRE_SECRET }}` — nunca aparecen en los
logs aunque se intente hacer `echo`.

---

## 7. Datos sensibles por tabla

Analizando cada tabla del modelo de datos:

### `users`

| Campo | Sensibilidad | Protección |
|---|---|---|
| `email` | Media (PII) | TDE en disco |
| `password` | Alta | bcrypt hash — irreversible |
| `full_name` | Media (PII) | TDE en disco |
| `role` | Baja | TDE en disco |

### `cameras`

| Campo | Sensibilidad | Protección |
|---|---|---|
| `api_key` | Alta | SHA-256 hash — irreversible |
| `public_key_pem` | Nula (pública) | Texto claro (correcto) |
| `location` | Baja | TDE en disco |

### `segments`

| Campo | Sensibilidad | Protección |
|---|---|---|
| `sha256_hash` | Nula (hash público) | Texto claro (correcto) |
| `ecdsa_signature` | Baja (verificable) | Texto claro (correcto) |
| `frame_thumbnails` | Media (imágenes) | TDE en disco |

### `verifications`

| Campo | Sensibilidad | Protección |
|---|---|---|
| `ip_address` | Media (PII) | TDE en disco |
| `user_agent` | Baja | TDE en disco |
| `computed_hash` | Nula | Texto claro (correcto) |

---

## 8. Decisiones de diseño y estándares

### Por qué TDE en lugar de cifrado por columna

El cifrado a nivel de columna (p.ej. con `pgcrypto`) añade complejidad
operacional significativa: gestión de claves de cifrado por columna,
impacto en rendimiento de búsquedas indexadas, y mayor superficie de error.

Para EVIDETH, la amenaza principal es el **robo de ficheros de BD**
(backups, snapshots), que TDE cubre completamente. El cifrado por columna
aportaría protección adicional solo frente a un atacante con acceso SQL
directo a la BD — escenario cubierto por otros controles (RBAC, red privada
de Azure, firewall de PostgreSQL).

### Resumen de estándares aplicados

| Estándar | Sección | Aplicación en EVIDETH |
|---|---|---|
| **OWASP ASVS v4.0** | §2.4.1 | bcrypt para hash de contraseñas |
| **OWASP ASVS v4.0** | §2.1 | Validación de credenciales débiles en startup |
| **OWASP ASVS v4.0** | §3.5.2 | JWT Secret Key mínimo 256 bits |
| **OWASP ASVS v4.0** | §6.2.1 | AES-256 para cifrado en reposo (vía Azure TDE) |
| **NIST SP 800-107** | §4 | Longitud mínima de clave HMAC (256 bits) |
| **NIST SP 800-57** | Part 1 | Gestión del ciclo de vida de claves y secretos |
| **GDPR Art. 32** | §1(a) | Medidas técnicas apropiadas para protección de PII |
