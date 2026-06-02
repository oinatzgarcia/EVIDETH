# Gestión de Identidades Segura en EVIDETH

Documentación del sistema de autenticación y autorización de EVIDETH.
Cubre la arquitectura de identidad, los mecanismos criptográficos,
el control de acceso por roles (RBAC) y las decisiones de diseño
referenciadas a estándares OWASP ASVS y NIST SP 800-57.

---

## Índice

1. [Arquitectura de identidad](#1-arquitectura-de-identidad)
2. [Identidad de usuarios — JWT](#2-identidad-de-usuarios--jwt)
3. [Identidad de cámaras — API Keys](#3-identidad-de-cámaras--api-keys)
4. [Control de acceso por roles (RBAC)](#4-control-de-acceso-por-roles-rbac)
5. [Revocación inmediata de acceso](#5-revocación-inmediata-de-acceso)
6. [Endpoints de autenticación](#6-endpoints-de-autenticación)
7. [Almacenamiento seguro de credenciales](#7-almacenamiento-seguro-de-credenciales)
8. [Configuración por entorno](#8-configuración-por-entorno)
9. [Decisiones de diseño y estándares](#9-decisiones-de-diseño-y-estándares)

---

## 1. Arquitectura de identidad

EVIDETH gestiona dos tipos de identidad diferenciados:

```
┌─────────────────────────────────────────────────────┐
│                  Clientes de la API                 │
│                                                     │
│   Usuarios (humanos)        Cámaras (dispositivos)  │
│   ─────────────────         ───────────────────────  │
│   JWT Bearer Token          API Key (X-API-Key)     │
│   Authorization header      Header personalizado    │
└──────────────┬──────────────────────┬───────────────┘
               │                      │
               ▼                      ▼
   ┌───────────────────┐   ┌──────────────────────┐
   │ get_current_user()│   │ get_current_camera() │
   │ dependencies.py   │   │ dependencies.py      │
   └───────────┬───────┘   └──────────┬───────────┘
               │                      │
               ▼                      ▼
   ┌───────────────────┐   ┌──────────────────────┐
   │ Tabla users (BD)  │   │ Tabla cameras (BD)   │
   │ is_active check   │   │ is_active check      │
   └───────────────────┘   └──────────────────────┘
```

La separación de identidad entre usuarios y cámaras responde al
**principio de menor privilegio** (NIST SP 800-53 AC-6): cada entidad
tiene exactamente los permisos necesarios para su función y ninguno más.

---

## 2. Identidad de usuarios — JWT

### Flujo de autenticación

```
Cliente                          EVIDETH API
  │                                   │
  │── POST /auth/login ──────────────►│
  │   {email, password}               │
  │                                   │── verify_password(bcrypt)
  │                                   │── comprobar is_active
  │                                   │── create_access_token()
  │◄── {access_token, token_type} ───│
  │                                   │
  │── GET /api/v1/cameras/ ──────────►│
  │   Authorization: Bearer <token>   │
  │                                   │── decode_token (HS256)
  │                                   │── comprobar is_active (BD)
  │◄── 200 OK ────────────────────── │
```

### Hash de contraseñas — bcrypt

Las contraseñas se almacenan **siempre hasheadas** con bcrypt,
nunca en texto claro:

```python
# app/core/security.py
import bcrypt as _bcrypt

def hash_password(password: str) -> str:
    return _bcrypt.hashpw(
        password.encode("utf-8"),
        _bcrypt.gensalt()          # salt aleatorio por contraseña
    ).decode("utf-8")

def verify_password(plain: str, hashed: str) -> bool:
    return _bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
```

**Por qué bcrypt** (OWASP ASVS §2.4.1):
- Función de derivación de clave con factor de coste adaptable
- Salt único por contraseña — protege contra ataques de rainbow table
- Resistente a hardware especializado (GPU) por diseño

### Estructura del JWT

```python
def create_access_token(data: dict, expires_delta=None) -> str:
    to_encode = data.copy()
    expire = datetime.now(UTC) + (
        expires_delta or timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire, "type": "access"})
    return jwt.encode(to_encode, settings.JWT_SECRET_KEY,
                      algorithm=settings.JWT_ALGORITHM)
```

Payload del JWT emitido en login:

```json
{
  "sub":  "3cc10625-8dfd-49a4-95ff-9e794ebe656a",
  "role": "admin",
  "exp":  1748707200,
  "type": "access"
}
```

| Campo | Descripción |
|---|---|
| `sub` | UUID del usuario (identificador único) |
| `role` | Rol del usuario (`admin` / `analyst`) |
| `exp` | Timestamp de expiración (Unix epoch) |
| `type` | Tipo de token (`access` / `refresh`) |

El campo `type` previene el uso de refresh tokens como access tokens
y viceversa — defensa en profundidad ante token confusion attacks.

### Renovación de token

```
POST /api/v1/auth/refresh
Authorization: Bearer <access_token_vigente>
→ {access_token: <nuevo_token>, token_type: "bearer"}
```

El endpoint `/auth/refresh` emite un nuevo token sin requerir
contraseña, usando el token actual como autenticación. Esto permite
sesiones largas sin almacenar contraseñas en el cliente.

---

## 3. Identidad de cámaras — API Keys

Las cámaras son entidades automáticas (no humanas) que no pueden
interactuar con un flujo de login interactivo. Se autentican mediante
**API Keys de larga duración** gestionadas por el sistema.

### Generación segura

```python
# app/core/security.py
import secrets

def generate_api_key() -> str:
    """Genera una API Key segura con el formato evideth_cam_<32 chars>."""
    chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    random_part = "".join(secrets.choice(chars) for _ in range(32))
    return f"evideth_cam_{random_part}"
```

- **`secrets.choice()`** — módulo de criptografía del sistema operativo
  (`/dev/urandom` en Linux), no `random` que es pseudoaleatorio.
- **Prefijo `evideth_cam_`** — permite identificar visualmente el tipo de
  clave y facilita la detección automática en secret scanning.
- **32 caracteres aleatorios** de un alfabeto de 62 símbolos →
  entropía = log₂(62³²) ≈ **190 bits** (muy por encima de los 128 bits
  mínimos recomendados por NIST SP 800-57).

### Almacenamiento hasheado

```python
import hashlib

def hash_api_key(api_key: str) -> str:
    """Hashea la API Key para almacenarla en BD (nunca en claro)."""
    return hashlib.sha256(api_key.encode()).hexdigest()

def verify_api_key(plain: str, hashed: str) -> bool:
    return hash_api_key(plain) == hashed
```

La API Key se entrega al administrador **una sola vez** al registrar
la cámara. La BD almacena únicamente el hash SHA-256 — si la BD queda
comprometida, las API Keys no son recuperables.

**Nota de diseño**: se usa SHA-256 en lugar de bcrypt porque la clave
tiene 190 bits de entropía aleatoria (no es una contraseña elegida por
humano). Con esta entropía, un ataque de fuerza bruta es computacionalmente
inviable aunque se disponga del hash, por lo que bcrypt no aportaría
beneficio de seguridad adicional pero sí latencia en cada request de cámara.

### Uso en peticiones

```http
POST /api/v1/cameras/segments
X-API-Key: evideth_cam_AbCdEfGh1234...
Content-Type: application/json
```

---

## 4. Control de acceso por roles (RBAC)

EVIDETH implementa RBAC de dos niveles mediante dependencias de FastAPI
inyectadas en cada endpoint.

### Roles definidos

```python
# app/db/models.py
class UserRole(str, enum.Enum):
    ADMIN   = "admin"
    ANALYST = "analyst"
```

### Dependencias de autorización

```python
# app/core/dependencies.py

def require_admin(current_user: User = Depends(get_current_user)) -> User:
    """Solo usuarios con rol ADMIN pueden acceder."""
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403,
                            detail="Acceso restringido a administradores")
    return current_user

def require_analyst(current_user: User = Depends(get_current_user)) -> User:
    """Usuarios con rol ANALYST o ADMIN pueden acceder."""
    if current_user.role not in (UserRole.ADMIN, UserRole.ANALYST):
        raise HTTPException(status_code=403,
                            detail="Acceso restringido a analistas y administradores")
    return current_user
```

### Matriz de permisos

| Recurso | Sin auth | ANALYST | ADMIN | Cámara |
|---|:---:|:---:|:---:|:---:|
| `GET /health` | ✅ | ✅ | ✅ | ✅ |
| `POST /auth/login` | ✅ | ✅ | ✅ | — |
| `GET /auth/me` | ❌ | ✅ | ✅ | — |
| `POST /auth/refresh` | ❌ | ✅ | ✅ | — |
| `GET /cameras/` | ❌ | ✅ | ✅ | — |
| `POST /cameras/` (registrar) | ❌ | ❌ | ✅ | — |
| `DELETE /cameras/:id` | ❌ | ❌ | ✅ | — |
| `POST /cameras/heartbeat` | — | — | — | ✅ |
| `POST /cameras/videos` | — | — | — | ✅ |
| `POST /cameras/segments` | — | — | — | ✅ |
| `GET /verification/` | ❌ | ✅ | ✅ | — |
| `GET /users/` | ❌ | ❌ | ✅ | — |
| `POST /users/` (crear) | ❌ | ❌ | ✅ | — |

---

## 5. Revocación inmediata de acceso

EVIDETH implementa **revocación inmediata** para ambos tipos de identidad,
sin necesidad de esperar a la expiración del token.

### Usuarios — comprobación `is_active` en cada petición

```python
# app/core/dependencies.py
def get_current_user(...) -> User:
    # ...validación JWT...
    user = db.query(User).filter(User.id == user_id).first()
    if not user.is_active:
        raise HTTPException(
            status_code=401,
            detail="Cuenta desactivada. Contacta con el administrador."
        )
    return user
```

Al desactivar un usuario (`is_active = False`), **todas sus sesiones
activas quedan bloqueadas inmediatamente** en la siguiente petición,
aunque el JWT no haya expirado. Esto cumple OWASP ASVS §3.3.

### Cámaras — revocación operacional de API Key

```python
# app/core/dependencies.py
def get_current_camera(...) -> Camera:
    # ...validación API Key...
    if not camera.is_active:
        raise HTTPException(
            status_code=401,
            detail="Cámara desactivada. API Key revocada operacionalmente."
        )
    return camera
```

La API Key sigue siendo criptográficamente válida tras la desactivación,
pero el sistema la rechaza operacionalmente. Sigue el principio de
**NIST SP 800-57**: las claves de entidades desactivadas deben considerarse
revocadas aunque no hayan expirado.

---

## 6. Endpoints de autenticación

### `POST /api/v1/auth/login`

Autentica un usuario con email y contraseña.

**Request:**
```json
{
  "email": "admin@evideth.com",
  "password": "Admin1234!"
}
```

**Response 200:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer"
}
```

**Errores:**
- `401` — Credenciales incorrectas (`login_failed`)
- `401` — Cuenta desactivada (`login_blocked_inactive`)

**Eventos de seguridad registrados** (→ App Insights + Log Analytics):

| Evento | Nivel | Campos |
|---|---|---|
| `login_failed` | WARNING | `ip`, `detail` (email) |
| `login_blocked_inactive` | WARNING | `ip`, `user_id`, `detail` |
| `login_ok` | INFO | `ip`, `user_id`, `detail` (role) |

---

### `GET /api/v1/auth/me`

Devuelve el perfil del usuario autenticado.

**Headers:** `Authorization: Bearer <token>`

**Response 200:**
```json
{
  "id": "3cc10625-8dfd-49a4-95ff-9e794ebe656a",
  "email": "admin@evideth.com",
  "full_name": "Admin EVIDETH",
  "role": "admin",
  "is_active": true,
  "created_at": "2026-05-06T15:48:19Z"
}
```

---

### `POST /api/v1/auth/refresh`

Renueva el JWT sin solicitar contraseña.

**Headers:** `Authorization: Bearer <token_vigente>`

**Response 200:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer"
}
```

**Evento registrado:** `token_refreshed` (INFO, `user_id`)

---

## 7. Almacenamiento seguro de credenciales

| Credencial | Almacenamiento en BD | Recuperable |
|---|---|---|
| Contraseña de usuario | bcrypt hash (salt único) | No |
| API Key de cámara | SHA-256 hex | No |
| JWT Secret Key | Variable de entorno / Azure Key Vault | Solo en runtime |

**Regla fundamental**: ninguna credencial en texto claro en la BD,
logs, ni en el código fuente. Los secrets se gestionan como variables
de entorno en Azure Container Apps y en GitHub Actions Secrets.

---

## 8. Configuración por entorno

```bash
# .env.example

# JWT
JWT_SECRET_KEY="cambiar-en-produccion-minimo-32-chars"
JWT_ALGORITHM="HS256"
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=30
JWT_REFRESH_TOKEN_EXPIRE_DAYS=7
```

| Variable | Descripción | Recomendación |
|---|---|---|
| `JWT_SECRET_KEY` | Clave HMAC para firmar tokens | Mínimo 256 bits de entropía, rotación periódica |
| `JWT_ALGORITHM` | Algoritmo de firma | `HS256` (simétrico) — suficiente para arquitectura centralizada |
| `JWT_ACCESS_TOKEN_EXPIRE_MINUTES` | Vida del access token | 30 min en producción |
| `JWT_REFRESH_TOKEN_EXPIRE_DAYS` | Vida del refresh token | 7 días en producción |

En producción, `JWT_SECRET_KEY` se almacena como **secret** en
Azure Container Apps (no como variable de entorno plana) y se
referencia desde la configuración del Container App.

---

## 9. Decisiones de diseño y estándares

### Resumen de decisiones

| Decisión | Alternativa considerada | Justificación |
|---|---|---|
| bcrypt para contraseñas | Argon2id, scrypt | bcrypt disponible en stdlib de Python, ampliamente auditado, OWASP recomendado |
| SHA-256 para API Keys | bcrypt, HMAC | 190 bits de entropía aleatoria — fuerza bruta inviable sin coste de bcrypt |
| HS256 para JWT | RS256 (asimétrico) | Arquitectura centralizada de un solo servicio — HS256 suficiente y más simple |
| `is_active` en cada petición | Blacklist de tokens | Sin estado adicional, revocación instantánea, más simple |
| Prefijo `evideth_cam_` en API Keys | Sin prefijo | Facilita secret scanning automático y detección visual |

### Estándares aplicados

| Estándar | Sección | Aplicación en EVIDETH |
|---|---|---|
| **OWASP ASVS v4.0** | §2.4.1 | bcrypt para hash de contraseñas |
| **OWASP ASVS v4.0** | §3.3 | Verificación de `is_active` en cada petición |
| **OWASP ASVS v4.0** | §6.2 | API Keys almacenadas hasheadas |
| **NIST SP 800-57** | Part 1 §5.3 | Revocación operacional de claves de cámaras desactivadas |
| **NIST SP 800-53** | AC-6 | Principio de menor privilegio en RBAC |
| **RFC 7519** | §4.1 | Claims estándar JWT (`sub`, `exp`) + claim privado `type` |
