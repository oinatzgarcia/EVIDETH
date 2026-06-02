# Tests de Integración — EVIDETH

## Índice

1. [Propósito](#propósito)
2. [Arquitectura de los tests](#arquitectura-de-los-tests)
3. [Infraestructura de test](#infraestructura-de-test)
4. [Fixtures](#fixtures)
5. [Suites de tests](#suites-de-tests)
   - [TestHealth](#testhealth)
   - [TestAuth](#testauth)
   - [TestRBAC](#testrbac)
   - [TestCameras](#testcameras)
   - [TestSegments](#testsegments)
6. [Ejecución](#ejecución)
7. [Cobertura y decisiones de diseño](#cobertura-y-decisiones-de-diseño)

---

## Propósito

Los tests de integración de EVIDETH verifican que los flujos completos de la API REST funcionan
correctamente de extremo a extremo: desde la petición HTTP hasta la persistencia en base de datos,
pasando por autenticación, autorización y lógica de negocio.

A diferencia de los tests unitarios, que aíslan funciones individuales con mocks, estos tests
levantan la aplicación FastAPI completa y la conectan a una base de datos SQLite local, simulando
un entorno de ejecución real sin dependencias externas (PostgreSQL, Azure).

**Principios forenses que verifican:**

- **Integridad**: los hashes SHA-256 de los segmentos se almacenan y devuelven sin modificación.
- **Inmutabilidad**: ningún segmento puede sobrescribirse una vez registrado (HTTP 409).
- **Autenticidad**: las firmas ECDSA y las API Keys se validan antes de aceptar cualquier dato.
- **Trazabilidad**: cada segmento, cámara y acción queda registrado con su autoría.

---

## Arquitectura de los tests

```
tests/integration/
└── test_api.py          # Suite completa de integración REST
```

La suite se organiza en cinco clases de test que siguen el flujo natural del sistema:

```
TestHealth → TestAuth → TestRBAC → TestCameras → TestSegments
```

Cada clase es independiente entre sí, pero comparte fixtures de `scope="module"` para evitar
recrear usuarios y cámaras en cada test.

---

## Infraestructura de test

### Base de datos SQLite

En lugar de PostgreSQL, los tests usan una base de datos SQLite temporal:

```python
SQLITE_URL = "sqlite:///./test_integration.db"

engine_test = create_engine(
    SQLITE_URL,
    connect_args={"check_same_thread": False},
)
```

SQLite es suficiente para verificar la lógica de la API porque:

- El ORM (SQLAlchemy) abstrae las diferencias entre motores.
- El esquema se crea idéntico al de producción mediante `Base.metadata.create_all()`.
- No requiere infraestructura externa, por lo que los tests corren en CI/CD sin configuración adicional.

> **Limitación conocida**: SQLite no replica el comportamiento de PostgreSQL en restricciones
> avanzadas (ej. tipos `ARRAY`, `JSONB`). Para validar esos casos específicos se usan tests
> unitarios con mocks o un entorno de staging con PostgreSQL real.

### Override de dependencias

FastAPI permite reemplazar dependencias en tiempo de test sin tocar el código de producción:

```python
app.dependency_overrides[get_db] = override_get_db
```

Esto garantiza que todos los endpoints usen la BD de test en lugar de la de producción,
manteniendo el aislamiento total.

### Variables de entorno requeridas

Los tests requieren las siguientes variables para que `app.config.Settings()` no falle:

```bash
SECRET_KEY=<cualquier-valor>
DATABASE_URL=sqlite:///./test_integration.db
JWT_SECRET_KEY=<cualquier-valor>
```

En desarrollo local se pueden pasar inline:

```bash
SECRET_KEY=test DATABASE_URL=sqlite:///./test_integration.db JWT_SECRET_KEY=test \
python -m pytest tests/integration/test_api.py -v
```

En CI/CD (GitHub Actions) se definen como `env` en el step del workflow.

---

## Fixtures

Las fixtures de `scope="module"` se crean una vez por módulo y se reutilizan en todos los tests,
evitando operaciones costosas (creación de usuarios, login, registro de cámaras) en cada test individual.

| Fixture | Scope | Descripción |
|---|---|---|
| `setup_db` | module | Crea y destruye las tablas SQLite antes/después del módulo |
| `client` | module | `TestClient` de FastAPI (HTTPX) |
| `db_session` | module | Sesión SQLAlchemy directa para insertar datos de prueba |
| `admin_user` | module | Usuario con rol `ADMIN` insertado en BD |
| `analyst_user` | module | Usuario con rol `ANALYST` insertado en BD |
| `admin_token` | module | JWT de acceso obtenido mediante login del admin |
| `analyst_token` | module | JWT de acceso obtenido mediante login del analyst |
| `registered_camera` | module | Cámara registrada por el admin; devuelve `{camera_id, api_key}` |
| `active_video_id` | module | Video iniciado con la cámara registrada; devuelve el `id` del video |

### Credenciales de test

| Usuario | Email | Contraseña | Rol |
|---|---|---|---|
| Admin | `admin@evideth.com` | `Admin1234!` | `ADMIN` |
| Analyst | `analyst@evideth.com` | `Analyst1234!` | `ANALYST` |

---

## Suites de tests

### TestHealth

Verifica que el servidor arranca correctamente y el endpoint de health check responde.

| Test | Método | Endpoint | Esperado | Qué verifica |
|---|---|---|---|---|
| `test_health_returns_200` | GET | `/api/v1/health` | 200 + `status: healthy` | Arranque del servidor y disponibilidad del probe de Azure |

---

### TestAuth

Cubre el ciclo completo de autenticación JWT: login, obtención de tokens y acceso a rutas protegidas.

| Test | Método | Endpoint | Esperado | Qué verifica |
|---|---|---|---|---|
| `test_login_admin_returns_jwt` | POST | `/api/v1/auth/login` | 200 + `access_token` + `refresh_token` | Flujo completo de login; el rol devuelto es `admin` |
| `test_login_wrong_password_returns_401` | POST | `/api/v1/auth/login` | 401 | Rechazo de credenciales incorrectas sin revelar si el usuario existe |
| `test_me_with_valid_token` | GET | `/api/v1/auth/me` | 200 + perfil del usuario | Decodificación correcta del JWT y resolución del usuario en BD |
| `test_me_without_token_returns_401` | GET | `/api/v1/auth/me` | 401 | Protección de endpoints autenticados |
| `test_me_with_invalid_token_returns_401` | GET | `/api/v1/auth/me` | 401 | Rechazo de tokens malformados |

**Nota sobre seguridad**: `test_login_wrong_password_returns_401` verifica que el mensaje de error
es genérico ("credenciales inválidas"), no revelando si el email existe. Esto previene
ataques de enumeración de usuarios ([OWASP - Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)).

---

### TestRBAC

Verifica el control de acceso basado en roles (Role-Based Access Control). Garantiza que cada
rol solo puede ejecutar las operaciones para las que está autorizado.

| Test | Rol | Método | Endpoint | Esperado | Qué verifica |
|---|---|---|---|---|---|
| `test_analyst_cannot_register_camera` | ANALYST | POST | `/api/v1/cameras/` | 403 | Solo ADMIN puede registrar cámaras |
| `test_analyst_can_list_cameras` | ANALYST | GET | `/api/v1/cameras/` | 200 | ANALYST tiene acceso de lectura |
| `test_unauthenticated_cannot_list_cameras` | — | GET | `/api/v1/cameras/` | 401 | Ningún endpoint de datos es público |

**Matriz de permisos del sistema:**

| Operación | ADMIN | ANALYST |
|---|---|---|
| Registrar cámara | ✅ | ❌ |
| Listar cámaras | ✅ | ✅ |
| Ver detalle de cámara | ✅ | ✅ |
| Ver segmentos | ✅ | ✅ |
| Iniciar verificación | ✅ | ✅ |
| Gestionar usuarios | ✅ | ❌ |

---

### TestCameras

Cubre el ciclo de vida de una cámara: registro, consulta, heartbeat y detección de duplicados.

| Test | Método | Endpoint | Esperado | Qué verifica |
|---|---|---|---|---|
| `test_admin_registers_camera` | POST | `/api/v1/cameras/` | 201 + `api_key` en claro | La API Key solo se devuelve en el momento del registro (nunca más) |
| `test_duplicate_camera_id_returns_400` | POST | `/api/v1/cameras/` | 400 | Unicidad del `camera_id` |
| `test_get_camera_by_id` | GET | `/api/v1/cameras/{id}` | 200 + metadata correcta | Persistencia de campos (`location`, `name`, etc.) |
| `test_camera_heartbeat_with_api_key` | POST | `/api/v1/cameras/heartbeat` | 200 + `status: ok` | Autenticación por API Key y actualización de `last_seen` |
| `test_heartbeat_with_invalid_api_key_returns_401` | POST | `/api/v1/cameras/heartbeat` | 401 | Las API Keys se validan contra su hash SHA-256 almacenado |

**Modelo de seguridad de API Keys:**

```
Registro      → API Key generada en claro → devuelta al admin UNA VEZ
               → hash SHA-256 almacenado en BD (nunca el valor en claro)

Autenticación → cámara envía API Key en X-API-Key header
               → sistema recalcula SHA-256 y compara con el hash en BD
               → si coincide → autenticada; si no → 401
```

---

### TestSegments

Verifica el flujo de captura forense de segmentos de video: registro de hashes, detección de
duplicados e inmutabilidad.

| Test | Método | Endpoint | Esperado | Qué verifica |
|---|---|---|---|---|
| `test_start_video_with_api_key` | POST | `/api/v1/cameras/videos` | 201 + `status: recording` | La cámara inicia una grabación autenticándose con API Key |
| `test_upload_segment_minimal` | POST | `/api/v1/cameras/segments` | 201 + `status: pending` | Registro de segmento sin firma ECDSA → estado PENDING (correcto) |
| `test_upload_duplicate_segment_returns_409` | POST | `/api/v1/cameras/segments` | 409 | Inmutabilidad: ningún segmento puede sobrescribirse |
| `test_invalid_sha256_format_returns_422` | POST | `/api/v1/cameras/segments` | 422 | Validación Pydantic: el hash debe ser exactamente 64 caracteres hex |

**Estados de un segmento:**

```
PENDING  → hash recibido, sin firma ECDSA (cámara sin clave registrada)
VALID    → hash + firma ECDSA verificada correctamente
INVALID  → firma ECDSA no verifica → posible manipulación
TAMPERED → hash no coincide con el video almacenado en Blob Storage
```

El test `test_upload_segment_minimal` verifica que `status == "pending"` cuando la cámara
no tiene clave pública ECDSA registrada — comportamiento correcto y esperado del sistema.

---

## Ejecución

### Suite completa

```bash
SECRET_KEY=test \
DATABASE_URL=sqlite:///./test_integration.db \
JWT_SECRET_KEY=test \
python -m pytest tests/integration/test_api.py -v
```

### Suite específica

```bash
# Solo autenticación
python -m pytest tests/integration/test_api.py::TestAuth -v

# Solo segmentos
python -m pytest tests/integration/test_api.py::TestSegments -v

# Un test concreto
python -m pytest tests/integration/test_api.py::TestCameras::test_camera_heartbeat_with_api_key -v
```

### Con reporte de cobertura

```bash
python -m pytest tests/integration/test_api.py -v --cov=app --cov-report=term-missing
```

### Resultado esperado

```
tests/integration/test_api.py::TestHealth::test_health_returns_200              PASSED
tests/integration/test_api.py::TestAuth::test_login_admin_returns_jwt           PASSED
tests/integration/test_api.py::TestAuth::test_login_wrong_password_returns_401  PASSED
tests/integration/test_api.py::TestAuth::test_me_with_valid_token               PASSED
tests/integration/test_api.py::TestAuth::test_me_without_token_returns_401      PASSED
tests/integration/test_api.py::TestAuth::test_me_with_invalid_token_returns_401 PASSED
tests/integration/test_api.py::TestRBAC::test_analyst_cannot_register_camera    PASSED
tests/integration/test_api.py::TestRBAC::test_analyst_can_list_cameras          PASSED
tests/integration/test_api.py::TestRBAC::test_unauthenticated_cannot_list_cameras PASSED
tests/integration/test_api.py::TestCameras::test_admin_registers_camera         PASSED
tests/integration/test_api.py::TestCameras::test_duplicate_camera_id_returns_400 PASSED
tests/integration/test_api.py::TestCameras::test_get_camera_by_id              PASSED
tests/integration/test_api.py::TestCameras::test_camera_heartbeat_with_api_key  PASSED
tests/integration/test_api.py::TestCameras::test_heartbeat_with_invalid_api_key_returns_401 PASSED
tests/integration/test_api.py::TestSegments::test_start_video_with_api_key     PASSED
tests/integration/test_api.py::TestSegments::test_upload_segment_minimal        PASSED
tests/integration/test_api.py::TestSegments::test_upload_duplicate_segment_returns_409 PASSED
tests/integration/test_api.py::TestSegments::test_invalid_sha256_format_returns_422 PASSED

======================== 18 passed in X.XXs =========================
```

---

## Cobertura y decisiones de diseño

### Qué cubren estos tests

- **Flujos felices** (happy path): login correcto, registro de cámara, subida de segmento.
- **Flujos de error esperados**: credenciales incorrectas, duplicados, tokens inválidos, hashes malformados.
- **Control de acceso**: todas las combinaciones relevantes de rol × operación.
- **Contratos de API**: códigos HTTP correctos (200, 201, 400, 401, 403, 409, 422).

### Qué NO cubren (y dónde está esa cobertura)

| Caso | Cobertura en |
|---|---|
| Verificación ECDSA completa | `tests/integration/test_ecdsa_e2e.py` |
| Verificación de video end-to-end | `tests/integration/test_verification_e2e.py` |
| Lógica de hash SHA-256 aislada | `tests/unit/test_hash_utils.py` |
| Formato y validación de API Keys | `tests/unit/test_api_key_format.py` |
| Lógica del verificador ECDSA | `tests/unit/test_verifier_ecdsa.py` |

### Decisión: SQLite vs PostgreSQL en tests

Se eligió SQLite porque:

1. **Sin dependencias externas**: los tests corren en cualquier máquina sin Docker ni servidor.
2. **Velocidad**: SQLite en memoria es ~10x más rápido que una conexión a PostgreSQL real.
3. **Suficiencia**: el 95% de la lógica de negocio es independiente del motor de BD.

Los tests que requieren características específicas de PostgreSQL (tipos avanzados, full-text search)
se ejecutan en el entorno de staging del pipeline CI/CD con un contenedor PostgreSQL real.
