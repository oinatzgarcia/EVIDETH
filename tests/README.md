# EVIDETH — Suite de Tests

Documentación de la estrategia de verificación automática del sistema EVIDETH.
Todos los tests se ejecutan sin infraestructura externa (sin PostgreSQL, sin Azure)
mediante un motor SQLite en memoria con `StaticPool`.

---

## Estructura

```
tests/
├── unit/                      # Tests de caja blanca — funciones puras
│   ├── test_hash_utils.py     # Validación y normalización de SHA-256
│   ├── test_api_key_format.py # Formato y entropía de las API Keys
│   └── test_verifier_ecdsa.py # Firma/verificación ECDSA P-256 (sin BD)
│
├── integration/               # Tests de caja negra — API HTTP completa
│   ├── test_api.py            # Endpoints CRUD: auth, cámaras, segmentos
│   ├── test_ecdsa_e2e.py      # Flujo ECDSA extremo a extremo vía API
│   └── test_verification_e2e.py # Motor de verificación forense
│
└── features/                  # Tests de escenario — flujos de negocio
    └── test_scenarios.py      # 5 escenarios E2E de la especificación
```

---

## Ejecución local

```bash
# Todos los tests
SECRET_KEY=test JWT_SECRET_KEY=test \
python -m pytest tests/ -v

# Solo una capa
python -m pytest tests/unit/       -v   # Rápido, sin BD
python -m pytest tests/integration/ -v  # API HTTP completa
python -m pytest tests/features/    -v  # Escenarios E2E

# Un escenario concreto
python -m pytest tests/features/test_scenarios.py::TestScenario3Rbac -v
```

> **Nota**: Los tests de escenario son secuenciales dentro de cada clase.
> Ejecutar un paso aislado (e.g. `::test_step4_...`) emitirá un `SKIP`
> indicando el prerequisito faltante — comportamiento esperado.

---

## Capa 1 — Tests Unitarios (`tests/unit/`)

Verifican funciones puras sin BD ni red. Se ejecutan en milisegundos.

| Fichero | Qué verifica | Estándar |
|---|---|---|
| `test_hash_utils.py` | SHA-256 bien formado (64 hex), rechazo de hashes truncados o con caracteres no-hex, normalización a minúsculas | NIST FIPS 180-4 |
| `test_api_key_format.py` | Longitud mínima de API Key (≥32 bytes), formato `hex` o `base64url`, unicidad estadística | OWASP ASVS §2.10 |
| `test_verifier_ecdsa.py` | Firma válida → verificación OK; firma con clave incorrecta → fallo; payload modificado → fallo; curva P-256 (secp256r1) | NIST SP 800-186, RFC 6979 |

---

## Capa 2 — Tests de Integración (`tests/integration/`)

Ejercitan la API HTTP completa (FastAPI + SQLAlchemy) con BD SQLite en memoria.
Cada módulo usa un fixture `client` de scope `module` con un engine independiente.

### `test_api.py`

Cubre los endpoints principales del sistema:

| Clase | Endpoints | Aspectos verificados |
|---|---|---|
| `TestHealth` | `GET /api/v1/health` | Disponibilidad del servicio |
| `TestAuth` | `POST /api/v1/auth/login` | JWT válido en credenciales correctas; 401 en incorrectas |
| `TestCameras` | `POST/GET/PATCH /api/v1/cameras/` | Registro, listado paginado, desactivación |
| `TestHeartbeat` | `POST /api/v1/cameras/heartbeat` | API Key válida → 200; inválida → 401; cámara inactiva → 401 |
| `TestVideos` | `POST /api/v1/cameras/videos` | Inicio de grabación; metadatos (fps, resolución) |
| `TestSegments` | `POST /api/v1/cameras/segments` | SHA-256 válido → 201; truncado → 422; no-hex → 422; duplicado → 409 |
| `TestUsers` | `POST/GET/DELETE /api/v1/users/` | CRUD de usuarios; protección RBAC |

### `test_ecdsa_e2e.py`

Verifica el ciclo completo de firma digital sobre segmentos de vídeo:

- Generación de par de claves ECDSA P-256 efímeras
- Firma de hash SHA-256 de un segmento de 30 segundos
- Verificación de la firma mediante clave pública
- Rechazo de firmas con hash manipulado (detección de tampering)
- Rechazo de firmas con clave pública incorrecta

### `test_verification_e2e.py`

Verifica el motor forense de integridad:

- Verificación de cadena completa de segmentos (hashes + firmas)
- Detección de segmento faltante en la secuencia
- Detección de hash alterado en segmento existente
- Consulta de rango temporal (start/end en segundos)
- Rechazo de rango temporal invertido (`start > end`)

---

## Capa 3 — Tests de Escenario (`tests/features/`)

Simulan flujos de usuario completos tal como los ejecutaría un operador real
de EVIDETH. Son los tests más cercanos a los requisitos funcionales de la tesis.

Cada escenario es una clase pytest con pasos numerados que comparten estado
mediante atributos de clase (`cls._campo`). Si un paso falla, los siguientes
se omiten con `pytest.skip` (no se propaga como `ERROR`).

### Escenario 1 — Ciclo de vida de una cámara

> *Una cámara se registra, opera y es desactivada por el administrador.*

| Paso | Acción | Resultado esperado |
|---|---|---|
| 1 | Admin registra cámara | 201 + `api_key` en respuesta |
| 2 | Cámara aparece en listado | 200 + `camera_id` presente |
| 3 | Cámara envía heartbeat | 200 |
| 4 | Admin desactiva cámara | 200 + `is_active: false` |
| 5 | Heartbeat tras desactivación | **401** — revocación inmediata |

**Garantía de seguridad**: la desactivación es instantánea. Una API Key
criptográficamente válida es rechazada si la cámara está inactiva
(NIST SP 800-57 §5.3.1 — revocación de credenciales).

### Escenario 2 — Flujo de captura forense

> *Una cámara graba un vídeo con tres segmentos y un analista los verifica.*

| Paso | Acción | Resultado esperado |
|---|---|---|
| 1 | Registrar cámara | 201 |
| 2 | Iniciar grabación de vídeo | 201 + `status: recording` |
| 3 | Subir 3 segmentos con SHA-256 | 201 × 3 |
| 4 | Analista consulta segmentos | 200 + `total: 3` + hashes coinciden |

**Garantía de integridad**: los hashes almacenados son idénticos a los
enviados por la cámara, sin transformación ni truncamiento.

### Escenario 3 — RBAC completo

> *Un analista forense opera con los permisos correctos y es revocado.*

| Paso | Acción | Resultado esperado |
|---|---|---|
| 1 | Admin crea analista | 201 + `role: analyst` |
| 2 | Analista hace login | 200 + `access_token` |
| 3 | Analista lee cámaras | 200 — operación permitida |
| 4 | Analista intenta eliminar usuario | **403** — operación prohibida |
| 5 | Admin desactiva analista | 200 + `is_active: false` |
| 6 | Analista desactivado opera | **401** — JWT válido pero usuario inactivo |

**Garantía de seguridad**: el sistema comprueba `is_active` en cada petición,
no solo en el momento del login. Un JWT vigente no garantiza acceso si el
usuario ha sido desactivado (OWASP ASVS §4.2, NIST SP 800-53 AC-2).

### Escenario 4 — Blindaje de integridad de datos

> *El sistema rechaza activamente datos forenses inválidos o duplicados.*

| Paso | Dato enviado | Resultado esperado |
|---|---|---|
| 1 | Setup cámara + vídeo | 201 |
| 2 | Hash truncado (32 chars) | **422** |
| 3 | Hash con caracteres no-hex | **422** |
| 4 | Hash SHA-256 válido | 201 |
| 5 | Mismo `segment_index` de nuevo | **409** — conflicto de duplicado |
| 6 | `start_time > end_time` | **422** |

### Escenario 5 — Aislamiento multi-cámara

> *Dos cámaras operan simultáneamente sin interferencia entre sus datos.*

| Paso | Acción | Resultado esperado |
|---|---|---|
| 1 | Registrar cámara A y B | 201 × 2 |
| 2 | Cada cámara inicia su propio vídeo | 201 × 2 |
| 3 | Cada cámara sube 2 segmentos propios | 201 × 4 |
| 4 | Cámara B intenta escribir en vídeo de A | **401/403/404** |
| 5 | Verificar conteos independientes | 2 segmentos por vídeo, sin mezcla |

**Garantía de aislamiento**: una API Key solo puede escribir en vídeos
inicializados por esa misma cámara. No existe path de escalada entre cámaras.

---

## Arquitectura de fixtures

```
scope="class"
    client ──► engine SQLite :memory: + StaticPool
               │   └── dependency_overrides[get_db] activo
               │
    admin_token(client) ──► crea User admin en la misma BD
                            devuelve JWT firmado
```

**¿Por qué SQLite con StaticPool y no PostgreSQL?**

SQLite en memoria con `StaticPool` garantiza que todas las conexiones
(fixture + app) comparten **exactamente el mismo objeto de conexión**.
Sin `StaticPool`, SQLite crearía una BD diferente por conexión y el
fixture vería una BD vacía distinta a la de la app.

La BD de producción (PostgreSQL en Azure) no es necesaria para los tests:
el `dependency_overrides` de FastAPI reemplaza `get_db` completamente.
Esto es una práctica estándar de testing en FastAPI (documentación oficial).

---

## Integración continua (GitHub Actions)

Los tests se ejecutan automáticamente en `.github/workflows/backend.yml`,
disparado por `ci.yml` cuando cambia cualquier fichero en `app/**` o `tests/**`.

```
push / PR a main o develop
        │
        ▼
   ci.yml — paths-filter
        │
        ├── tests/** ──► backend.yml
        │                   ├── Ruff lint
        │                   ├── Import check
        │                   ├── Alembic migrations
        │                   └── pytest tests/ -v
        │
        └── ci-success ◄── resultado agregado
```

En CI, `backend.yml` levanta un servicio PostgreSQL real (imagen `postgres:15`)
con `DATABASE_URL` en el entorno. Los tests de `features/` e `integration/`
usan el override SQLite y **no dependen** de ese PostgreSQL; los tests de
`unit/` no usan BD en absoluto. El servicio PostgreSQL solo es necesario para
la verificación de migraciones Alembic (`alembic upgrade head`).

---

## Referencias normativas

- **NIST FIPS 180-4** — Secure Hash Standard (SHA-256)
- **NIST SP 800-186** — Recommendations for Discrete Logarithm-Based Cryptography (ECDSA P-256)
- **NIST SP 800-53 AC-2** — Account Management (revocación inmediata)
- **NIST SP 800-57 §5.3.1** — Key Management (revocación de credenciales)
- **OWASP ASVS §2.10** — Service Authentication Requirements (API Keys)
- **OWASP ASVS §4.2** — Operation Level Access Control (Least Privilege)
- **RFC 6979** — Deterministic Usage of ECDSA
- **RFC 2606** — Reserved Top Level DNS Names (dominios `@example.com` en tests)
