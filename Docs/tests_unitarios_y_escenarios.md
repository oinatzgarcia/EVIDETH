# Tests Unitarios y Escenarios E2E — EVIDETH

## Índice

1. [Arquitectura de tests](#arquitectura-de-tests)
2. [Tests unitarios](#tests-unitarios)
   - [test_verifier_ecdsa.py](#test_verifier_ecdsapy)
   - [test_hash_utils.py](#test_hash_utilspy)
   - [test_api_key_format.py](#test_api_key_formatpy)
3. [Módulo `app/utils/crypto.py`](#módulo-apputilscryptopy)
4. [Escenarios E2E (Features)](#escenarios-e2e-features)
   - [Escenario 1 — Ciclo de vida de una cámara](#escenario-1--ciclo-de-vida-de-una-cámara)
   - [Escenario 2 — Captura forense completa](#escenario-2--captura-forense-completa)
   - [Escenario 3 — RBAC completo](#escenario-3--rbac-completo)
   - [Escenario 4 — Blindaje de integridad de datos](#escenario-4--blindaje-de-integridad-de-datos)
   - [Escenario 5 — Aislamiento multi-cámara](#escenario-5--aislamiento-multi-cámara)
5. [Ejecución](#ejecución)
6. [Pre-commit: tests automáticos antes de cada commit](#pre-commit-tests-automáticos-antes-de-cada-commit)

---

## Arquitectura de tests

```
tests/
├── unit/                          # Tests unitarios — sin BD, sin red
│   ├── test_verifier_ecdsa.py     # 9 tests — verificación ECDSA P-256
│   ├── test_hash_utils.py         # 10 tests — SHA-256 + Merkle root
│   └── test_api_key_format.py     # 15 tests — generación y validación de API Keys
│
├── features/                      # Escenarios E2E — flujos completos de sistema
│   └── test_scenarios.py          # 5 escenarios, 23 pasos ordenados
│
└── integration/                   # Tests de integración REST (ver tests_integracion.md)
    └── test_api.py
```

### Principio de separación de capas

| Tipo | BD | Red | Tiempo |  Cuándo se ejecuta |
|---|---|---|---|---|
| Unitarios | ❌ | ❌ | < 1 s | En cada `git commit` (pre-commit hook) |
| Escenarios E2E | SQLite (local) | ❌ | < 30 s | En cada `git push` (CI/CD) |
| Integración REST | SQLite (local) | ❌ | < 30 s | En cada `git push` (CI/CD) |

---

## Tests unitarios

Los tests unitarios verifican funciones individuales de forma completamente aislada.
No importan nada de `app.db` ni `app.config`, por lo que no requieren PostgreSQL,
psycopg2, ni variables de entorno.

### `test_verifier_ecdsa.py`

**Ruta:** `tests/unit/test_verifier_ecdsa.py`  
**Módulo bajo prueba:** `app/utils/crypto.py` → `verify_ecdsa_signature()`  
**Algoritmo verificado:** ECDSA P-256 con SHA-256 (NIST FIPS 186-5)

Esta suite valida el núcleo criptográfico de EVIDETH: la función que comprueba
que la firma digital de cada segmento fue producida por la cámara legítima.

| Test | Qué verifica |
|---|---|
| `test_valid_signature` | Firma válida con la misma clave → `True` |
| `test_invalid_signature_tampered_merkle` | Mismo par de claves pero Merkle root diferente → `False` (simula vídeo manipulado) |
| `test_wrong_key` | Firma de cámara A verificada con clave de cámara B → `False` (simula suplantación de identidad) |
| `test_urlsafe_padding_variants` | 20 firmas cubren todos los casos de padding base64url (longitud DER variable 70–72 bytes) |
| `test_tampered_signature_bytes` | Firma válida con último byte XOR-flipado → `False` (corrupción parcial) |
| `test_invalid_pem_returns_false` | PEM corrupto → `False` sin lanzar excepción |
| `test_empty_signature_returns_false` | Firma vacía → `False` |
| `test_empty_merkle_root_returns_false` | Merkle root vacío → `False` |
| `test_deterministic_for_same_inputs` | Misma entrada × 5 iteraciones → siempre `True` (determinismo) |

**Convención de firma en EVIDETH:**

```
datos firmados = bytes.fromhex(merkle_root_hex)   # 32 bytes raw
firma         = base64url( ECDSA-SHA256(datos) )  # DER encoding, sin padding
```

> Referencia: NIST FIPS 186-5, NIST SP 800-57 Part 1.

---

### `test_hash_utils.py`

**Ruta:** `tests/unit/test_hash_utils.py`  
**Módulo bajo prueba:** lógica SHA-256 y Merkle root del sistema  

Verifica las propiedades criptográficas del hashing de segmentos y del árbol Merkle
que garantizan la detección de manipulación a nivel de segundo de vídeo.

#### Suite `TestSha256Hash` (6 tests)

| Test | Qué verifica |
|---|---|
| `test_output_is_64_chars_hex` | SHA-256 produce exactamente 64 caracteres hexadecimales |
| `test_deterministic` | Mismo input → mismo hash (propiedad fundamental) |
| `test_different_inputs_differ` | Entradas distintas → hashes distintos (resistencia a colisiones) |
| `test_avalanche_effect` | Cambiar 1 carácter → más de 100 bits de diferencia en el hash (efecto avaláncha SHA-256) |
| `test_empty_bytes_has_known_hash` | Hash de `b""` coincide con el valor de referencia NIST: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `test_large_data` | Hashea 4 MB sin errores (equivale a ~30 s de vídeo comprimido) |

#### Suite `TestMerkleRootSimple` (4 tests)

| Test | Qué verifica |
|---|---|
| `test_single_hash_merkle` | Un solo hash → Merkle root de 64 chars válido |
| `test_merkle_order_matters` | El orden de los frames importa (no conmutativo) |
| `test_tampered_frame_changes_root` | Modificar el frame 5 de 10 → Merkle root completamente diferente |
| `test_identical_segments_differ_by_index` | Mismo contenido con índice diferente → hashes distintos |

**Por qué el efecto avaláncha es importante en forense:**  
Un manipulador que cambie 1 frame de un segmento de 30 segundos alterará el Merkle root
completo del segmento. No existe forma de modificar un frame sin que el hash cambie,
lo que garantiza la detección de manipulación a nivel de segundo.

---

### `test_api_key_format.py`

**Ruta:** `tests/unit/test_api_key_format.py`  
**Módulo bajo prueba:** generación y validación de API Keys de cámaras

Las cámaras se autentican mediante API Keys con el formato:
```
evideth_cam_<32 caracteres alfanuméricos>
```

El valor en claro solo se devuelve una vez al registrar la cámara.
En base de datos solo se almacena el hash SHA-256 de la clave.

#### Suite `TestApiKeyGeneration` (6 tests)

| Test | Qué verifica |
|---|---|
| `test_prefix_correct` | La clave empieza con `evideth_cam_` |
| `test_total_length` | Longitud total = 12 (prefijo) + 32 (parte aleatoria) = 44 chars |
| `test_only_alphanumeric_after_prefix` | Solo `[A-Za-z0-9]` en la parte aleatoria |
| `test_matches_regex_pattern` | 10 claves generadas cumplen el patrón regex `^evideth_cam_[A-Za-z0-9]{32}$` |
| `test_uniqueness` | 1000 claves generadas son todas distintas (entropía de `secrets` module) |
| `test_uses_secrets_module` | La distribución es no-determinista (criptográficamente segura) |

#### Suite `TestApiKeyValidation` (9 tests)

| Test | Input inválido | Código esperado |
|---|---|---|
| `test_valid_key_accepted` | Clave correcta | `True` |
| `test_empty_key_rejected` | `""` | `False` |
| `test_missing_prefix_rejected` | 32 chars sin prefijo | `False` |
| `test_wrong_prefix_rejected` | `api_cam_<32>` | `False` |
| `test_special_chars_rejected` | `evideth_cam_AbC123@#!!` | `False` |
| `test_too_short_rejected` | `evideth_cam_abc123` | `False` |
| `test_too_long_rejected` | `evideth_cam_` + 40 chars | `False` |
| `test_sql_injection_rejected` | `evideth_cam_' OR '1'='1` | `False` |
| `test_jwt_token_rejected` | Token JWT real | `False` |

> **Seguridad:** Los tests `test_sql_injection_rejected` y `test_jwt_token_rejected`
> garantizan que el validador de formato funciona como primera línea de defensa
> contra intentos de inyección, antes de que la clave llegue a la base de datos.
> (OWASP — Input Validation Cheat Sheet)

---

## Módulo `app/utils/crypto.py`

**Creado en el refactor del 26/05/2026** para resolver la dependencia circular
`test → verifier → models → session → psycopg2` que impedía ejecutar los tests
unitarios sin una base de datos PostgreSQL activa.

### Diseño

```
Antes:  test_verifier_ecdsa.py
            └── app/services/verifier.py       ← lógica de BD + criptografía mezcladas
                    └── app/db/models.py
                            └── app/db/session.py
                                    └── psycopg2  ← 💥 ModuleNotFoundError en pre-commit

Ahora:  test_verifier_ecdsa.py
            └── app/utils/crypto.py             ← criptografía pura, cero deps de BD ✅

        app/services/verifier.py
            └── app/utils/crypto.py             ← re-importa la función (backward compat)
```

### API pública

```python
from app.utils.crypto import verify_ecdsa_signature

result: bool = verify_ecdsa_signature(
    merkle_root    = "a3f9...",   # hex str de 64 chars
    signature_b64  = "MEUC...",   # base64url, sin padding
    public_key_pem = "-----BEGIN PUBLIC KEY-----\n...",
)
```

**Garantías de la función:**
- Nunca lanza excepción: cualquier error devuelve `False`.
- Sin efectos secundarios: no escribe en BD, no hace requests de red.
- Determinista: misma entrada → mismo resultado.
- Sin imports de `app.db`, `app.config` ni `app.services`.

---

## Escenarios E2E (Features)

**Ruta:** `tests/features/test_scenarios.py`  
**Infraestructura:** FastAPI TestClient + SQLite local (sin PostgreSQL)

Cada escenario es una clase de test con pasos numerados que se ejecutan en orden.
El estado entre pasos se comparte mediante atributos de clase (`cls._campo`).

```python
# Override de DB: los tests usan SQLite, no PostgreSQL
app.dependency_overrides[get_db] = override_get_db
```

### Escenario 1 — Ciclo de vida de una cámara

**Clase:** `TestScenario1CameraLifecycle`

Verifica que el sistema gestiona correctamente el ciclo completo de una cámara:
desde el registro hasta la revocación de acceso.

| Paso | Acción | Verificación |
|---|---|---|
| 1 | Admin registra cámara | 201 + API Key en texto claro (única vez) |
| 2 | Consultar listado | La cámara aparece en `GET /cameras/?is_active=True` |
| 3 | Heartbeat activo | 200 + `camera_id` correcto |
| 4 | Admin desactiva cámara | 200 + `is_active: false` |
| 5 | Heartbeat tras desactivación | 401 — API Key criptográficamente válida pero revocada |

> **Ref. NIST SP 800-57:** la revocación operacional de credenciales es instantánea.
> Una API Key desactivada no tiene período de gracia.

---

### Escenario 2 — Captura forense completa

**Clase:** `TestScenario2ForensicCaptureFlow`

Simula el flujo completo de una cámara que graba y un analista que inspecciona.

| Paso | Acción | Verificación |
|---|---|---|
| 1 | Admin registra cámara de captura | 201 |
| 2 | Cámara inicia grabación | 201 + `status: recording` + `id` del vídeo |
| 3 | Cámara sube 3 segmentos (0-30s, 30-60s, 60-90s) | Cada uno → 201 |
| 4 | Analista consulta segmentos del vídeo | 200 + `total: 3` + hashes coinciden exactamente |

**Garantías forenses verificadas:**
- Cobertura temporal continua: no hay huecos entre segmentos.
- Integridad de hashes: los SHA-256 enviados por la cámara = los almacenados en BD.
- Inmutabilidad: ningún segmento puede sobrescribirse (409 en duplicado).

---

### Escenario 3 — RBAC completo

**Clase:** `TestScenario3Rbac`

Ciclo de vida completo de un analista forense: creación, operación y revocación.

| Paso | Acción | Verificación |
|---|---|---|
| 1 | Admin crea analista vía API | 201 + `role: analyst` + `is_active: true` |
| 2 | Analista hace login | 200 + `access_token` válido |
| 3 | Analista lista cámaras | 200 (operación permitida para ANALYST) |
| 4 | Analista intenta eliminar usuario | 403 (operación solo de ADMIN) |
| 5 | Admin desactiva al analista | 200 + `is_active: false` |
| 6 | Analista desactivado intenta operar | 401 (aunque su JWT siga vigente) |

**Principio clave — revocación inmediata:**  
El sistema comprueba `is_active` en **cada petición**, no solo en el login.
Esto garantiza que un usuario comprometido pueda ser revocado al instante
sin esperar a que su JWT expire.

> Ref: OWASP ASVS §4.2 (Least Privilege), NIST SP 800-53 AC-2 (Account Management)

| Operación | ADMIN | ANALYST |
|---|---|---|
| Registrar cámara | ✅ | ❌ (403) |
| Listar / consultar cámaras | ✅ | ✅ |
| Ver segmentos de vídeo | ✅ | ✅ |
| Iniciar verificación | ✅ | ✅ |
| Gestionar usuarios | ✅ | ❌ (403) |

---

### Escenario 4 — Blindaje de integridad de datos

**Clase:** `TestScenario4DataIntegrityGuard`

Verifica que el API aplica múltiples capas de validación antes de persistir
cualquier dato forense. Solo entran datos íntegros.

| Paso | Input | HTTP esperado | Motivo |
|---|---|---|---|
| 2 | Hash de 32 chars (truncado) | 422 | SHA-256 debe tener exactamente 64 chars |
| 3 | Hash con caracteres `zzzz...` (no-hex) | 422 | Solo `[0-9a-f]` son válidos |
| 4 | Segmento completamente válido | 201 | Todos los campos correctos |
| 5 | Mismo `segment_index` por segunda vez | 409 | Inmutabilidad: no se puede sobrescribir |
| 6 | `end_time_secs` < `start_time_secs` | 422 | Rango temporal negativo rechazado por Pydantic |

**Por qué esto es importante en forense:**  
Un dato corrupto o manipulado que llegue a la BD contamina la cadena de custodia.
La validación a nivel de API (Pydantic) es la primera barrera; la restricción de
duplicados en BD (índice único sobre `video_id + segment_index`) es la segunda.

---

### Escenario 5 — Aislamiento multi-cámara

**Clase:** `TestScenario5MultiCamera`

Dos cámaras operan en paralelo y se verifica que sus datos no se mezclan ni
pueden acceder a los recursos de la otra.

| Paso | Acción | Verificación |
|---|---|---|
| 1 | Registrar cámara A y cámara B | 201 × 2 |
| 2 | Cada cámara inicia su propio vídeo | `video_id_A ≠ video_id_B` |
| 3 | Cada cámara sube 2 segmentos al **su** vídeo | 201 × 4 |
| 4 | Cámara B intenta escribir en vídeo de cámara A | 401 / 403 / 404 |
| 5 | Consultar conteo de segmentos por vídeo | Cada vídeo tiene exactamente 2 |

**Paso 4 — security through opacity:**  
Cuando la cámara B intenta acceder al vídeo de la cámara A, el sistema responde
404 (no 403), de modo que no revela la existencia del recurso ajeno.
Esto sigue el principio de RFC 7231 §6.5.4 y es más seguro que un 403 explícito.

> Ref: OWASP ASVS §4.2 (Least Privilege)

---

## Ejecución

### Tests unitarios (sin DB, sin variables de entorno)

```bash
# Todos los tests unitarios
python -m pytest tests/unit/ -v

# Por módulo
python -m pytest tests/unit/test_verifier_ecdsa.py -v
python -m pytest tests/unit/test_hash_utils.py -v
python -m pytest tests/unit/test_api_key_format.py -v
```

### Escenarios E2E

```bash
# Todos los escenarios
SECRET_KEY=test JWT_SECRET_KEY=test \
python -m pytest tests/features/test_scenarios.py -v

# Un escenario concreto
python -m pytest tests/features/test_scenarios.py::TestScenario3Rbac -v
```

### Resultado esperado — tests unitarios

```
tests/unit/test_verifier_ecdsa.py::TestVerifyEcdsaSignature::test_valid_signature               PASSED
tests/unit/test_verifier_ecdsa.py::TestVerifyEcdsaSignature::test_invalid_signature_tampered_merkle  PASSED
tests/unit/test_verifier_ecdsa.py::TestVerifyEcdsaSignature::test_wrong_key                     PASSED
tests/unit/test_verifier_ecdsa.py::TestVerifyEcdsaSignature::test_urlsafe_padding_variants      PASSED
tests/unit/test_verifier_ecdsa.py::TestVerifyEcdsaSignature::test_tampered_signature_bytes      PASSED
tests/unit/test_verifier_ecdsa.py::TestVerifyEcdsaSignature::test_invalid_pem_returns_false     PASSED
tests/unit/test_verifier_ecdsa.py::TestVerifyEcdsaSignature::test_empty_signature_returns_false PASSED
tests/unit/test_verifier_ecdsa.py::TestVerifyEcdsaSignature::test_empty_merkle_root_returns_false PASSED
tests/unit/test_verifier_ecdsa.py::TestVerifyEcdsaSignature::test_deterministic_for_same_inputs PASSED
tests/unit/test_hash_utils.py::TestSha256Hash::test_output_is_64_chars_hex                      PASSED
tests/unit/test_hash_utils.py::TestSha256Hash::test_deterministic                               PASSED
tests/unit/test_hash_utils.py::TestSha256Hash::test_different_inputs_differ                     PASSED
tests/unit/test_hash_utils.py::TestSha256Hash::test_avalanche_effect                            PASSED
tests/unit/test_hash_utils.py::TestSha256Hash::test_empty_bytes_has_known_hash                  PASSED
tests/unit/test_hash_utils.py::TestSha256Hash::test_large_data                                  PASSED
tests/unit/test_hash_utils.py::TestMerkleRootSimple::test_single_hash_merkle                    PASSED
tests/unit/test_hash_utils.py::TestMerkleRootSimple::test_merkle_order_matters                  PASSED
tests/unit/test_hash_utils.py::TestMerkleRootSimple::test_tampered_frame_changes_root           PASSED
tests/unit/test_hash_utils.py::TestMerkleRootSimple::test_identical_segments_differ_by_index    PASSED
tests/unit/test_api_key_format.py::TestApiKeyGeneration::test_prefix_correct                    PASSED
tests/unit/test_api_key_format.py::TestApiKeyGeneration::test_total_length                      PASSED
tests/unit/test_api_key_format.py::TestApiKeyGeneration::test_only_alphanumeric_after_prefix    PASSED
tests/unit/test_api_key_format.py::TestApiKeyGeneration::test_matches_regex_pattern             PASSED
tests/unit/test_api_key_format.py::TestApiKeyGeneration::test_uniqueness                        PASSED
tests/unit/test_api_key_format.py::TestApiKeyGeneration::test_uses_secrets_module               PASSED
======================== 25 passed in X.XXs =========================
```

---

## Pre-commit: tests automáticos antes de cada commit

El hook `unit-tests` del fichero `.pre-commit-config.yaml` ejecuta los 25 tests
unitarios automáticamente antes de cada `git commit`, usando el Python del venv
del proyecto para garantizar que las dependencias son las correctas.

```yaml
- id: unit-tests
  name: "🧪 Tests unitarios (pytest)"
  entry: >-
    env
    SECRET_KEY=pre-commit-dummy-not-a-real-secret
    DATABASE_URL=sqlite:///./test_precommit.db
    JWT_SECRET_KEY=pre-commit-dummy-not-a-real-secret
    USE_AZURE_KEY_VAULT=false
    ./venv/bin/python -m pytest tests/unit/ -v --tb=short -q
  language: system
  pass_filenames: false
  types: [python]
```

**Por qué `./venv/bin/python` y no `pytest` directamente:**  
El hook usa el Python del venv del proyecto (donde `httpx==0.27.0` está fijado),
evitando el `TypeError` que introduce `httpx>=0.28` al eliminar el argumento
`app=` del constructor de `httpx.Client` (usado internamente por `starlette.testclient`).

**Por qué SQLite y no PostgreSQL en el hook:**  
Los tests unitarios no necesitan BD. La variable `DATABASE_URL=sqlite:///...` es
un dummy que permite que `app.config.Settings()` cargue sin `.env` real, sin que
ningún test llegue a conectarse a ella.

### Pipeline completo en cada commit

```
✅ trailing-whitespace   → elimina espacios al final de línea
✅ end-of-file-fixer     → añade salto de línea al final
✅ check-yaml            → valida sintaxis YAML
✅ check-merge-conflicts → detecta marcadores <<< sin resolver
✅ detect-private-key    → detecta claves PEM hardcodeadas
✅ Gitleaks              → escanea secretos y credenciales en el diff
✅ Black                 → formatea Python automáticamente
✅ isort                 → ordena imports según perfil Black
✅ pytest (25 tests)     → verifica criptografía pura antes de commitear
```
