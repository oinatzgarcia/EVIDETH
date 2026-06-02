# Azure Key Vault en EVIDETH

Documentacion completa de la integracion de Azure Key Vault en EVIDETH:
arcitectura, flujo de autenticacion, convencion de nombres, uso en codigo
y procedimientos operacionales.

---

## Indice

1. [Por que Key Vault](#1-por-que-key-vault)
2. [Arquitectura de la integracion](#2-arquitectura-de-la-integracion)
3. [Autenticacion: DefaultAzureCredential](#3-autenticacion-defaultazurecredential)
4. [Convencion de nombres de secretos](#4-convencion-de-nombres-de-secretos)
5. [API del cliente KeyVaultClient](#5-api-del-cliente-keyvaultclient)
6. [Bootstrap al arrancar la aplicacion](#6-bootstrap-al-arrancar-la-aplicacion)
7. [Gestion de claves ECDSA por camara](#7-gestion-de-claves-ecdsa-por-camara)
8. [Configuracion en Azure](#8-configuracion-en-azure)
9. [Verificacion y tests](#9-verificacion-y-tests)
10. [Decisiones de diseno](#10-decisiones-de-diseno)

---

## 1. Por que Key Vault

Sin Key Vault, los secretos criticos (`JWT_SECRET_KEY`, `DATABASE_URL`,
claves ECDSA) deben configurarse como variables de entorno en el Container
App, lo que implica que:

- Aparecen en texto plano en la configuracion del despliegue de Azure
- Cualquier persona con acceso al portal de Azure puede leerlos
- La rotacion requiere redespliegue manual
- Las claves privadas ECDSA no tienen un lugar seguro donde vivir

Con Key Vault:

- Los secretos **nunca aparecen en texto plano** en variables de entorno
- Acceso controlado por **RBAC de Azure** (solo la identidad del Container App)
- **Versionado automatico**: cada rotacion crea una nueva version sin borrar las anteriores
- **Audit log** de cada acceso a cada secreto (quien, cuando, desde donde)
- Las claves privadas ECDSA tienen un almacen dedicado y auditado

---

## 2. Arquitectura de la integracion

```
                          PRODUCCION (Azure)

  +------------------------+      Managed Identity       +------------------+
  |   EVIDETH Container    | --------------------------> |   Key Vault      |
  |   App                  |   (sin CLIENT_SECRET)       |                  |
  |                        |                             |  evideth-jwt-... |
  |  bootstrap_secrets()   | <-- JWT_SECRET_KEY -------- |  evideth-cam-... |
  |  kv.get_camera_key()   | <-- ECDSA private key ----- |  evideth-db-...  |
  +------------------------+                             +------------------+

                          DESARROLLO LOCAL

  +------------------------+
  |   EVIDETH local        |   AZURE_KEY_VAULT_URL vacio
  |                        |   Key Vault = no-op
  |  Settings lee .env     |   Secretos desde .env
  +------------------------+

                          CI (GitHub Actions)

  +------------------------+      Service Principal       +------------------+
  |   GitHub Actions       | --------------------------> |   Key Vault      |
  |   Runner               |   (Actions Secrets)         |   (opcional)     |
  +------------------------+                             +------------------+
  O bien: sin Key Vault, con secretos de Actions directamente en env vars del CI
```

---

## 3. Autenticacion: DefaultAzureCredential

EVIDETH usa `DefaultAzureCredential` de `azure-identity`, que prueba
los siguientes metodos de autenticacion en orden:

| Orden | Metodo | Cuando aplica |
|---|---|---|
| 1 | `EnvironmentCredential` | `AZURE_CLIENT_ID` + `AZURE_CLIENT_SECRET` en env |
| 2 | `WorkloadIdentityCredential` | Kubernetes con Workload Identity |
| 3 | `ManagedIdentityCredential` | **Azure Container App en produccion** |
| 4 | `AzureCliCredential` | `az login` en desarrollo local |
| 5 | `VisualStudioCodeCredential` | Extension Azure en VS Code |

En produccion, el Container App tiene una **Managed Identity** asignada
con el rol `Key Vault Secrets User` sobre el Key Vault de EVIDETH.
`DefaultAzureCredential` detecta automaticamente la Managed Identity
sin necesidad de ningun secreto adicional en variables de entorno.

### Inicializacion en el codigo

```python
# app/core/key_vault.py
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

credential = DefaultAzureCredential()
self._secret_client = SecretClient(
    vault_url=settings.AZURE_KEY_VAULT_URL,
    credential=credential,
)
```

---

## 4. Convencion de nombres de secretos

Todos los secretos de EVIDETH siguen el prefijo `evideth-` para
aislarlos de otros secretos que pueda haber en el mismo Key Vault.

### Secretos de aplicacion

| Nombre en Key Vault | Settings que sobreescribe | Descripcion |
|---|---|---|
| `evideth-jwt-secret-key` | `JWT_SECRET_KEY` | Clave HMAC para firmar JWT |
| `evideth-secret-key` | `SECRET_KEY` | Clave general de la aplicacion |

### Secretos de camaras (ECDSA)

| Patron de nombre | Descripcion |
|---|---|
| `evideth-camera-{camera_id}-private-key` | Clave privada EC P-256 en PEM |
| `evideth-camera-{camera_id}-public-key` | Clave publica EC P-256 en PEM |

El `camera_id` se normaliza antes de usarlo como nombre de secreto:
- Convertido a minusculas
- Guiones bajos (`_`) y espacios reemplazados por guiones (`-`)

Ejemplos:

```
cam-001          -> evideth-camera-cam-001-private-key
cam_exterior     -> evideth-camera-cam-exterior-private-key
CAM LOBBY 02     -> evideth-camera-cam-lobby-02-private-key
```

---

## 5. API del cliente KeyVaultClient

El singleton `kv` es la forma recomendada de acceder a Key Vault
desde cualquier modulo de EVIDETH:

```python
from app.core.key_vault import kv
```

### Secretos generales

```python
# Obtener un secreto (con fallback si KV no disponible)
value = kv.get_secret("evideth-jwt-secret-key", fallback="dev-default")

# Almacenar un secreto
ok = kv.set_secret("evideth-jwt-secret-key", "nuevo-valor-seguro")

# Eliminar un secreto (soft-delete, recuperable)
ok = kv.delete_secret("evideth-jwt-secret-key")
```

### Claves ECDSA por camara

```python
# Al registrar una camara nueva
ok = kv.store_camera_private_key("cam-001", private_pem)
ok = kv.store_camera_public_key("cam-001", public_pem)

# En el simulador, antes de firmar un segmento
private_pem = kv.get_camera_private_key("cam-001")

# Rotar claves (Key Vault versiona automaticamente)
ok = kv.rotate_camera_keys("cam-001", new_private_pem, new_public_pem)
```

### Comportamiento segun disponibilidad

| Estado de Key Vault | `get_secret` | `set_secret` | `get_camera_private_key` |
|---|---|---|---|
| URL vacia (dev local) | Devuelve `fallback` | `False` | `None` |
| URL configurada, OK | Valor del secreto | `True` | PEM de la clave |
| URL configurada, error red | Devuelve `fallback` | `False` | `None` |

Nunca lanza excepciones no controladas -- todos los errores se loguean
y se devuelve el valor de fallback.

---

## 6. Bootstrap al arrancar la aplicacion

Al arrancar, `app/main.py` llama a `bootstrap_secrets_from_key_vault()`
**antes de inicializar la BD** para asegurar que `JWT_SECRET_KEY` ya
tiene el valor de Key Vault cuando se procesa el primer JWT:

```python
# app/main.py - lifespan
async def lifespan(app: FastAPI):
    setup_telemetry()                      # 1. Application Insights
    bootstrap_secrets_from_key_vault()     # 2. Key Vault -> Settings
    models.Base.metadata.create_all(...)   # 3. BD
    yield
```

### Mapa de secretos cargados en bootstrap

```python
# app/core/key_vault_bootstrap.py
KEY_VAULT_SECRET_MAP = {
    "evideth-jwt-secret-key": "JWT_SECRET_KEY",
    "evideth-secret-key":     "SECRET_KEY",
}
```

Si un secreto no existe en Key Vault, se mantiene el valor de la
variable de entorno sin error. El bootstrap es aditivo, nunca destructivo.

---

## 7. Gestion de claves ECDSA por camara

### Flujo al registrar una camara nueva

```
Admin llama POST /api/v1/cameras/
         |
         v
  Generar par EC P-256
  (en el simulador o en el backend)
         |
         +---> kv.store_camera_private_key(camera_id, priv_pem)
         |          Clave privada -> Key Vault UNICAMENTE
         |          NUNCA a la base de datos
         |
         +---> kv.store_camera_public_key(camera_id, pub_pem)
         |          Clave publica -> Key Vault
         |
         +---> POST /api/v1/cameras/{id}/public-key
                   Clave publica -> BD (cameras.public_key_pem)
                   Para verificacion sin llamar a KV en cada segmento
```

### Flujo al verificar la firma de un segmento

```
Verificador llama verify_video()
         |
         v
  Leer cameras.public_key_pem de la BD   <- rapido, sin llamada a KV
         |
         v
  ECDSA verify(segmento.sha256_hash,
               segmento.ecdsa_signature,
               public_key_pem)
         |
         v
  Resultado: PASS / FAIL
```

La clave publica se mantiene en BD para rendimiento. La clave privada
jamas sale de Key Vault.

### Rotacion de claves

```bash
# 1. Generar nuevo par de claves
openssl ecparam -name prime256v1 -genkey -noout -out cam001_new.pem
openssl ec -in cam001_new.pem -pubout -out cam001_new_pub.pem

# 2. Subir a Key Vault via API de EVIDETH (o script)
# Key Vault versiona automaticamente -- la version anterior queda
# disponible para verificar segmentos antiguos si es necesario.

# 3. Actualizar clave publica en BD
PATCH /api/v1/cameras/{camera_id}
Body: { "public_key_pem": "<nueva clave publica>" }
```

---

## 8. Configuracion en Azure

### Crear el Key Vault

```bash
az keyvault create \
  --name evideth-kv \
  --resource-group evideth-rg \
  --location westeurope \
  --sku standard \
  --enable-soft-delete true \
  --retention-days 90
```

### Habilitar Managed Identity en el Container App

```bash
# Asignar identidad al Container App
az containerapp identity assign \
  --name evideth-backend \
  --resource-group evideth-rg \
  --system-assigned

# Obtener el principal ID de la identidad
PRINCIPAL_ID=$(az containerapp identity show \
  --name evideth-backend \
  --resource-group evideth-rg \
  --query principalId -o tsv)

# Dar acceso de lectura al Key Vault
az keyvault set-policy \
  --name evideth-kv \
  --object-id $PRINCIPAL_ID \
  --secret-permissions get list
```

### Cargar los secretos de aplicacion

```bash
# JWT Secret Key (minimo 32 caracteres)
az keyvault secret set \
  --vault-name evideth-kv \
  --name evideth-jwt-secret-key \
  --value "$(openssl rand -base64 48)"

# App Secret Key
az keyvault secret set \
  --vault-name evideth-kv \
  --name evideth-secret-key \
  --value "$(openssl rand -base64 48)"
```

### Configurar la URL del Key Vault en el Container App

```bash
# Solo la URL -- sin CLIENT_SECRET gracias a Managed Identity
az containerapp update \
  --name evideth-backend \
  --resource-group evideth-rg \
  --set-env-vars AZURE_KEY_VAULT_URL=https://evideth-kv.vault.azure.net/
```

---

## 9. Verificacion y tests

### Tests unitarios (sin Azure, en CI)

Los tests unitarios en `tests/unit/test_key_vault.py` verifican el
comportamiento del cliente con mocks de `SecretClient`:

```bash
pytest tests/unit/test_key_vault.py -v
```

Escenarios cubiertos:

| Test | Que verifica |
|---|---|
| `TestKeyVaultDisabled` | Fallback correcto cuando URL esta vacia |
| `TestKeyVaultSecrets` | get/set/delete de secretos con KV disponible |
| `TestCameraECDSAKeys` | Gestion completa de claves ECDSA por camara |
| `TestKeyVaultUnavailable` | Sin crash cuando KV no es accesible |
| `TestSecretNamingConvention` | Normalizacion correcta de camera_id |
| `TestKeyVaultBootstrap` | Bootstrap no-op cuando KV no disponible |

### Verificacion manual con Azure CLI

```bash
# Comprobar que el secreto existe
az keyvault secret show \
  --vault-name evideth-kv \
  --name evideth-jwt-secret-key \
  --query "{name:name, created:attributes.created}" \
  -o table

# Ver versiones de un secreto de camara
az keyvault secret list-versions \
  --vault-name evideth-kv \
  --name evideth-camera-cam-001-private-key \
  --query "[].{version:id, created:attributes.created}" \
  -o table

# Ver el audit log de accesos
az monitor activity-log list \
  --resource-group evideth-rg \
  --resource-type Microsoft.KeyVault/vaults \
  --offset 24h \
  -o table
```

### Health check de Key Vault desde la app

```python
from app.core.key_vault import kv

# Comprobar disponibilidad
print(f"Key Vault disponible: {kv.available}")

# Test de conectividad (intenta leer un secreto de prueba)
result = kv.get_secret("evideth-jwt-secret-key")
print(f"JWT secret cargado: {'si' if result else 'no'}")
```

---

## 10. Decisiones de diseño

### Por que secretos y no claves criptograficas nativas de Key Vault

Azure Key Vault ofrece dos tipos de almacenamiento:
- **Keys**: operaciones criptograficas en HSM (sign, verify) sin exportar la clave
- **Secrets**: valores arbitrarios recuperables (PEM, tokens, passwords)

EVIDETH usa **Secrets** para las claves ECDSA por tres razones:
1. El simulador Docker necesita la clave privada en memoria para firmar con la
   libreria `ecdsa` de Python -- las Keys de KV no son exportables.
2. La verificacion usa la libreria `cryptography` de Python, que tambien
   necesita el PEM en memoria.
3. El nivel de seguridad de Secrets con RBAC y audit log es suficiente
   para el modelo de amenazas de EVIDETH (OWASP ASVS nivel 2).

En un sistema de nivel 3 (alta seguridad), se usarian Keys de KV con
operaciones de firma en el HSM sin exportar nunca la clave privada.

### Resumen de estandares aplicados

| Estandar | Seccion | Aplicacion |
|---|---|---|
| **OWASP ASVS v4.0** | S6.4.1 | Gestion centralizada de claves en Key Vault |
| **OWASP ASVS v4.0** | S6.4.2 | Rotacion de claves con historial de versiones |
| **NIST SP 800-57** | Part 1, S5.3 | Ciclo de vida de claves criptograficas |
| **NIST SP 800-53** | SC-12 | Establecimiento y gestion de claves criptograficas |
