# Pipeline CI/CD de EVIDETH

## Visión General

EVIDETH implementa un pipeline de integración y despliegue continuo (CI/CD) mediante **GitHub Actions**. El objetivo es que cualquier cambio de código o infraestructura que se suba a la rama `main` quede automáticamente construido y desplegado en Azure sin intervención manual.

El pipeline se compone de **cuatro workflows** definidos en `.github/workflows/`:

| Workflow | Fichero | Disparador |
|---|---|---|
| Build & Push Backend | `build-push.yml` | Push a `main` con cambios en `app/`, `Dockerfile` o `requirements.txt` |
| Terraform Apply | `terraform-apply.yml` | Push a `main` con cambios en `terraform/` o manual |
| Terraform Plan | `terraform-plan.yml` | Pull Request contra `main` |
| Terraform Destroy | `terraform-destroy.yml` | Manual (`workflow_dispatch`) con entorno `destroy` |

---

## Autenticación con Azure — OIDC (sin contraseñas)

Todos los workflows se autentican en Azure mediante **OpenID Connect (OIDC) / Workload Identity Federation** usando una **Managed Identity** (`evideth-github-oidc`) en el Resource Group `rg-evideth`. Este mecanismo elimina por completo el uso de contraseñas o client secrets almacenados en GitHub.

Las únicas variables necesarias son variables de repositorio (no secretos):

```
AZURE_CLIENT_ID        → Client ID de la Managed Identity evideth-github-oidc
AZURE_TENANT_ID        → ID del tenant de Azure AD
AZURE_SUBSCRIPTION_ID  → ID de la suscripción de Azure
```

El único secreto real almacenado en GitHub es `JWT_SECRET_KEY`, que se inyecta como variable de entorno en Terraform para configurar el backend.

Cada entorno de GitHub Actions tiene su propia **federated credential** registrada en la Managed Identity:

| Entorno GitHub | Subject federado |
|---|---|
| `production` (o ninguno) | `repo:oinatzgarcia/EVIDETH:ref:refs/heads/main` |
| `destroy` | `repo:oinatzgarcia/EVIDETH:environment:destroy` |

Esta aproximación sigue las recomendaciones de seguridad de Microsoft para pipelines CI/CD y evita la rotación periódica de credenciales.

---

## Workflow 1 — Build & Push Backend (`build-push.yml`)

### Propósito

Construye la imagen Docker del backend FastAPI y la publica en el **Azure Container Registry (ACR)** del proyecto.

### Disparadores

Se ejecuta automáticamente cuando:
- Se hace push a `main` con cambios en cualquiera de estas rutas:
  - `app/**` — código Python del backend
  - `Dockerfile` — imagen de contenedor
  - `requirements.txt` — dependencias Python
  - `alembic/**` o `alembic.ini` — migraciones de base de datos
- Es llamado por `terraform-apply.yml` (via `workflow_call`)
- Se lanza manualmente desde la UI de GitHub (`workflow_dispatch`)

### Pasos

```
1. Checkout del repositorio
2. Azure Login via OIDC
3. Login en el ACR (az acr login)
4. Setup de Docker Buildx (builds multi-plataforma)
5. Build & Push de la imagen con caché de GitHub Actions
6. Verificación: listado de tags en el ACR
```

### Imagen resultante

```
evidethdevacr94f04b.azurecr.io/evideth-backend:latest
```

La imagen se etiqueta siempre como `latest`. En un entorno de producción real se usaría el SHA del commit o un tag semántico para garantizar reproducibilidad.

---

## Workflow 2 — Terraform Apply (`terraform-apply.yml`)

### Propósito

Aprovisiona o actualiza toda la infraestructura de Azure declarada en los ficheros `.tf` del directorio `terraform/`.

### Disparadores

- Push a `main` con cambios en `terraform/**` o en los propios workflows
- Lanzamiento manual (`workflow_dispatch`)

### Jobs (orden importante)

#### Job 1 — Terraform Apply

Se ejecuta **primero**, garantizando que toda la infraestructura (incluido el ACR) existe antes de intentar subir la imagen.

```
1. Checkout del repositorio
2. Azure Login via OIDC
3. Setup de Terraform (~1.5)
4. terraform init    → inicializa backend remoto en Azure Storage
5. Force-unlock del estado (elimina locks huérfanos de applies fallidos)
6. terraform validate → validación sintáctica de los ficheros .tf
7. terraform plan    → genera el plan de cambios (fichero tfplan)
8. terraform apply   → aplica el plan sobre la infraestructura real
```

> **Nota bootstrap**: En el primer despliegue desde cero el Container App arranca con la imagen placeholder `mcr.microsoft.com/azuredocs/containerapps-helloworld:latest` (imagen oficial de Microsoft). El Job 2 posterior actualiza la imagen real. Terraform ignora cambios futuros en `template` gracias a `lifecycle { ignore_changes = [template] }`, por lo que los deploys de código no requieren re-apply de infra.

#### Job 2 — Build & Push Backend Image

Depende del Job 1 (`needs: apply`). Una vez la infraestructura y el ACR existen, construye y sube la imagen real del backend:

```
build-push.yml (via workflow_call)
→ Docker build
→ Docker push → ACR evidethdevacr94f04b
→ az containerapp update (imagen real en el Container App)
```

### Variables de Terraform inyectadas

| Variable Terraform | Fuente GitHub | Descripción |
|---|---|---|
| `ARM_CLIENT_ID` | `vars.AZURE_CLIENT_ID` | Identidad OIDC |
| `ARM_TENANT_ID` | `vars.AZURE_TENANT_ID` | Tenant de Azure AD |
| `ARM_SUBSCRIPTION_ID` | `vars.AZURE_SUBSCRIPTION_ID` | Suscripción de Azure |
| `TF_VAR_subscription_id` | `vars.AZURE_SUBSCRIPTION_ID` | Pasada como variable a los `.tf` |
| `TF_VAR_jwt_secret_key` | `secrets.JWT_SECRET_KEY` | Clave JWT del backend |
| `TF_VAR_environment` | `"dev"` (hardcoded) | Entorno de despliegue |

---

## Workflow 3 — Terraform Plan (`terraform-plan.yml`)

### Propósito

Ejecuta un `terraform plan` sin aplicar cambios y publica el resultado como comentario en el Pull Request. Sirve como revisión de seguridad antes de que los cambios de infraestructura lleguen a `main`.

### Disparadores

- Pull Request contra `main` con cambios en `terraform/**`

### Flujo

```
PR abierto/actualizado → terraform plan → comentario automático en el PR
```

El revisor puede ver exactamente qué recursos se van a crear, modificar o destruir antes de aprobar el merge.

---

## Workflow 4 — Terraform Destroy (`terraform-destroy.yml`)

### Propósito

Destruye **toda** la infraestructura de Azure gestionada por Terraform. Pensado para limpiar entornos de desarrollo o resetear el despliegue desde cero.

### Disparadores

- **Solo manual** (`workflow_dispatch`) — nunca se dispara automáticamente.
- Requiere el entorno de GitHub `destroy`, que tiene su propia federated credential registrada en la Managed Identity de Azure.

### Pasos

```
1. Checkout del repositorio
2. Azure Login via OIDC (entorno destroy)
3. terraform init
4. terraform destroy -auto-approve
```

> ⚠️ **Atención**: Este workflow elimina TODOS los recursos de Azure del proyecto, incluidos la base de datos, el Key Vault y el Storage Account con los vídeos. Úsalo únicamente en entornos de desarrollo. El storage account del tfstate (`evidethtfstate` en `rg-evideth`) **no es gestionado por Terraform** y sobrevive al destroy, preservando el estado para el siguiente apply.

### Lanzar el destroy

```
GitHub → EVIDETH → Actions → "Terraform Destroy" → Run workflow
```

---

## Flujo Completo de Despliegue

### Despliegue normal (cambios de código)

```
Developer
    │
    ├── git push (cambios en app/)
    │
    │   GitHub Actions
    │   ┌────────────────────────────────────────┐
    │   │  build-push.yml                        │
    │   │  1. Docker build                       │
    │   │  2. Docker push → ACR                  │
    │   └────────────────────────────────────────┘
    │
    └── Container App descarga nueva imagen en el siguiente restart
```

### Despliegue de infraestructura (cambios en Terraform)

```
Developer
    │
    ├── git push (cambios en terraform/)
    │
    │   GitHub Actions
    │   ┌────────────────────────────────────────┐
    │   │  terraform-apply.yml                   │
    │   │  Job 1: terraform apply (infra → Azure)│  ← PRIMERO
    │   │  Job 2: build-push (imagen → ACR)      │  ← DESPUÉS
    │   └────────────────────────────────────────┘
    │
    └── Azure: infraestructura + imagen actualizadas
```

### Bootstrap desde cero (tras destroy)

```
1. GitHub → Actions → "Terraform Apply" → Run workflow
   └── Job 1: Terraform crea toda la infra
           └── Container App arranca con imagen placeholder (helloworld)
   └── Job 2: Build & Push sube la imagen real al ACR
           └── Container App actualizado con evideth-backend:latest

2. Verificar arranque:
   az containerapp logs show \
     --name evideth-dev-backend \
     --resource-group evideth-dev-rg \
     --follow
```

---

## Infraestructura Gestionada por Terraform

Cuando `terraform-apply.yml` se ejecuta, gestiona los siguientes recursos de Azure en el Resource Group `evideth-dev-rg` (región `spaincentral`):

| Recurso | Nombre | Propósito |
|---|---|---|
| Resource Group | `evideth-dev-rg` | Contenedor lógico de todos los recursos |
| Virtual Network + Subnet | `evideth-dev-vnet` | Red privada para comunicación interna |
| Network Security Group | `evideth-dev-app-nsg` | Reglas de firewall a nivel de subred |
| PostgreSQL Flexible Server | `evideth-dev-pgserver` | Base de datos principal |
| Key Vault | `evideth-dev-kv-94f04b` | Almacenamiento de secretos y clave ECDSA P-256 |
| Container Registry | `evidethdevacr94f04b` | Registro de imágenes Docker |
| Storage Account | `evidethdevst94f04b` | Almacenamiento de vídeos en Blob Storage |
| Log Analytics Workspace | `evideth-dev-logs` | Telemetría y logs centralizados |
| Container App Environment | `evideth-dev-cae` | Entorno de ejecución de contenedores |
| Container App | `evideth-dev-backend` | Backend FastAPI en ejecución |

> **No gestionado por Terraform** (sobrevive al destroy):
> - Resource Group `rg-evideth` — contiene la Managed Identity y el storage del tfstate
> - Managed Identity `evideth-github-oidc` — identidad OIDC para GitHub Actions
> - Storage Account `evidethtfstate` — backend remoto del estado de Terraform

---

## Seguridad del Pipeline

- **OIDC con Managed Identity**: No existen contraseñas de Azure en GitHub. Los tokens OIDC tienen vida útil de minutos y son específicos para cada ejecución del workflow.
- **Federated credentials por entorno**: El entorno `destroy` tiene su propia credencial federada, separada del entorno de apply, limitando el blast radius de cada workflow.
- **Principio de mínimo privilegio**: La Managed Identity tiene únicamente los permisos de Azure necesarios. No tiene `Microsoft.Authorization/roleAssignments/write`.
- **Secretos aislados**: `JWT_SECRET_KEY` es el único secreto real en GitHub. Las credenciales de base de datos se generan dinámicamente por Terraform y se almacenan en Key Vault.
- **Plan antes de apply**: Los Pull Requests ejecutan `terraform plan` para revisión antes del merge.
- **Destroy solo manual**: El workflow de destroy nunca se dispara automáticamente, requiere acción explícita y entorno dedicado.

---

## Guía de Uso para el Desarrollador

### Actualizar el backend (código Python)

```bash
git add app/
git commit -m "feat: nuevo endpoint de verificación"
git push origin main
# → build-push.yml se dispara automáticamente (~2 min)
# → La nueva imagen queda disponible en ACR
```

### Actualizar la infraestructura (Terraform)

```bash
git add terraform/
git commit -m "feat: aumentar réplicas máximas del Container App"
git push origin main
# → terraform-apply.yml se dispara
# → Job 1: infraestructura actualizada en Azure
# → Job 2: imagen actualizada en ACR
```

### Destruir la infraestructura

```
GitHub → Actions → "Terraform Destroy" → Run workflow
```

### Redesplegar desde cero (tras destroy)

```
GitHub → Actions → "Terraform Apply" → Run workflow
```

### Revisar cambios de infraestructura antes de aplicar

```bash
git checkout -b infra/nueva-config
git add terraform/
git commit -m "infra: nueva configuración"
git push origin infra/nueva-config
# → Abrir PR en GitHub
# → terraform-plan.yml añade comentario con el plan en el PR
```

---

## Añadir Nuevas Variables de Entorno o Secretos

1. Si es sensible (contraseña, clave API): añadirla como **Secret** en `GitHub → Settings → Secrets and variables → Actions`.
2. Si es pública (URL, nombre de recurso): añadirla como **Variable** en la misma sección.
3. Referenciarla en `terraform-apply.yml` como `TF_VAR_nombre_variable`.
4. Declararla en `terraform/variables.tf`.
5. Inyectarla en el Container App dentro de `terraform/container_app.tf`.

---

## Pre-commit Hooks — Calidad y Seguridad Local

Además de los workflows remotos, EVIDETH incorpora **hooks de pre-commit** que se ejecutan en la máquina del desarrollador antes de cada `git commit`.

### Filosofía: dos capas de protección

```
┌─────────────────────────────────────────────────────────────┐
│  CAPA 1 — Local (pre-commit hooks)                          │
│  Se ejecuta en tu máquina antes de `git commit`             │
│  → Secret scan, formato, tests unitarios                    │
└─────────────────────────────┬───────────────────────────────┘
                              │ git push
┌─────────────────────────────▼───────────────────────────────┐
│  CAPA 2 — Remoto (GitHub Actions)                           │
│  Se ejecuta en la nube después de `git push`                │
│  → Tests unitarios + integración, build Docker, deploy      │
└─────────────────────────────────────────────────────────────┘
```

### Hooks configurados

| Hook | Herramienta | Qué hace |
|---|---|---|
| `trailing-whitespace` | pre-commit-hooks | Elimina espacios al final de línea |
| `end-of-file-fixer` | pre-commit-hooks | Asegura salto de línea al final de cada fichero |
| `check-yaml` / `check-json` | pre-commit-hooks | Valida sintaxis de YAML y JSON |
| `check-merge-conflict` | pre-commit-hooks | Detecta marcadores `<<<<<<` sin resolver |
| `check-added-large-files` | pre-commit-hooks | Bloquea ficheros > 500 KB |
| `detect-private-key` | pre-commit-hooks | Detecta claves privadas PEM/RSA hardcodeadas |
| **`gitleaks`** | Gitleaks v8 | **Escanea el diff en busca de secretos y credenciales** |
| `black` | Black 24.2 | Formatea el código Python automáticamente |
| `isort` | isort 5.13 | Ordena los imports según PEP8 |
| **`pytest tests/unit/`** | pytest | **Ejecuta tests unitarios — bloquea el commit si fallan** |

### Instalación (una sola vez por desarrollador)

```bash
git pull origin main
pre-commit install
# Opcional: ejecutar sobre todos los ficheros ahora
pre-commit run --all-files
```

### Saltar un hook puntualmente

```bash
# Saltar todos los hooks (solo en casos excepcionales justificados)
git commit --no-verify -m "mensaje"

# Ejecutar solo el secret scan
pre-commit run gitleaks

# Ejecutar solo los tests
pre-commit run unit-tests
```

> ⚠️ El uso de `--no-verify` debe quedar justificado en el mensaje del commit.

### Diferencia entre pre-commit y GitHub Actions

| Dimensión | Pre-commit (local) | GitHub Actions (remoto) |
|---|---|---|
| **Cuándo se ejecuta** | Antes del `git commit` | Después del `git push` |
| **Quién lo ve** | Solo el desarrollador | Todo el equipo y el historial de CI |
| **Tests ejecutados** | Solo unitarios (rápidos) | Unitarios + integración + características |
| **Secret scan** | ✅ Gitleaks (diff del commit) | ✅ En `ci.yml` (histórico completo) |
| **Formato de código** | ✅ Black + isort (auto-fix) | ✅ Verificación (sin auto-fix) |
| **Requisito** | Instalación manual por desarrollador | Automático en cada push |
