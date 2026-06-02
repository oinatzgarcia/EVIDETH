# CI/CD Pipeline — EVIDETH

> **Stack:** GitHub Actions · Docker · Azure Container Registry · Azure Container Apps  
> **Autenticación Azure:** Workload Identity Federation (OIDC) — sin secretos  
> **Rama protegida:** `main` — ningún merge sin CI verde

---

## Estructura de workflows

Los workflows se organizan en **4 ficheros** dentro de `.github/workflows/`:

```
.github/
└── workflows/
    ├── ci.yml                  # Orquestador — punto de entrada principal
    ├── backend.yml             # Validación del backend (reutilizable)
    ├── frontend.yml            # Validación del frontend (reutilizable)
    ├── infra.yml               # Validación de infraestructura (reutilizable)
    ├── build-push.yml          # Build Docker + push a ACR
    ├── terraform-apply.yml     # Aprovisionamiento de infraestructura en Azure
    ├── terraform-plan.yml      # Plan de infraestructura en PRs
    └── terraform-destroy.yml   # ⚠️ Destrucción TOTAL de infraestructura (manual)
```

Los workflows `backend.yml`, `frontend.yml` e `infra.yml` son **reutilizables** (`on: workflow_call`).  
Solo `ci.yml` se dispara directamente por eventos de Git.

---

## Flujo general

```mermaid
flowchart TD
    A([git push / Pull Request]) --> B[ci.yml · Orquestador]

    B --> C[backend.yml]
    B --> D[frontend.yml]
    B --> E[infra.yml]

    C --> F{?¿Todo verde?}
    D --> F
    E --> F

    F -- ✅ Sí --> G[ci-success]
    F -- ❌ No --> H[❌ PR bloqueado · no merge]

    G -->|Solo en main| I[build-push · Docker → ACR]
    I --> J[terraform-apply · Infra → Azure]
    J --> K([✅ Container App desplegado])
```

---

## Workflows detallados

### `ci.yml` — Orquestador

**Disparadores:** `push` y `pull_request` a `main` y `develop`.

**Responsabilidad:** Detectar qué ha cambiado mediante filtros de rutas (`paths`) y llamar a los workflows reutilizables correspondientes. Expone un job final `ci-success` que es el **único check requerido** en el Branch Protection de `main`.

```yaml
name: CI

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main, develop]

jobs:
  changes:
    runs-on: ubuntu-latest
    outputs:
      backend:  ${{ steps.filter.outputs.backend }}
      frontend: ${{ steps.filter.outputs.frontend }}
      infra:    ${{ steps.filter.outputs.infra }}
    steps:
      - uses: actions/checkout@v4
      - uses: dorny/paths-filter@v3
        id: filter
        with:
          filters: |
            backend:
              - 'app/**'
              - 'alembic/**'
              - 'requirements*.txt'
              - 'Dockerfile'
            frontend:
              - 'frontend/**'
              - 'static/**'
              - 'templates/**'
            infra:
              - 'infra/**'
              - 'terraform/**'
              - 'docker-compose*.yml'
              - '.github/workflows/**'

  backend:
    needs: changes
    if: needs.changes.outputs.backend == 'true'
    uses: ./.github/workflows/backend.yml
    secrets: inherit

  frontend:
    needs: changes
    if: needs.changes.outputs.frontend == 'true'
    uses: ./.github/workflows/frontend.yml
    secrets: inherit

  infra:
    needs: changes
    if: needs.changes.outputs.infra == 'true'
    uses: ./.github/workflows/infra.yml
    secrets: inherit

  ci-success:
    needs: [backend, frontend, infra]
    if: always()
    runs-on: ubuntu-latest
    steps:
      - name: Check all jobs passed
        run: |
          if [[ "${{ contains(needs.*.result, 'failure') }}" == "true" ]]; then
            echo "❌ Uno o más jobs fallaron"
            exit 1
          fi
          echo "✅ CI completado"
```

---

### `backend.yml` — Validación del backend

**Disparado por:** `ci.yml` vía `workflow_call`.

**Responsabilidad:** Lint, tests, comprobación de migraciones y smoke test de la API.

```yaml
name: Backend

on:
  workflow_call:

jobs:
  backend:
    runs-on: ubuntu-latest

    services:
      postgres:
        image: postgres:16
        env:
          POSTGRES_USER: evideth
          POSTGRES_PASSWORD: evideth
          POSTGRES_DB: evideth_test
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 5432:5432

    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
          cache: 'pip'

      - name: Instalar dependencias
        run: pip install -r requirements.txt -r requirements-dev.txt

      - name: Lint — Ruff
        run: ruff check app/

      - name: Tests — pytest
        env:
          DATABASE_URL: postgresql://evideth:evideth@localhost:5432/evideth_test
          USE_AZURE_KEY_VAULT: "false"
          SECRET_KEY: ci-test-secret
        run: pytest tests/ -v --tb=short

      - name: Alembic — check migraciones pendientes
        env:
          DATABASE_URL: postgresql://evideth:evideth@localhost:5432/evideth_test
        run: alembic upgrade head
```

---

### `frontend.yml` — Validación del frontend

**Disparado por:** `ci.yml` vía `workflow_call`.

**Responsabilidad:** Lint de HTML/CSS/JS y verificación de assets estáticos.

```yaml
name: Frontend

on:
  workflow_call:

jobs:
  frontend:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Verificar estructura de ficheros estáticos
        run: |
          test -d static || echo "⚠️  Sin carpeta static"
          test -d templates || echo "⚠️  Sin carpeta templates"
          echo "✅ Frontend check OK"
```

---

### `infra.yml` — Validación de infraestructura

**Disparado por:** `ci.yml` vía `workflow_call`.

**Responsabilidad:** Validar el código Terraform (`fmt`, `validate`) sin aplicar cambios. El formato se aplica automáticamente y las diferencias se reportan como advertencia sin bloquear el pipeline.

```yaml
name: Infrastructure

on:
  workflow_call:

jobs:
  terraform:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: '~> 1.5'

      - name: Terraform fmt (auto-format + diff report)
        working-directory: terraform/
        run: |
          terraform fmt -recursive -diff > /tmp/fmt_diff.txt 2>&1 || true
          if [ -s /tmp/fmt_diff.txt ]; then
            echo "⚠️  Ficheros .tf reformateados. Ejecuta localmente:"
            echo "   cd terraform && terraform fmt -recursive"
            cat /tmp/fmt_diff.txt
          else
            echo "✅ Formato Terraform correcto"
          fi

      - name: Terraform Init (backend=false)
        working-directory: terraform/
        run: terraform init -backend=false

      - name: Terraform Validate
        working-directory: terraform/
        run: terraform validate
```

---

### `build-push.yml` — Build Docker + Push a ACR

**Disparadores:** Push a `main` con cambios en `app/`, `Dockerfile` o `requirements.txt`. También llamado por `terraform-apply.yml` vía `workflow_call`.

**Responsabilidad:** Construir la imagen Docker del backend FastAPI y publicarla en el Azure Container Registry (ACR) del proyecto.

**Imagen resultante:**
```
evidethdevacr94f04b.azurecr.io/evideth-backend:latest
```

---

### `terraform-apply.yml` — Aprovisionamiento

**Disparadores:** Push a `main` con cambios en `terraform/`. También lanzable manualmente.

**Responsabilidad:** Aprovisionar o actualizar la infraestructura de Azure en dos jobs encadenados:
1. **Job 1** — `build-push`: garantiza que la imagen Docker existe en ACR
2. **Job 2** — `apply`: ejecuta `terraform plan` + `terraform apply`

---

### `terraform-plan.yml` — Plan en PRs

**Disparadores:** Pull Request contra `main` con cambios en `terraform/`.

**Responsabilidad:** Ejecutar `terraform plan` sin aplicar cambios y publicar el resultado como comentario en el PR para revisión antes del merge.

---

### `terraform-destroy.yml` — Destrucción de infraestructura

> ⚠️ **ADVERTENCIA:** Este workflow destruye **TODA** la infraestructura de Azure de forma **irreversible**. Debe usarse únicamente al finalizar el proyecto o cuando se necesite un reprovisioning completo desde cero.

**Disparador:** Únicamente `workflow_dispatch` (lanzamiento manual desde la UI de GitHub). **Nunca** se activa por push, PR ni schedule.

#### Doble salvaguarda

El workflow implementa dos capas de protección en serie:

```mermaid
flowchart LR
    A([workflow_dispatch]) --> B{Salvaguarda 1\nDisparo manual}
    B --> C[Job: confirm]
    C --> D{Salvaguarda 2\n¿Escribiste\n'DESTROY'?}
    D -- ❌ No --> E([Workflow cancelado\nNada modificado])
    D -- ✅ Sí --> F[Job: destroy]
    F --> G[terraform plan -destroy]
    G --> H[terraform apply -destroy]
    H --> I([✅ Infraestructura eliminada])
```

| Salvaguarda | Mecanismo | Efecto si falla |
|---|---|---|
| **1. Disparo manual** | `on: workflow_dispatch` exclusivo | No hay forma de activarlo accidentalmente |
| **2. Confirmación escrita** | Input requerido: exactamente `DESTROY` | Job `confirm` falla con exit 1; `destroy` no arranca |

#### Inputs del workflow

| Campo | Obligatorio | Descripción |
|---|---|---|
| `confirmation` | ✅ Sí | Debe contener exactamente `DESTROY` (mayúsculas) |
| `reason` | No | Motivo del destroy — queda registrado en el log |

#### Cómo lanzarlo

1. GitHub → **Actions** → `🚨 Terraform DESTROY`
2. Pulsar **Run workflow**
3. Rellenar los campos:
   - `confirmation`: `DESTROY`
   - `reason`: (opcional) motivo
4. Pulsar **Run workflow** y confirmar

#### Jobs

```yaml
jobs:
  confirm:    # Verifica que confirmation == "DESTROY"
    runs-on: ubuntu-latest
    steps:
      - name: Comprobar confirmación
        run: |
          if [ "${{ github.event.inputs.confirmation }}" != "DESTROY" ]; then
            echo "❌ Confirmación incorrecta. Destroy cancelado."
            exit 1
          fi
          echo "✅ Confirmación válida"

  destroy:
    needs: confirm     # Solo arranca si confirm tuvo éxito
    environment: destroy   # Entorno con revisor opcional en GitHub
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: azure/login@v2  # OIDC — sin secretos
      - uses: hashicorp/setup-terraform@v3
      - run: terraform init
        working-directory: terraform/
      - name: Terraform Plan Destroy (preview)
        run: terraform plan -destroy -out=tfdestroyplan
        working-directory: terraform/
      - name: Terraform Destroy
        run: terraform apply -destroy -auto-approve tfdestroyplan
        working-directory: terraform/
```

#### Comportamiento post-destroy

| Recurso | Estado tras el destroy | Motivo |
|---|---|---|
| Container App, PostgreSQL, Key Vault, ACR, Blob Storage | ❌ Eliminado | Gestionado por Terraform |
| Storage Account del estado Terraform (`evidethtfstate`) | ✅ Conservado | **Intencionado** — no gestionado por Terraform |
| Estado `.tfstate` en Azure Blob | ✅ Conservado | Necesario para re-desplegar sin conflictos |

> El Storage Account del tfstate se conserva para permitir un `terraform apply` posterior sin necesidad de reinicializar el backend desde cero.

#### Re-despliegue tras un destroy

Para restaurar toda la infraestructura después de un destroy:

```bash
# Opción A — desde GitHub Actions (recomendado)
Actions → Terraform Apply → Run workflow

# Opción B — localmente
cd terraform
terraform init
terraform apply
```

#### Protección adicional recomendada (entorno GitHub)

Crear el entorno `destroy` en `GitHub → Settings → Environments` y añadir un **Required reviewer**. Con esta configuración, ninguna ejecución del destroy arranca sin aprobación explícita, añadiendo una tercera capa de seguridad.

```
Entornos configurados en GitHub:
  └── destroy
      ├── Required reviewers: [oinatzgarcia]
      └── Wait timer: 0 min (o configurar un delay de seguridad)
```

---

## Autenticación con Azure — OIDC

EVIDETH utiliza **Workload Identity Federation** para autenticar los workflows de GitHub Actions con Azure **sin almacenar ningún secreto** (`CLIENT_SECRET`) en el repositorio.

```mermaid
sequenceDiagram
    participant GH as GitHub Actions
    participant AAD as Azure AD (Entra ID)
    participant AZ as Azure Resources

    GH->>AAD: Token OIDC firmado por GitHub
    AAD->>AAD: Valida issuer + subject (repo/branch)
    AAD->>GH: Access Token temporal
    GH->>AZ: Llamadas autenticadas (ACR, Terraform, etc.)
```

Los **3 secretos** necesarios en el repositorio son únicamente identificadores, no credenciales:

| Secreto | Valor |
|---------|-------|
| `AZURE_CLIENT_ID` | Client ID de la Managed Identity `evideth-github-oidc` |
| `AZURE_TENANT_ID` | Tenant ID de la suscripción Azure |
| `AZURE_SUBSCRIPTION_ID` | ID de la suscripción Azure |

---

## Branch Protection — main

La rama `main` tiene las siguientes reglas activas en GitHub:

| Regla | Estado | Descripción |
|-------|--------|-------------|
| Require status checks to pass | ✅ Activo | El check `CI · All checks passed` debe ser verde |
| Require branches to be up to date | ✅ Activo | La rama debe estar actualizada respecto a `main` |
| Block force pushes | ✅ Activo | Impide `git push --force` sobre `main` |
| Restrict deletions | ✅ Activo | Nadie puede borrar la rama `main` |

> El único check requerido es **`CI`** (el job `ci-success` de `ci.yml`).  
> Los workflows reutilizables (`backend`, `frontend`, `infra`) reportan su resultado a través de él.

---

## Secretos del repositorio

| Secreto | Usado en | Propósito |
|---------|----------|-----------|
| `AZURE_CLIENT_ID` | `infra.yml`, `build-push.yml`, `terraform-destroy.yml` | Managed Identity OIDC |
| `AZURE_TENANT_ID` | `infra.yml`, `build-push.yml`, `terraform-destroy.yml` | Tenant Azure |
| `AZURE_SUBSCRIPTION_ID` | `infra.yml`, `build-push.yml`, `terraform-destroy.yml` | Suscripción Azure |
| `JWT_SECRET_KEY` | `terraform-apply.yml`, `terraform-destroy.yml` | Clave JWT del backend |

> ⚠️ No se almacena ningún `CLIENT_SECRET`, `password` ni token de larga duración.  
> Los tokens OIDC tienen vida útil de minutos y se generan por workflow run.

---

## Resumen de jobs por evento

| Evento | `backend` | `frontend` | `infra` | `ci-success` | `destroy` |
|--------|-----------|------------|---------|--------------|----------|
| Push a `app/**` | ✅ Ejecuta | ⏭️ Skip | ⏭️ Skip | ✅ | — |
| Push a `templates/**` | ⏭️ Skip | ✅ Ejecuta | ⏭️ Skip | ✅ | — |
| Push a `terraform/**` | ⏭️ Skip | ⏭️ Skip | ✅ Ejecuta | ✅ | — |
| Push a `main` (full) | ✅ Ejecuta | ✅ Ejecuta | ✅ Ejecuta | ✅ | — |
| PR → `main` | Según paths | Según paths | Según paths | ✅ Siempre | — |
| `workflow_dispatch` manual | — | — | — | — | ✅ Con confirmación |

---

*EVIDETH · TFG Ingeniería en Ciberseguridad · Universidad del País Vasco UPV/EHU · 2026*
