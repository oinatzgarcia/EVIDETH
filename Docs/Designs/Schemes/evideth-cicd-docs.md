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
    ├── ci.yml          # Orquestador — punto de entrada principal
    ├── backend.yml     # Validación del backend (reutilizable)
    ├── frontend.yml    # Validación del frontend (reutilizable)
    └── infra.yml       # Validación de infraestructura (reutilizable)
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

    C --> F{¿Todo verde?}
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

**Responsabilidad:** Validar el código Terraform (`fmt`, `validate`, `plan`) sin aplicar cambios.

```yaml
name: Infrastructure

on:
  workflow_call:

jobs:
  terraform:
    runs-on: ubuntu-latest

    permissions:
      id-token: write   # necesario para OIDC
      contents: read

    steps:
      - uses: actions/checkout@v4

      - uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: '~1.7'

      - name: Azure Login (OIDC)
        uses: azure/login@v2
        with:
          client-id:       ${{ secrets.AZURE_CLIENT_ID }}
          tenant-id:       ${{ secrets.AZURE_TENANT_ID }}
          subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}

      - name: Terraform Init
        working-directory: infra/
        run: terraform init -backend-config="key=evideth-dev.tfstate"

      - name: Terraform Format check
        working-directory: infra/
        run: terraform fmt -check -recursive

      - name: Terraform Validate
        working-directory: infra/
        run: terraform validate

      - name: Terraform Plan
        working-directory: infra/
        run: terraform plan -out=tfplan
        env:
          TF_VAR_environment: dev
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
| `AZURE_CLIENT_ID` | `infra.yml`, `build-push.yml` | Managed Identity OIDC |
| `AZURE_TENANT_ID` | `infra.yml`, `build-push.yml` | Tenant Azure |
| `AZURE_SUBSCRIPTION_ID` | `infra.yml`, `build-push.yml` | Suscripción Azure |

> ⚠️ No se almacena ningún `CLIENT_SECRET`, `password` ni token de larga duración.  
> Los tokens OIDC tienen vida útil de minutos y se generan por workflow run.

---

## Resumen de jobs por evento

| Evento | `backend` | `frontend` | `infra` | `ci-success` |
|--------|-----------|------------|---------|--------------|
| Push a `app/**` | ✅ Ejecuta | ⏭️ Skip | ⏭️ Skip | ✅ |
| Push a `templates/**` | ⏭️ Skip | ✅ Ejecuta | ⏭️ Skip | ✅ |
| Push a `infra/**` | ⏭️ Skip | ⏭️ Skip | ✅ Ejecuta | ✅ |
| Push a `main` (full) | ✅ Ejecuta | ✅ Ejecuta | ✅ Ejecuta | ✅ |
| PR → `main` | Según paths | Según paths | Según paths | ✅ Siempre |

---

*EVIDETH · TFG Ingeniería en Ciberseguridad · Universidad del País Vasco UPV/EHU · 2026*
