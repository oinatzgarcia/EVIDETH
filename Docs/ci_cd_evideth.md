# Pipeline CI/CD de EVIDETH

## Visión General

EVIDETH implementa un pipeline de integración y despliegue continuo (CI/CD) mediante **GitHub Actions**. El objetivo es que cualquier cambio de código o infraestructura que se suba a la rama `main` quede automáticamente construido y desplegado en Azure sin intervención manual.

El pipeline se compone de **tres workflows** definidos en `.github/workflows/`:

| Workflow | Fichero | Disparador |
|---|---|---|
| Build & Push Backend | `build-push.yml` | Push a `main` con cambios en `app/`, `Dockerfile` o `requirements.txt` |
| Terraform Apply | `terraform-apply.yml` | Push a `main` con cambios en `terraform/` |
| Terraform Plan | `terraform-plan.yml` | Pull Request contra `main` |

---

## Autenticación con Azure — OIDC (sin contraseñas)

Todos los workflows se autentican en Azure mediante **OpenID Connect (OIDC) / Workload Identity Federation**. Este mecanismo elimina por completo el uso de contraseñas o client secrets almacenados en GitHub: en su lugar, GitHub genera un token firmado de corta vida que Azure valida directamente.

Las únicas variables necesarias son variables de repositorio (no secretos):

```
AZURE_CLIENT_ID        → ID de la App Registration en Azure AD
AZURE_TENANT_ID        → ID del tenant de Azure AD
AZURE_SUBSCRIPTION_ID  → ID de la suscripción de Azure
```

El único secreto real almacenado en GitHub es `JWT_SECRET_KEY`, que se inyecta como variable de entorno en Terraform para configurar el backend.

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

Aprovisiona o actualiza toda la infraestructura de Azure declarada en los ficheros `.tf` del directorio `terraform/`. Se ejecuta en dos jobs encadenados.

### Disparadores

- Push a `main` con cambios en `terraform/**` o en los propios workflows
- Lanzamiento manual (`workflow_dispatch`)

### Jobs

#### Job 1 — Build & Push Backend Image

Antes de aplicar la infraestructura, se garantiza que la imagen Docker existe en el ACR. Para ello reutiliza el workflow `build-push.yml` mediante `workflow_call`. Esto evita que el Container App intente arrancar con una imagen inexistente.

#### Job 2 — Terraform Apply

Depende del Job 1 (`needs: build-push`). Una vez la imagen está disponible:

```
1. Checkout del repositorio
2. Azure Login via OIDC
3. Setup de Terraform (~1.5)
4. terraform init    → inicializa backend remoto en Azure Storage
5. terraform validate → validación sintáctica de los ficheros .tf
6. terraform plan    → genera el plan de cambios (fichero tfplan)
7. terraform apply   → aplica el plan sobre la infraestructura real
```

El plan y el apply se ejecutan en el **mismo paso** para evitar que un plan generado en un contexto distinto (por ejemplo, con una región incorrecta) sea reutilizado en el apply.

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

El revisor puede ver exactamente qué recursos se van a crear, modificar o destruir antes de aprobar el merge. Esto aplica el principio de **revisión de infraestructura como código** (IaC review), análogo a la revisión de código fuente.

---

## Flujo Completo de Despliegue

El ciclo completo desde un cambio de código hasta el despliegue en producción es:

```
Developer
    │
    ├── git push (cambios en app/) ──────────────────────────────────────────┐
    │                                                                        │
    │   GitHub Actions                                                       │
    │   ┌────────────────────────────────────────────────────────────────┐  │
    │   │  build-push.yml                                                │  │
    │   │  1. Docker build                                               │  │
    │   │  2. Docker push → ACR                                          │  │
    │   └────────────────────────────────────────────────────────────────┘  │
    │                                                                        │
    ├── git push (cambios en terraform/) ────────────────────────────────────┤
    │                                                                        │
    │   GitHub Actions                                                       │
    │   ┌────────────────────────────────────────────────────────────────┐  │
    │   │  terraform-apply.yml                                           │  │
    │   │  Job 1: build-push (imagen → ACR)                              │  │
    │   │  Job 2: terraform apply (infraestructura → Azure)              │  │
    │   └────────────────────────────────────────────────────────────────┘  │
    │                                                                        │
    └── Azure                                                                │
        ├── Container App actualizado con nueva imagen                       │
        ├── PostgreSQL, Key Vault, Storage sin cambios (idempotente)         │
        └── Backend EVIDETH accesible via HTTPS                  ←──────────┘
```

---

## Infraestructura Gestionada por Terraform

Cuando `terraform-apply.yml` se ejecuta, gestiona los siguientes recursos de Azure en el Resource Group `evideth-dev-rg` (región `spaincentral`):

| Recurso | Nombre | Propósito |
|---|---|---|
| Resource Group | `evideth-dev-rg` | Contenedor lógico de todos los recursos |
| Virtual Network + Subnet | `evideth-dev-vnet` | Red privada para comunicación interna |
| Network Security Group | `evideth-dev-app-nsg` | Reglas de firewall a nivel de subred |
| PostgreSQL Flexible Server | `evideth-dev-pg-*` | Base de datos principal |
| Key Vault | `evideth-dev-kv-*` | Almacenamiento de secretos y clave ECDSA P-256 |
| Container Registry | `evidethdevacr*` | Registro de imágenes Docker |
| Storage Account | `evidethdevst*` | Almacenamiento de vídeos en Blob Storage |
| Log Analytics Workspace | `evideth-dev-logs` | Telemetría y logs centralizados |
| Container App Environment | `evideth-dev-cae` | Entorno de ejecución de contenedores |
| Container App | `evideth-dev-backend` | Backend FastAPI en ejecución |

El estado de Terraform se almacena en un **backend remoto** (Azure Blob Storage), lo que permite que cualquier ejecución del workflow parta del estado real de la infraestructura.

---

## Seguridad del Pipeline

El diseño del pipeline incorpora varias medidas de seguridad relevantes para un sistema de custodia de evidencias digitales:

- **OIDC en lugar de client secrets**: No existen contraseñas de Azure almacenadas en GitHub. Los tokens OIDC tienen una vida útil de minutos y son específicos para cada ejecución.
- **Principio de mínimo privilegio**: El Service Principal de GitHub Actions tiene únicamente los permisos de Azure necesarios para crear y gestionar recursos. No tiene permisos `Microsoft.Authorization/roleAssignments/write`.
- **Secretos aislados**: `JWT_SECRET_KEY` es el único secreto real en GitHub. Las credenciales de base de datos se generan dinámicamente por Terraform y se almacenan directamente en Key Vault, sin pasar por GitHub.
- **Plan antes de apply**: Los Pull Requests ejecutan `terraform plan` para que los cambios de infraestructura sean revisados antes del merge, evitando modificaciones accidentales en recursos críticos.
- **Caché de imagen**: El build Docker usa caché de GitHub Actions (`cache-from: type=gha`) para reducir tiempos de build y el número de capas descargadas desde registros externos.

---

## Guía de Uso para el Desarrollador

### Actualizar el backend (código Python)

```bash
# Editar código en app/
git add app/
git commit -m "feat: nuevo endpoint de verificación"
git push origin main
# → build-push.yml se dispara automáticamente (~28s)
# → La nueva imagen queda disponible en ACR
# → El Container App descarga la nueva imagen en el siguiente restart
```

### Actualizar la infraestructura (Terraform)

```bash
# Editar ficheros .tf en terraform/
git add terraform/
git commit -m "feat: aumentar réplicas máximas del Container App"
git push origin main
# → terraform-apply.yml se dispara (~2m)
# → Job 1: imagen actualizada en ACR
# → Job 2: infraestructura actualizada en Azure
```

### Revisar cambios de infraestructura antes de aplicar

```bash
# Crear rama y Pull Request
git checkout -b infra/nueva-config
git add terraform/
git commit -m "infra: nueva configuración"
git push origin infra/nueva-config
# → Abrir PR en GitHub
# → terraform-plan.yml añade comentario con el plan en el PR
# → Revisar y aprobar antes de mergear
```

### Lanzar el pipeline manualmente

Desde GitHub → Actions → seleccionar el workflow → **Run workflow**. Útil para forzar un redespliegue sin cambios de código.

---

## Añadir Nuevas Variables de Entorno o Secretos

Si se necesita exponer una nueva variable al backend:

1. Si es sensible (contraseña, clave API): añadirla como **Secret** en `GitHub → Settings → Secrets and variables → Actions`.
2. Si es pública (URL, nombre de recurso): añadirla como **Variable** en la misma sección.
3. Referenciarla en `terraform-apply.yml` como `TF_VAR_nombre_variable`.
4. Declararla en `terraform/variables.tf`.
5. Inyectarla en el Container App dentro de `terraform/container_app.tf`.
