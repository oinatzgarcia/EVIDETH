# EVIDETH — Infraestructura Terraform (Azure)

Despliegue de EVIDETH en Azure usando Terraform.
El backend FastAPI + PostgreSQL corren en Azure.
El simulador de cámara corre en local apuntando al backend.

## Recursos desplegados

| Recurso | Tipo Azure | Coste dev/mes |
|---|---|---|
| Backend API | Container App | ~5-8 EUR |
| Base de datos | PostgreSQL Flexible B1ms | ~10 EUR |
| Imágenes Docker | Container Registry Basic | ~5 EUR |
| Vídeos | Blob Storage Standard LRS | ~1 EUR |
| Claves ECDSA | Key Vault Standard | <1 EUR |
| Monitorización | Log Analytics | ~2 EUR |
| **Total estimado** | | **~23-27 EUR/mes** |

## Prerrequisitos

```bash
# 1. Instalar Terraform >= 1.5
# Windows: choco install terraform
# Mac:     brew install terraform
# Linux:   apt install terraform

# 2. Instalar Azure CLI
# https://docs.microsoft.com/cli/azure/install-azure-cli

# 3. Login en Azure
az login
az account set --subscription "TU_SUBSCRIPTION_ID"

# Verificar
az account show
terraform -version
```

## Despliegue paso a paso

### 1. Configurar variables

```bash
cd terraform/
cp terraform.tfvars.example terraform.tfvars
# Editar terraform.tfvars con tus valores reales
# Especialmente: jwt_secret_key (openssl rand -hex 32)
```

### 2. Desplegar infraestructura

```bash
cd terraform/
terraform init       # Descarga providers (~1 min)
terraform validate   # Comprueba sintaxis
terraform plan       # Previsualiza recursos a crear
terraform apply      # Despliega (~8-12 min)
```

### 3. Build y push de la imagen Docker

```bash
# Obtener credenciales del ACR
export ACR_URL=$(terraform output -raw acr_login_server)
export ACR_USER=$(terraform output -raw acr_admin_username)
export ACR_PASS=$(terraform output -raw acr_admin_password)

# Login en ACR
echo $ACR_PASS | docker login $ACR_URL -u $ACR_USER --password-stdin

# Build desde la raíz del proyecto
cd ..
docker build -t $ACR_URL/evideth-backend:latest .
docker push $ACR_URL/evideth-backend:latest
```

### 4. Ejecutar migraciones Alembic

```bash
export RG=$(cd terraform && terraform output -raw resource_group_name)
export APP=$(cd terraform && terraform output -raw container_app_name)

az containerapp exec \
  --name $APP \
  --resource-group $RG \
  --command "alembic upgrade head"
```

### 5. Configurar el simulador local

```bash
# Obtener la URL del backend
cd terraform/
terraform output backend_url
# Ejemplo: https://evideth-dev-backend.westeurope.azurecontainerapps.io

# Configurar el simulador
cp simulator/.env.example simulator/.env
# Editar simulator/.env:
#   EVIDETH_API_URL = <backend_url>
#   CAMERA_API_KEY  = <clave generada en el backend>

# Arrancar solo el simulador (el backend está en Azure)
docker compose up --build
```

### 6. Forzar redeploy tras nuevo push de imagen

```bash
az containerapp update \
  --name evideth-dev-backend \
  --resource-group evideth-dev-rg \
  --image $ACR_URL/evideth-backend:latest
```

## Destruir infraestructura

```bash
cd terraform/
terraform destroy   # Elimina TODO para no incurrir en costes
```

## Estructura de archivos

```
terraform/
├── main.tf              # Provider + Resource Group + Log Analytics
├── variables.tf         # Variables de entrada + locals
├── network.tf           # VNet + subnets + NSG + DNS privado
├── database.tf          # PostgreSQL Flexible Server + BD evideth_db
├── registry.tf          # Azure Container Registry (ACR)
├── storage.tf           # Azure Blob Storage (evideth-videos)
├── keyvault.tf          # Key Vault + clave ECDSA P-256 + secretos
├── container_app.tf     # Container App Environment + App backend
├── outputs.tf           # Outputs: URL, ACR, Key Vault, etc.
├── terraform.tfvars.example  # Plantilla de variables (copiar a .tfvars)
└── README.md            # Esta guía
```

## Variables de entorno inyectadas al Container App

Las variables coinciden exactamente con `.env.example`:

| Variable | Origen |
|---|---|
| `DATABASE_URL` | Generada por Terraform (PostgreSQL FQDN + password) |
| `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER` | Generadas por Terraform |
| `SECRET_KEY` / `JWT_SECRET_KEY` | Variable `jwt_secret_key` del tfvars |
| `AZURE_KEY_VAULT_URL` | URL del Key Vault creado |
| `AZURE_TENANT_ID` | Tenant ID de tu suscripción |
| `AZURE_STORAGE_CONNECTION_STRING` | Conexión del Storage Account creado |
| `AZURE_STORAGE_CONTAINER_NAME` | `evideth-videos` |
| `ECDSA_KEY_NAME` | `evideth-signing-key` |
| `SEGMENT_DURATION_SECONDS` | `30` |
| `CORS_ORIGINS` | Variable `allowed_origins` del tfvars |
| `APP_ENV`, `DEBUG`, `LOG_LEVEL` | Según entorno (`dev`/`prod`) |
