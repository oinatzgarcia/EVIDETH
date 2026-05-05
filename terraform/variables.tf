# ─────────────────────────────────────────────────────────────
# EVIDETH — variables.tf
# Todas las variables de entrada del módulo Terraform.
# Los valores por defecto corresponden al entorno "dev".
# Para producción usa terraform.tfvars o -var flags.
# ─────────────────────────────────────────────────────────────

# ── Azure ───────────────────────────────────────────
variable "subscription_id" {
  description = "ID de la suscripción Azure (requerido en Azure for Students)"
  type        = string
}

variable "project_name" {
  description = "Nombre base del proyecto (usado en todos los nombres de recursos)"
  type        = string
  default     = "evideth"
}

variable "environment" {
  description = "Entorno de despliegue: dev | staging | prod"
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "El entorno debe ser dev, staging o prod."
  }
}

variable "location" {
  description = "Región de Azure permitida por la política sys.regionrestriction"
  type        = string
  default     = "spaincentral"
  # Regiones permitidas verificadas en la suscripción Azure for Students:
  # spaincentral | francecentral | switzerlandnorth | polandcentral | germanywestcentral
  # Cualquier otra región (eastus, westeurope, northeurope...) devuelve 403 RequestDisallowedByAzure.
}

# ── Base de datos ─────────────────────────────────────
variable "db_admin_user" {
  description = "Usuario administrador de PostgreSQL Flexible Server"
  type        = string
  default     = "evidethadmin"
}

variable "db_name" {
  description = "Nombre de la base de datos (debe coincidir con DB_NAME del .env)"
  type        = string
  default     = "evideth_db"   # Igual que DB_NAME en .env.example
}

variable "db_sku" {
  description = "SKU del servidor PostgreSQL Flexible"
  type        = string
  default     = "B_Standard_B1ms"   # ~10 EUR/mes — dev
  # Producción recomendado: "GP_Standard_D2s_v3"
}

# ── Container App ─────────────────────────────────
variable "backend_image_tag" {
  description = "Tag de la imagen Docker del backend en el ACR"
  type        = string
  default     = "latest"
}

variable "backend_cpu" {
  description = "vCPU asignados al Container App (0.25 | 0.5 | 1.0 | 2.0)"
  type        = number
  default     = 0.5
}

variable "backend_memory" {
  description = "Memoria RAM del Container App (debe ser coherente con cpu)"
  type        = string
  default     = "1Gi"
  # Pares válidos: 0.5cpu/1Gi · 1cpu/2Gi · 2cpu/4Gi
}

variable "backend_min_replicas" {
  description = "Réplicas mínimas (1 en dev para evitar cold starts)"
  type        = number
  default     = 1
}

variable "backend_max_replicas" {
  description = "Réplicas máximas (autoescalado HTTP)"
  type        = number
  default     = 3
}

# ── Secretos ─────────────────────────────────────
variable "jwt_secret_key" {
  description = "Clave secreta para JWT y SECRET_KEY de la app (mínimo 32 chars)"
  type        = string
  sensitive   = true
}

variable "allowed_origins" {
  description = "CORS origins permitidos (separados por comas)"
  type        = string
  default     = "*"
  # Producción: "https://tudominio.com,https://www.tudominio.com"
}

# ── Locals ─────────────────────────────────────────
locals {
  common_tags = {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "Terraform"
    Owner       = "TFG-Ciberseguridad-2026"
  }

  # Sufijo único de 6 chars para recursos con nombres globales
  # (Storage Account, ACR, Key Vault — deben ser únicos en Azure)
  unique_suffix = lower(substr(md5("${var.project_name}${var.environment}"), 0, 6))
}
