# ─────────────────────────────────────────────────────────────
# EVIDETH — container_app.tf
# Container App Environment + Container App del backend FastAPI
#
# Variables de entorno inyectadas coinciden EXACTAMENTE con
# los nombres definidos en .env.example del proyecto.
# ─────────────────────────────────────────────────────────────

# ── Container App Environment ────────────────────────────────
resource "azurerm_container_app_environment" "main" {
  name                       = "${var.project_name}-${var.environment}-cae"
  resource_group_name        = azurerm_resource_group.main.name
  location                   = azurerm_resource_group.main.location
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id
  infrastructure_subnet_id   = azurerm_subnet.app.id   # Necesario para alcanzar PG privado
  tags                       = local.common_tags

  # Evitar que Terraform intente recrear el CAE por el campo
  # infrastructure_resource_group_name que Azure gestiona solo
  lifecycle {
    ignore_changes = [infrastructure_resource_group_name]
  }
}

# ── Espera propagación de identidad/permisos tras crear el CAE ──
# Azure necesita ~30s para que la Managed Identity sea válida
# y el Key Vault Access Policy esté activo antes de leer secretos.
# Sin esta espera aparece el error 412 Precondition Failed.
resource "time_sleep" "wait_for_identity" {
  depends_on = [
    azurerm_container_app_environment.main,
    azurerm_key_vault_access_policy.terraform,
  ]
  create_duration = "30s"
}

# ── Connection string PostgreSQL (formato DATABASE_URL) ───────
# Formato: postgresql://user:pass@host:5432/db?sslmode=require
# Igual que DATABASE_URL en .env.example
locals {
  db_connection_string = "postgresql://${var.db_admin_user}:${random_password.db_password.result}@${azurerm_postgresql_flexible_server.main.fqdn}:5432/${var.db_name}?sslmode=require"
}

# ── Container App — Backend EVIDETH ──────────────────────────
resource "azurerm_container_app" "backend" {
  name                         = "${var.project_name}-${var.environment}-backend"
  container_app_environment_id = azurerm_container_app_environment.main.id
  resource_group_name          = azurerm_resource_group.main.name
  revision_mode                = "Single"

  # Managed Identity: acceso a Key Vault y ACR sin credenciales hardcodeadas
  identity {
    type = "SystemAssigned"
  }

  # ── Autenticación con ACR ─────────────────────────────────
  registry {
    server               = azurerm_container_registry.main.login_server
    username             = azurerm_container_registry.main.admin_username
    password_secret_name = "acr-password"
  }

  # ── Secrets (valores sensibles — no aparecen en logs) ─────
  secret {
    name  = "acr-password"
    value = azurerm_container_registry.main.admin_password
  }
  secret {
    name  = "database-url"
    value = local.db_connection_string
  }
  secret {
    name  = "jwt-secret-key"
    value = var.jwt_secret_key
  }
  secret {
    name  = "storage-connection-string"
    value = azurerm_storage_account.main.primary_connection_string
  }

  template {
    min_replicas = var.backend_min_replicas
    max_replicas = var.backend_max_replicas

    container {
      name   = "evideth-backend"
      image  = "${azurerm_container_registry.main.login_server}/evideth-backend:${var.backend_image_tag}"
      cpu    = var.backend_cpu
      memory = var.backend_memory

      # ── Variables de entorno ────────────────────────────────
      # Nombres EXACTOS del .env.example del proyecto

      # App
      env {
        name  = "APP_NAME"
        value = "EVIDETH"
      }
      env {
        name  = "APP_ENV"
        value = var.environment == "prod" ? "production" : "development"
      }
      env {
        name  = "APP_PORT"
        value = "8000"
      }
      env {
        name  = "DEBUG"
        value = var.environment == "prod" ? "False" : "True"
      }

      # Auth
      env {
        name        = "SECRET_KEY"
        secret_name = "jwt-secret-key"
      }
      env {
        name        = "JWT_SECRET_KEY"
        secret_name = "jwt-secret-key"
      }
      env {
        name  = "JWT_ALGORITHM"
        value = "HS256"
      }
      env {
        name  = "JWT_ACCESS_TOKEN_EXPIRE_MINUTES"
        value = "30"
      }
      env {
        name  = "JWT_REFRESH_TOKEN_EXPIRE_DAYS"
        value = "7"
      }

      # Base de datos (DATABASE_URL y variables individuales)
      env {
        name        = "DATABASE_URL"
        secret_name = "database-url"
      }
      env {
        name  = "DB_HOST"
        value = azurerm_postgresql_flexible_server.main.fqdn
      }
      env {
        name  = "DB_PORT"
        value = "5432"
      }
      env {
        name  = "DB_NAME"
        value = var.db_name
      }
      env {
        name  = "DB_USER"
        value = var.db_admin_user
      }

      # Azure Key Vault — autenticación via Managed Identity
      env {
        name  = "AZURE_KEY_VAULT_URL"
        value = azurerm_key_vault.main.vault_uri
      }
      env {
        name  = "AZURE_TENANT_ID"
        value = data.azurerm_client_config.current.tenant_id
      }
      # AZURE_CLIENT_ID es inyectado automáticamente por Azure con Managed Identity
      # NO usar AZURE_CLIENT_SECRET con Managed Identity (más seguro)

      # Azure Blob Storage
      env {
        name        = "AZURE_STORAGE_CONNECTION_STRING"
        secret_name = "storage-connection-string"
      }
      env {
        name  = "AZURE_STORAGE_CONTAINER_NAME"
        value = azurerm_storage_container.videos.name
      }

      # Criptografía ECDSA
      env {
        name  = "ECDSA_KEY_NAME"
        value = "evideth-signing-key"
      }
      env {
        name  = "HASH_ALGORITHM"
        value = "SHA-256"
      }
      env {
        name  = "SEGMENT_DURATION_SECONDS"
        value = "30"
      }

      # Procesamiento de vídeo
      env {
        name  = "MAX_VIDEO_SIZE_MB"
        value = "500"
      }
      env {
        name  = "UPLOAD_TEMP_DIR"
        value = "/tmp/uploads/temp"
      }
      env {
        name  = "SEGMENTS_DIR"
        value = "/tmp/uploads/segments"
      }
      env {
        name  = "SUPPORTED_FORMATS"
        value = "mp4,avi,mov,mkv"
      }

      # CORS
      env {
        name  = "CORS_ORIGINS"
        value = var.allowed_origins
      }
      env {
        name  = "CORS_ALLOW_CREDENTIALS"
        value = "True"
      }

      # Logging
      env {
        name  = "LOG_LEVEL"
        value = var.environment == "prod" ? "WARNING" : "INFO"
      }

      # ── Health checks ──────────────────────────────────────
      liveness_probe {
        transport               = "HTTP"
        path                    = "/api/v1/health"
        port                    = 8000
        initial_delay           = 40
        interval_seconds        = 30
        failure_count_threshold = 3
      }

      readiness_probe {
        transport        = "HTTP"
        path             = "/api/v1/health"
        port             = 8000
        interval_seconds = 10
      }
    }

    # ── Autoescalado por peticiones HTTP concurrentes ────────
    custom_scale_rule {
      name             = "http-scaling"
      custom_rule_type = "http"
      metadata = {
        concurrentRequests = "20"
      }
    }
  }

  # ── Ingress HTTPS público ─────────────────────────────────
  ingress {
    external_enabled = true
    target_port      = 8000
    transport        = "http"

    traffic_weight {
      percentage      = 100
      latest_revision = true
    }
  }

  tags = local.common_tags

  depends_on = [
    azurerm_postgresql_flexible_server_database.evideth,
    azurerm_key_vault_access_policy.terraform,
    azurerm_storage_container.videos,
    # Espera a que la identidad y los permisos del CAE estén propagados
    # antes de que Azure intente resolver los secrets (evita error 412)
    time_sleep.wait_for_identity,
  ]
}

# ── Rol AcrPull: Container App puede descargar imágenes del ACR ──
# NOTA: depende de la identidad del Container App ya creado
resource "azurerm_role_assignment" "acr_pull" {
  principal_id         = azurerm_container_app.backend.identity[0].principal_id
  role_definition_name = "AcrPull"
  scope                = azurerm_container_registry.main.id

  depends_on = [azurerm_container_app.backend]
}

# ── Access Policy para la Managed Identity del Container App ──
# Se crea DESPUÉS del Container App (necesitamos el principal_id)
resource "azurerm_key_vault_access_policy" "container_app" {
  key_vault_id = azurerm_key_vault.main.id
  tenant_id    = data.azurerm_client_config.current.tenant_id
  object_id    = azurerm_container_app.backend.identity[0].principal_id

  key_permissions = [
    "Get", "List", "Sign", "Verify",
  ]
  secret_permissions = [
    "Get", "List",
  ]

  depends_on = [azurerm_container_app.backend]
}
