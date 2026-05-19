# ─────────────────────────────────────────────────────────────
# EVIDETH — outputs.tf
# Valores de salida tras el terraform apply.
# Ejecuta: terraform output <nombre> para obtener un valor.
# ─────────────────────────────────────────────────────────────

# ── URL pública del backend ───────────────────────────────────
# Esta URL la necesita el simulador de cámara en local
output "backend_url" {
  description = "URL HTTPS pública del backend. Configúrala en simulator/.env como EVIDETH_API_URL"
  value       = "https://${azurerm_container_app.backend.ingress[0].fqdn}"
}

# ── ACR ───────────────────────────────────────────────────────
output "acr_login_server" {
  description = "URL del Container Registry. Usa: docker login <este_valor>"
  value       = azurerm_container_registry.main.login_server
}

output "acr_admin_username" {
  description = "Usuario admin del ACR para docker login"
  value       = azurerm_container_registry.main.admin_username
}

output "acr_admin_password" {
  description = "Password del ACR (sensible). Usa: terraform output -raw acr_admin_password"
  value       = azurerm_container_registry.main.admin_password
  sensitive   = true
}

# ── Key Vault ─────────────────────────────────────────────────
output "key_vault_url" {
  description = "URL del Key Vault. Configúrala en .env como AZURE_KEY_VAULT_URL"
  value       = azurerm_key_vault.main.vault_uri
}

output "ecdsa_key_id" {
  description = "ID completo (versioned) de la clave ECDSA P-256. Úsalo para verificar creación."
  value       = azurerm_key_vault_key.ecdsa_signing.id
}

output "ecdsa_key_name" {
  description = "Nombre lógico de la clave ECDSA. Cópialo en .env como ECDSA_KEY_NAME"
  value       = azurerm_key_vault_key.ecdsa_signing.name
}

# ── Storage ───────────────────────────────────────────────────
output "storage_account_name" {
  description = "Nombre del Storage Account de Azure Blob Storage"
  value       = azurerm_storage_account.main.name
}

output "storage_container_name" {
  description = "Nombre del contenedor de vídeos (evideth-videos)"
  value       = azurerm_storage_container.videos.name
}

# ── PostgreSQL ────────────────────────────────────────────────
output "postgresql_fqdn" {
  description = "FQDN del servidor PostgreSQL (solo accesible desde la VNet)"
  value       = azurerm_postgresql_flexible_server.main.fqdn
}

output "db_admin_password" {
  description = "Password generada aleatoriamente para PostgreSQL (SENSIBLE)"
  value       = random_password.db_password.result
  sensitive   = true
}

# ── Infraestructura ───────────────────────────────────────────
output "resource_group_name" {
  description = "Nombre del Resource Group en Azure"
  value       = azurerm_resource_group.main.name
}

output "container_app_name" {
  description = "Nombre del Container App para comandos az containerapp"
  value       = azurerm_container_app.backend.name
}

output "tenant_id" {
  description = "Tenant ID de Azure (para AZURE_TENANT_ID en el simulador local)"
  value       = data.azurerm_client_config.current.tenant_id
}

# ── Resumen de despliegue ─────────────────────────────────────
output "deploy_summary" {
  description = "Resumen del despliegue"
  value = <<-EOT
    ╔══════════════════════════════════════════════════════╗
    ║           EVIDETH — Despliegue completado            ║
    ╠══════════════════════════════════════════════════════╣
    ║  Backend URL : https://${azurerm_container_app.backend.ingress[0].fqdn}
    ║  ACR         : ${azurerm_container_registry.main.login_server}
    ║  Key Vault   : ${azurerm_key_vault.main.vault_uri}
    ║  ECDSA Key   : ${azurerm_key_vault_key.ecdsa_signing.name}
    ║  PostgreSQL  : ${azurerm_postgresql_flexible_server.main.fqdn}
    ║  RG          : ${azurerm_resource_group.main.name}
    ╚══════════════════════════════════════════════════════╝
    Próximos pasos:
      1. docker build + push al ACR
      2. az containerapp update --image ...
      3. Ejecutar alembic upgrade head
      4. Configurar simulator/.env con EVIDETH_API_URL
  EOT
}
