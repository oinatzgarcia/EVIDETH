# ─────────────────────────────────────────────────────────────
# EVIDETH — keyvault.tf
# Azure Key Vault para:
#  - Claves ECDSA P-256 de firma de segmentos
#  - Secretos: db-password, jwt-secret-key, storage-connection-string
# El Container App accede via Managed Identity (sin credenciales)
# ─────────────────────────────────────────────────────────────

data "azurerm_client_config" "current" {}

resource "azurerm_key_vault" "main" {
  name                        = "${var.project_name}-${var.environment}-kv-${local.unique_suffix}"
  resource_group_name         = azurerm_resource_group.main.name
  location                    = azurerm_resource_group.main.location
  enabled_for_disk_encryption = false
  tenant_id                   = data.azurerm_client_config.current.tenant_id
  soft_delete_retention_days  = 7
  purge_protection_enabled    = false # true en producción
  sku_name                    = "standard"

  tags = local.common_tags
}

# ── Access Policy: Terraform (para crear/leer secretos y claves) ──
resource "azurerm_key_vault_access_policy" "terraform" {
  key_vault_id = azurerm_key_vault.main.id
  tenant_id    = data.azurerm_client_config.current.tenant_id
  object_id    = data.azurerm_client_config.current.object_id

  secret_permissions = ["Get", "List", "Set", "Delete", "Purge", "Recover"]
  # GetRotationPolicy es necesario para que Terraform pueda crear
  # claves EC (ECDSA) sin error 403 ForbiddenByPolicy
  key_permissions = [
    "Get", "List", "Create", "Delete",
    "Sign", "Verify", "Update", "Purge", "Recover",
    "GetRotationPolicy", "SetRotationPolicy"
  ]
}

# NOTA: azurerm_key_vault_access_policy.container_app se define en
# container_app.tf para poder referenciar la Managed Identity del
# Container App en el mismo fichero donde se crea.

# ── Secretos en Key Vault ────────────────────────────────────
resource "azurerm_key_vault_secret" "jwt_secret" {
  name         = "jwt-secret-key"
  value        = var.jwt_secret_key
  key_vault_id = azurerm_key_vault.main.id
  depends_on   = [azurerm_key_vault_access_policy.terraform]
}

# ── Clave ECDSA P-256 para firma de segmentos ──────────────────
# Las cámaras la usan para firmar; el backend para verificar
resource "azurerm_key_vault_key" "ecdsa_signing" {
  name         = "evideth-signing-key" # Igual que ECDSA_KEY_NAME en .env.example
  key_vault_id = azurerm_key_vault.main.id
  key_type     = "EC"
  curve        = "P-256"
  key_opts     = ["sign", "verify"]
  depends_on   = [azurerm_key_vault_access_policy.terraform]
}
