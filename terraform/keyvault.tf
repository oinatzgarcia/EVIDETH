# ─────────────────────────────────────────────────────────────
# EVIDETH — keyvault.tf
# Azure Key Vault para:
#  - Claves ECDSA P-256 de firma de segmentos
#  - Secretos: jwt-secret-key
# El Container App accede via Managed Identity (sin credenciales)
#
# IMPORTANTE: usamos el modelo Access Policy (no RBAC).
# enable_rbac_authorization = false es OBLIGATORIO para que el
# Service Principal de Terraform pueda crear/gestionar claves y
# secretos cuando se despliega desde una cuenta educativa (@euneiz)
# que tiene restricciones de Conditional Access en el tenant.
# ─────────────────────────────────────────────────────────────

data "azurerm_client_config" "current" {}

resource "azurerm_key_vault" "main" {
  name                        = "${var.project_name}-${var.environment}-kv-${local.unique_suffix}"
  resource_group_name         = azurerm_resource_group.main.name
  location                    = azurerm_resource_group.main.location
  enabled_for_disk_encryption = false
  tenant_id                   = data.azurerm_client_config.current.tenant_id
  soft_delete_retention_days  = 7
  purge_protection_enabled    = false   # true en producción
  sku_name                    = "standard"

  # ── CRÍTICO: forzar Access Policies (modelo legacy pero funcional
  # con SP de Terraform en tenants con políticas universitarias).
  # Si se omite o se pone true, Azure CLI y el portal pueden activar
  # RBAC y bloquear al SP con Forbidden aunque tenga el rol asignado.
  enable_rbac_authorization   = false

  tags = local.common_tags
}

# ── Access Policy: Service Principal de Terraform ────────────
# Permisos completos para gestionar secretos y claves ECDSA.
# GetRotationPolicy + SetRotationPolicy son necesarios en
# azurerm provider >= 3.x para crear claves EC sin error 403.
resource "azurerm_key_vault_access_policy" "terraform" {
  key_vault_id = azurerm_key_vault.main.id
  tenant_id    = data.azurerm_client_config.current.tenant_id
  object_id    = data.azurerm_client_config.current.object_id

  secret_permissions = [
    "Get", "List", "Set", "Delete", "Purge", "Recover"
  ]

  key_permissions = [
    "Get", "List", "Create", "Delete",
    "Sign", "Verify", "Update", "Purge", "Recover",
    "GetRotationPolicy", "SetRotationPolicy"
  ]
}

# NOTA: azurerm_key_vault_access_policy.container_app se define en
# container_app.tf para referenciar la Managed Identity del
# Container App en el mismo fichero donde se crea.

# ── Secretos en Key Vault ────────────────────────────────────
resource "azurerm_key_vault_secret" "jwt_secret" {
  name         = "jwt-secret-key"
  value        = var.jwt_secret_key
  key_vault_id = azurerm_key_vault.main.id
  depends_on   = [azurerm_key_vault_access_policy.terraform]
}

# ── Clave ECDSA P-256 para firma de segmentos ──────────────────
# Las cámaras la usan para firmar (simulador); el backend verifica.
# Nombre igual a ECDSA_KEY_NAME en .env.example
#
# depends_on incluye la access policy del Container App (definida
# en container_app.tf) para garantizar que ambas policies están
# activas antes de intentar crear la clave.
resource "azurerm_key_vault_key" "ecdsa_signing" {
  name         = "evideth-signing-key"
  key_vault_id = azurerm_key_vault.main.id
  key_type     = "EC"
  curve        = "P-256"
  key_opts     = ["sign", "verify"]

  depends_on = [
    azurerm_key_vault_access_policy.terraform,
    azurerm_key_vault_access_policy.container_app,
  ]
}
