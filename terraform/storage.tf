# ─────────────────────────────────────────────────────────────
# EVIDETH — storage.tf
# Azure Blob Storage para vídeos y segmentos procesados.
# Nombre del container: "evideth-videos"
# (coincide con AZURE_STORAGE_CONTAINER_NAME del .env.example)
# ─────────────────────────────────────────────────────────────

resource "azurerm_storage_account" "main" {
  name                     = "${var.project_name}${var.environment}st${local.unique_suffix}"
  resource_group_name      = azurerm_resource_group.main.name
  location                 = azurerm_resource_group.main.location
  account_tier             = "Standard"
  account_replication_type = "LRS" # Locally Redundant (dev); usar GRS en prod
  min_tls_version          = "TLS1_2"

  blob_properties {
    delete_retention_policy {
      days = 7
    }
  }

  tags = local.common_tags
}

# ── Contenedor para vídeos originales y segmentos ────────────
# Nombre: "evideth-videos" — igual que AZURE_STORAGE_CONTAINER_NAME en .env.example
resource "azurerm_storage_container" "videos" {
  name                  = "evideth-videos"
  storage_account_name  = azurerm_storage_account.main.name
  container_access_type = "private"
}

# ── Guardar connection string en Key Vault ───────────────────
resource "azurerm_key_vault_secret" "storage_connection" {
  name         = "storage-connection-string"
  value        = azurerm_storage_account.main.primary_connection_string
  key_vault_id = azurerm_key_vault.main.id

  depends_on = [azurerm_key_vault_access_policy.terraform]
}
