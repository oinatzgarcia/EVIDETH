# ─────────────────────────────────────────────────────────────
# EVIDETH — registry.tf
# Azure Container Registry (ACR) para alojar la imagen Docker
# del backend FastAPI.
#
# Uso:
#   docker build -t <acr_login_server>/evideth-backend:latest .
#   docker push <acr_login_server>/evideth-backend:latest
# ─────────────────────────────────────────────────────────────

resource "azurerm_container_registry" "main" {
  name                = "${var.project_name}${var.environment}acr${local.unique_suffix}"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  sku                 = "Basic"    # ~5 EUR/mes
  admin_enabled       = true       # Necesario para Container Apps con SKU Basic

  tags = local.common_tags
}
