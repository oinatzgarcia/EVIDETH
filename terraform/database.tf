# ─────────────────────────────────────────────────────────────
# EVIDETH — database.tf
# PostgreSQL Flexible Server 16 + base de datos evideth_db
# La BD es PRIVADA: solo accesible desde la VNet (subnet-db)
# ─────────────────────────────────────────────────────────────

# Password aleatoria segura (24 chars con especiales)
resource "random_password" "db_password" {
  length           = 24
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

# ── PostgreSQL Flexible Server ───────────────────────────────
resource "azurerm_postgresql_flexible_server" "main" {
  name                   = "${var.project_name}-${var.environment}-pgserver"
  resource_group_name    = azurerm_resource_group.main.name
  location               = azurerm_resource_group.main.location
  version                = "16"
  delegated_subnet_id    = azurerm_subnet.db.id
  private_dns_zone_id    = azurerm_private_dns_zone.postgres.id
  administrator_login    = var.db_admin_user
  administrator_password = random_password.db_password.result

  sku_name   = var.db_sku     # B_Standard_B1ms (~10 EUR/mes)
  storage_mb = 32768          # 32 GB

  backup_retention_days        = 7
  geo_redundant_backup_enabled = false   # Solo en prod

  # Azure gestiona zonas de disponibilidad automáticamente
  lifecycle {
    ignore_changes = [zone, high_availability[0].standby_availability_zone]
  }

  depends_on = [azurerm_private_dns_zone_virtual_network_link.postgres]

  tags = local.common_tags
}

# ── Base de datos EVIDETH ─────────────────────────────────────
# Nombre: evideth_db (igual que DB_NAME en .env.example)
resource "azurerm_postgresql_flexible_server_database" "evideth" {
  name      = var.db_name    # evideth_db
  server_id = azurerm_postgresql_flexible_server.main.id
  collation = "en_US.utf8"
  charset   = "utf8"
}

# ── Extensiones PostgreSQL ────────────────────────────────────
# pgcrypto: funciones criptográficas en BD
# uuid-ossp: generación de UUIDs (usado por SQLAlchemy)
resource "azurerm_postgresql_flexible_server_configuration" "extensions" {
  name      = "azure.extensions"
  server_id = azurerm_postgresql_flexible_server.main.id
  value     = "PGCRYPTO,UUID-OSSP"
}

# ── Guardar password en Key Vault ────────────────────────────
resource "azurerm_key_vault_secret" "db_password" {
  name         = "db-password"
  value        = random_password.db_password.result
  key_vault_id = azurerm_key_vault.main.id

  depends_on = [azurerm_key_vault_access_policy.terraform]
}
