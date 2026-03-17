# ─────────────────────────────────────────────────────────────
# EVIDETH — main.tf
# Punto de entrada de Terraform: provider, backend y recursos
# compartidos (Resource Group + Log Analytics)
# ─────────────────────────────────────────────────────────────

terraform {
  required_version = ">= 1.5"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.90"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.4.0"
    }
  }

  # ── Backend remoto (descomenta cuando tengas el Storage Account de tfstate) ──
  # backend "azurerm" {
  #   resource_group_name  = "evideth-tfstate-rg"
  #   storage_account_name = "evidethtfstate"
  #   container_name       = "tfstate"
  #   key                  = "evideth.terraform.tfstate"
  # }
}

provider "azurerm" {
  # Suscripción Azure for Students — especificada explícitamente
  # para evitar errores RequestDisallowedByAzure
  subscription_id = var.subscription_id

  features {
    key_vault {
      purge_soft_delete_on_destroy    = true
      recover_soft_deleted_key_vaults = true
    }
  }
}

# ── Resource Group ────────────────────────────────────────────
resource "azurerm_resource_group" "main" {
  name     = "${var.project_name}-${var.environment}-rg"
  location = var.location
  tags     = local.common_tags
}

# ── Log Analytics Workspace (monitorización + Container Apps) ─
resource "azurerm_log_analytics_workspace" "main" {
  name                = "${var.project_name}-${var.environment}-logs"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  sku                 = "PerGB2018"
  retention_in_days   = 30
  tags                = local.common_tags
}
