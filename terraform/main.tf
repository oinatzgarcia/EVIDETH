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
    # Necesario para time_sleep: evita error 412 al crear Container App
    # esperando propagación de identidad y permisos de Key Vault
    time = {
      source  = "hashicorp/time"
      version = ">= 0.9.0"
    }
  }

  # ── Backend remoto: estado guardado en Azure Storage ────────────
  backend "azurerm" {
    resource_group_name  = "rg-evideth"
    storage_account_name = "evidethtfstate"
    container_name       = "tfstate"
    key                  = "evideth.terraform.tfstate"
    use_oidc             = true
  }
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
    resource_group {
      # Permite borrar el RG aunque contenga recursos no gestionados
      # por Terraform (p.ej. storage accounts de prueba creados manualmente)
      prevent_deletion_if_contains_resources = false
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
