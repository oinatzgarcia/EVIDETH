# EVIDETH
🔐 EVIDETH - Forensic Video Integrity Verification System using cryptographic hashing (SHA-256) and ECDSA signatures.
<div align="center">
  <img src="Docs/Images/Logo.png" alt="EVIDETH Logo" width="360"/>
  
  # EVIDETH
  ### Forensic Video Integrity Verification System
  
  **SHA-256 Hashing · ECDSA P-256 Signatures · Azure Cloud**
  
  <br/>
  
  <img src="Docs/Images/Dashboard.png" alt="EVIDETH Dashboard" width="85%"/>
  
  <br/>
  
  <p>
    <img src="https://img.shields.io/badge/Python-3.11+-blue.svg"/>
    <img src="https://img.shields.io/badge/FastAPI-0.109+-green.svg"/>
    <img src="https://img.shields.io/badge/Azure-Cloud-0078D4.svg"/>
  </p>
</div>

---

## 🎯 Overview

EVIDETH is a forensic-grade video integrity verification system that ensures authenticity and tamper-proof surveillance footage through cryptographic signatures.

**Key Features:**
- 🔐 SHA-256 + ECDSA P-256 cryptographic verification
- 📹 30-second video segmentation for granular analysis
- ☁️ Azure Key Vault integration
- 🦉 Inspired by Athena's wisdom and vigilance

---

## ☁️ Azure Cloud Infrastructure

EVIDETH is deployed on **Microsoft Azure** (Spain Central) using a private, security-first architecture. All resources live in the `evideth-dev-rg` resource group.

### Architecture Overview

| Layer | Resource | Purpose |
|---|---|---|
| **Network** | `capp-svc-lb` + `capp-svc-lb-ip` | Public load balancer & IP entry point |
| **Network** | `evideth-dev-app-nsg` | Network Security Group — traffic rules |
| **Network** | `evideth-dev-vnet` | Virtual Network with app + data subnets |
| **Compute** | `evideth-dev-backend` (Container App) | FastAPI backend + static frontend |
| **Compute** | `evideth-dev-cae` | Container Apps Environment |
| **Registry** | `evidethdevacr94f04b.azurecr.io` | Docker image registry (CI/CD pipeline) |
| **Database** | `evideth-dev-pgserver` | PostgreSQL Flexible Server — **private VNet only** |
| **Database** | `evideth.postgres.database.azure.com` | Private DNS zone for PostgreSQL |
| **Security** | `evideth-dev-kv-94f04b` | Key Vault — ECDSA P-256 key + JWT secret |
| **Storage** | `evidethdevst94f04b` | Blob Storage — uploaded videos |
| **Observability** | `evideth-dev-logs` | Log Analytics Workspace |

### Key Security Decisions

- **PostgreSQL has no public endpoint** — accessible only within the VNet via private DNS zone.
- **Key Vault access via Managed Identity** — no credentials stored in code or environment variables.
- **CI/CD with OIDC** — GitHub Actions authenticates to Azure via Workload Identity Federation; no long-lived secrets in GitHub.
- **JWT for users, API Keys for cameras** — separate authentication mechanisms per client type.

### CI/CD Flow

```
GitHub Push → GitHub Actions (OIDC) → Build Docker image
  → Push to ACR (evidethdevacr94f04b) → Update Container App
```

### Request Flow

```
Camera (API Key) ──► Load Balancer ──► Container App
                                           │
                              ┌────────────┼────────────┐
                              ▼            ▼            ▼
                         Key Vault    PostgreSQL    Blob Storage
                        (ECDSA key)  (hashes+sigs)   (videos)
```

📄 **[Full Architecture Diagram (PDF)](Docs/Designs/Schemes/InfraestructuraAzure.pdf)**
