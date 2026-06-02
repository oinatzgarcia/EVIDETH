# Arquitectura Azure — EVIDETH

> **Entorno:** `dev` · **Región principal:** Spain Central · **TFG Ingeniería en Ciberseguridad 2026**

---

## Resource Groups

| Nombre | Región | Propósito |
|--------|--------|-----------|
| `evideth-dev-rg` | Spain Central | Recursos principales de la aplicación |
| `rg-evideth` | West Europe | Terraform state + OIDC identity |
| `ME_evideth-dev-cae_evideth-dev-rg_spaincentral` | Spain Central | Managed RG (gestionado por Azure CAE) |
| `NetworkWatcherRG` | Spain Central | Network Watcher (auto-creado) |
| `test` | Spain Central | Pruebas y experimentos |

---

## evideth-dev-rg — Recursos principales

### 🐳 Compute / Contenedores

| Recurso | Tipo | Detalle |
|---------|------|---------|
| `evideth-dev-backend` | Container App | FQDN público · `evideth-dev-backend.icywave-c2a647eb.spaincentral.azurecontainerapps.io` |
| `evideth-dev-cae` | Container Apps Environment | Entorno gestionado que aloja la Container App |
| `evidethdevacr94f04b` | Container Registry (ACR) | Almacena la imagen Docker del backend |

### 🗄️ Base de datos

| Recurso | Tipo | Detalle |
|---------|------|---------|
| `evideth-dev-pgserver` | PostgreSQL Flexible Server v16 | SKU `Standard_B1ms` · 32 GiB · Single AZ |

### 💾 Almacenamiento

| Recurso | Tipo | Detalle |
|---------|------|---------|
| `evidethdevst94f04b` | Storage Account | Blob Storage para segmentos de vídeo |

### 🔑 Seguridad

| Recurso | Tipo | Detalle |
|---------|------|---------|
| `evideth-dev-kv-94f04b` | Key Vault | Clave ECDSA P-256 para firma de hashes SHA-256 |

### 🌐 Red

| Recurso | Tipo | Detalle |
|---------|------|---------|
| `evideth-dev-vnet` | Virtual Network | Red privada principal |
| `evideth-dev-app-nsg` | Network Security Group | Reglas de tráfico para la app |
| `evideth-dev.postgres.database.azure.com` | Private DNS Zone | Resolución DNS interna del PostgreSQL |
| `evideth-dev.postgres.database.azure.com/evideth-dev-dns-link` | VNet Link | Enlaza la DNS Zone con la VNet |

### 📊 Observabilidad

| Recurso | Tipo | Detalle |
|---------|------|---------|
| `evideth-dev-logs` | Log Analytics Workspace | Logs centralizados del entorno dev |

---

## rg-evideth — Terraform state + OIDC

| Recurso | Tipo | Detalle |
|---------|------|---------|
| `evidethtfstate` | Storage Account | Remote state de Terraform (West Europe) |
| `evideth-github-oidc` | User Assigned Managed Identity | Autenticación OIDC sin secretos para GitHub Actions |

---

## ME_evideth-dev-cae_... — Managed Resource Group

> Gestionado automáticamente por Azure Container Apps Environment. No modificar manualmente.

| Recurso | Tipo | Detalle |
|---------|------|---------|
| `capp-svc-lb` | Load Balancer | Distribuye el tráfico entrante a la Container App |
| `capp-svc-lb-ip` | Public IP Address | IP pública del Load Balancer |

---

## Flujo de datos y conexiones

```
Internet
    │  HTTPS
    ▼
capp-svc-lb (Public IP)
    │
    ▼
evideth-dev-backend (Container App)
    ├──► evideth-dev-pgserver          [TCP 5432, DNS privado, dentro de VNet]
    ├──► evidethdevst94f04b            [HTTPS, Blob Storage, segmentos de vídeo]
    └──► evideth-dev-kv-94f04b         [HTTPS, clave ECDSA P-256 para firma SHA-256]

evidethdevacr94f04b (ACR)
    └──► evideth-dev-backend           [pull imagen Docker evideth-backend:latest]
```

---

## Pipeline CI/CD — GitHub Actions

```
git push (main / develop)
    │
    ▼
ci.yml  ─── Orquestador
    ├──► backend.yml      Ruff · pytest · Alembic check
    ├──► frontend.yml     Lint · static assets
    └──► infra.yml        terraform fmt · validate · plan
              │
              ▼  (solo en main)
    build-push.yml        Docker build → push ACR
              │
              ▼
    terraform-apply.yml   Infra → Azure (via OIDC)
              │
              ▼
    Container App actualizado ✅
```

### Autenticación GitHub → Azure

GitHub Actions se autentica con Azure usando **Workload Identity Federation (OIDC)** a través de la Managed Identity `evideth-github-oidc`, sin necesidad de almacenar ningún `CLIENT_SECRET` como secreto del repositorio.

---

## Seguridad criptográfica

| Componente | Estándar | Implementación |
|------------|----------|----------------|
| Hash de segmentos de vídeo | SHA-256 (NIST FIPS 180-4) | OpenCV + Python `hashlib` |
| Firma digital | ECDSA P-256 (NIST FIPS 186-4) | Azure Key Vault · clave `evideth-signing-key` |
| Autenticación usuarios | JWT (RFC 7519) | FastAPI + `python-jose` |
| Autenticación cámaras | API Keys | Header `X-API-Key` |
| Autenticación CI/CD | OIDC (RFC 6749) | Workload Identity Federation |

---

*Diagrama generado automáticamente · evideth-dev-backend.icywave-c2a647eb.spaincentral.azurecontainerapps.io*
