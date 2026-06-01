# EVIDETH
🔐 EVIDETH - Sistema Forense de Verificación de Integridad de Vídeo mediante hashing criptográfico (SHA-256) y firmas ECDSA.

<div align="center">
  <img src="Docs/Images/Logo.png" alt="Logo EVIDETH" width="360"/>
  
  # EVIDETH
  ### Sistema Forense de Verificación de Integridad de Vídeo
  
  **Hashing SHA-256 · Firmas ECDSA P-256 · Azure Cloud**
  
  <br/>
  
  <img src="Docs/Images/Dashboard.png" alt="Dashboard EVIDETH" width="85%"/>
  
  <br/>
  
  <p>
    <img src="https://img.shields.io/badge/Python-3.11+-blue.svg"/>
    <img src="https://img.shields.io/badge/FastAPI-0.109+-green.svg"/>
    <img src="https://img.shields.io/badge/Azure-Cloud-0078D4.svg"/>
  </p>
</div>

---

## 🎯 Descripción General

EVIDETH es un sistema de verificación de integridad de vídeo de grado forense que garantiza la autenticidad e inalterabilidad de grabaciones de vigilancia mediante firmas criptográficas.

**Características principales:**
- 🔐 Verificación criptográfica SHA-256 + ECDSA P-256
- 📹 Segmentación de vídeo en bloques de 30 segundos para análisis granular
- ☁️ Integración con Azure Key Vault
- 🦉 Inspirado en la sabiduría y vigilancia de Atenea

---

## 📚 Documentación

### 🏗️ Infraestructura y Despliegue

| Documento | Descripción |
|---|---|
| [Pipeline CI/CD](Docs/ci_cd_evideth.md) | Workflows de GitHub Actions: build, deploy, destroy y plan. Autenticación OIDC con Azure. |
| [Azure Key Vault](Docs/azure_key_vault.md) | Gestión de la clave ECDSA P-256 y secretos desde Key Vault. Managed Identity. |
| [Application Insights](Docs/application_insights.md) | Telemetría, trazas y métricas del backend en Azure Monitor. |
| [Logging y Observabilidad](Docs/logging_y_observabilidad.md) | Estructura de logs, niveles, correlación de trazas y Log Analytics Workspace. |

### 🔐 Seguridad e Identidades

| Documento | Descripción |
|---|---|
| [Gestión de Identidades](Docs/gestion_identidades.md) | JWT para usuarios, API Keys para cámaras, roles y control de acceso. |
| [Seguridad de Datos y Credenciales](Docs/seguridad_datos_y_credenciales.md) | Cifrado en tránsito y en reposo, gestión de secretos y modelo de amenazas. |

### 🧪 Testing

| Documento | Descripción |
|---|---|
| [Tests Unitarios y Escenarios](Docs/tests_unitarios_y_escenarios.md) | Cobertura de tests unitarios, fixtures y escenarios de prueba por módulo. |
| [Tests de Integración](Docs/tests_integracion.md) | Tests end-to-end contra la API real, base de datos y servicios Azure. |

### 🎨 Diseños

| Recurso | Descripción |
|---|---|
| [Diagrama de Arquitectura (PDF)](Docs/Designs/Schemes/InfraestructuraAzure.pdf) | Arquitectura completa de infraestructura Azure. |
| [Carpeta Designs](Docs/Designs/) | Diagramas, esquemas y mockups del sistema. |

---

## ☁️ Infraestructura Azure

EVIDETH está desplegado en **Microsoft Azure** (Spain Central) con una arquitectura privada y orientada a la seguridad. Todos los recursos se encuentran en el grupo de recursos `evideth-dev-rg`.

### Visión General de la Arquitectura

| Capa | Recurso | Función |
|---|---|---|
| **Red** | `capp-svc-lb` + `capp-svc-lb-ip` | Balanceador de carga público e IP de entrada |
| **Red** | `evideth-dev-app-nsg` | Grupo de seguridad de red — reglas de tráfico |
| **Red** | `evideth-dev-vnet` | Red virtual con subnets de aplicación y datos |
| **Cómputo** | `evideth-dev-backend` (Container App) | Backend FastAPI + frontend estático |
| **Cómputo** | `evideth-dev-cae` | Entorno de Container Apps |
| **Registro** | `evidethdevacr94f04b.azurecr.io` | Registro de imágenes Docker (pipeline CI/CD) |
| **Base de datos** | `evideth-dev-pgserver` | PostgreSQL Flexible Server — **solo acceso privado por VNet** |
| **Base de datos** | `evideth.postgres.database.azure.com` | Zona DNS privada para PostgreSQL |
| **Seguridad** | `evideth-dev-kv-94f04b` | Key Vault — clave ECDSA P-256 + secreto JWT |
| **Almacenamiento** | `evidethdevst94f04b` | Blob Storage — vídeos subidos |
| **Observabilidad** | `evideth-dev-logs` | Área de trabajo de Log Analytics |

### Decisiones de Seguridad Clave

- **PostgreSQL sin endpoint público** — accesible únicamente dentro de la VNet mediante zona DNS privada.
- **Acceso a Key Vault mediante Managed Identity** — sin credenciales almacenadas en el código ni en variables de entorno.
- **CI/CD con OIDC** — GitHub Actions se autentica en Azure mediante Workload Identity Federation; sin secretos de larga duración en GitHub.
- **JWT para usuarios, API Keys para cámaras** — mecanismos de autenticación independientes según el tipo de cliente.

### Flujo CI/CD

```
GitHub Push → GitHub Actions (OIDC) → Terraform Apply (infra)
  → Build imagen Docker → Push al ACR → Container App actualizado
```

### Flujo de Petición

```
Cámara (API Key) ──► Balanceador de carga ──► Container App
                                                    │
                               ┌────────────────────┼────────────────────┐
                               ▼                    ▼                    ▼
                          Key Vault           PostgreSQL           Blob Storage
                        (clave ECDSA)     (hashes + firmas)         (vídeos)
```

📄 **[Diagrama de Arquitectura Completo (PDF)](Docs/Designs/Schemes/InfraestructuraAzure.pdf)**
