from pydantic import ConfigDict, field_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # App
    APP_NAME: str = "EVIDETH"
    APP_ENV: str = "development"  # development | production | test
    DEBUG: bool = False
    SECRET_KEY: str = "dev-fallback-change-in-production"

    # Database
    DATABASE_URL: str = "postgresql://evideth:evideth@localhost:5432/evideth"

    # JWT
    JWT_SECRET_KEY: str = "dev-fallback-change-in-production"
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # Azure Key Vault
    AZURE_KEY_VAULT_URL: str = ""
    AZURE_CLIENT_ID: str = ""
    AZURE_CLIENT_SECRET: str = ""
    AZURE_TENANT_ID: str = ""

    # Azure Blob Storage
    AZURE_STORAGE_CONNECTION_STRING: str = ""
    AZURE_BLOB_CONTAINER: str = "evideth-videos"

    # Azure Application Insights
    # Formato: InstrumentationKey=xxx;IngestionEndpoint=https://...;
    # Dejar vacío en local/test para deshabilitar el exporter.
    APPLICATIONINSIGHTS_CONNECTION_STRING: str = ""

    @field_validator("JWT_SECRET_KEY")
    @classmethod
    def validate_jwt_secret(cls, v: str, info) -> str:
        """
        En producción (APP_ENV=production) la clave JWT debe:
        - Tener al menos 32 caracteres (256 bits mínimo NIST SP 800-107)
        - No ser el valor por defecto de desarrollo
        Ref: OWASP ASVS §3.5.2
        """
        import os
        env = os.getenv("APP_ENV", "development")
        weak_defaults = {
            "dev-fallback-change-in-production",
            "secret",
            "changeme",
            "password",
        }
        if env == "production":
            if v in weak_defaults:
                raise ValueError(
                    "JWT_SECRET_KEY usa un valor por defecto inseguro. "
                    "Configura una clave de al menos 32 caracteres en producción."
                )
            if len(v) < 32:
                raise ValueError(
                    f"JWT_SECRET_KEY demasiado corta ({len(v)} chars). "
                    "Mínimo 32 caracteres (NIST SP 800-107)."
                )
        return v

    @field_validator("DATABASE_URL")
    @classmethod
    def validate_db_url(cls, v: str) -> str:
        """
        Detecta credenciales débiles conocidas en la DATABASE_URL.
        En producción, la URL no debe contener contraseñas triviales.
        Ref: OWASP ASVS §2.1 (fuerza de credenciales).
        """
        import os
        env = os.getenv("APP_ENV", "development")
        weak_passwords = {":evideth@", ":password@", ":changeme@", ":secret@", ":1234@", ":admin@"}
        if env == "production":
            for weak in weak_passwords:
                if weak in v:
                    raise ValueError(
                        f"DATABASE_URL contiene una contraseña débil conocida ('{weak.strip(':@')}'). "
                        "Usa una contraseña robusta en producción."
                    )
        return v

    model_config = ConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()
