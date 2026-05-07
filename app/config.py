from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    # App
    APP_NAME: str = "EVIDETH"
    APP_ENV:  str = "development"   # development | production | test
    DEBUG:    bool = False
    SECRET_KEY: str

    # Database
    DATABASE_URL: str

    # JWT
    JWT_SECRET_KEY: str
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    JWT_REFRESH_TOKEN_EXPIRE_DAYS:   int = 7

    # Azure Key Vault
    AZURE_KEY_VAULT_URL:    str = ""
    AZURE_CLIENT_ID:        str = ""
    AZURE_CLIENT_SECRET:    str = ""
    AZURE_TENANT_ID:        str = ""

    # Azure Blob Storage
    AZURE_STORAGE_CONNECTION_STRING: str = ""
    AZURE_BLOB_CONTAINER:            str = "evideth-videos"

    class Config:
        env_file = ".env"
        extra    = "ignore"   # ignora variables de .env no declaradas

settings = Settings()
