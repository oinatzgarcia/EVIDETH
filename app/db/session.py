from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from app.config import settings

Base = declarative_base()

# Lazy singletons — el engine NO se crea al importar el módulo.
# Se inicializa la primera vez que get_db() es llamado.
# Esto evita que psycopg2 se cargue durante la recolección de tests
# unitarios que no necesitan base de datos.
_engine = None
_SessionLocal = None


def _get_engine():
    global _engine
    if _engine is None:
        connect_args = (
            {"check_same_thread": False}
            if "sqlite" in settings.DATABASE_URL
            else {}
        )
        _engine = create_engine(settings.DATABASE_URL, connect_args=connect_args)
    return _engine


def _get_session_local():
    global _SessionLocal
    if _SessionLocal is None:
        _SessionLocal = sessionmaker(
            autocommit=False, autoflush=False, bind=_get_engine()
        )
    return _SessionLocal


def get_db():
    SessionLocal = _get_session_local()
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Compatibilidad: algunos módulos importan `engine` y `SessionLocal` directamente.
# Estos proxies delegan al singleton lazy sin romper esos imports.
class _EngineProxy:
    def __getattr__(self, name):
        return getattr(_get_engine(), name)

    def __repr__(self):
        return repr(_get_engine())


class _SessionProxy:
    def __call__(self, *args, **kwargs):
        return _get_session_local()(*args, **kwargs)

    def __getattr__(self, name):
        return getattr(_get_session_local(), name)


engine = _EngineProxy()
SessionLocal = _SessionProxy()
