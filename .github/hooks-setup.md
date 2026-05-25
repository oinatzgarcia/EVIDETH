# Configuración de Git Hooks (pre-commit)

EVIDETH usa [pre-commit](https://pre-commit.com/) para ejecutar automáticamente checks de seguridad y calidad **antes de cada `git commit` local**.

## ¿Qué hace cada hook?

| Hook | Qué detecta / hace |
|---|---|
| `detect-private-key` | Claves privadas PEM/RSA hardcodeadas en el código |
| `gitleaks` | API Keys, tokens JWT, contraseñas, secretos de Azure/AWS |
| `black` | Formatea el código Python automáticamente |
| `isort` | Ordena los imports según el estándar PEP8 |
| `pytest tests/unit/` | Ejecuta los tests unitarios — bloquea el commit si fallan |

## Instalación (una sola vez por desarrollador)

```bash
# 1. Instalar pre-commit (ya incluido en requirements.txt)
pip install pre-commit

# 2. Registrar los hooks en tu repositorio local
pre-commit install

# Opcional: ejecutar sobre todos los ficheros ahora mismo
pre-commit run --all-files
```

A partir de ese momento, cada `git commit` ejecutará los hooks automáticamente.

## Saltar un hook puntualmente (NO recomendado)

```bash
# Saltar todos los hooks (solo en casos excepcionales)
git commit --no-verify -m "mensaje"

# Ver qué falló en detalle
pre-commit run --verbose
```

## Diferencia con GitHub Actions

| | Pre-commit (local) | GitHub Actions (remoto) |
|---|---|---|
| **Cuándo** | Antes del `git commit` | Después del `git push` |
| **Quién lo ve** | Solo tú | Todo el equipo |
| **Tests** | Solo unitarios (rápidos) | Unitarios + integración |
| **Secret scan** | ✅ Sí (Gitleaks) | ✅ Sí (en `ci.yml`) |

La combinación de ambos garantiza que ningún secreto ni código roto llegue jamás al repositorio.
