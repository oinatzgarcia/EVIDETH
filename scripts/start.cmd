@echo off
setlocal EnableDelayedExpansion

echo.
echo  ========================================
echo    EVIDETH - Forensic Video System v2.0
echo  ========================================
echo.

:: Ir al root del repo (scripts/ esta un nivel abajo)
cd /d "%~dp0.."

:: Comprobar Python
where python >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python no encontrado.
    echo         Instala Python 3.x desde https://python.org y asegurate
    echo         de marcar "Add to PATH" durante la instalacion.
    pause
    exit /b 1
)

echo [1/4] Verificando entorno virtual...
if not exist .venv\Scripts\python.exe (
    echo       Creando .venv ...
    python -m venv .venv
    if errorlevel 1 (
        echo [ERROR] No se pudo crear el entorno virtual.
        pause
        exit /b 1
    )
    echo       .venv creado correctamente.
) else (
    echo       .venv ya existe, omitiendo creacion.
)

echo.
echo [2/4] Actualizando pip...
.venv\Scripts\python.exe -m pip install --upgrade pip setuptools wheel --quiet

echo.
echo [3/4] Instalando dependencias...
if exist requirements.txt (
    .venv\Scripts\python.exe -m pip install -r requirements.txt --quiet
    echo       Dependencias OK.
) else (
    echo [WARN] No se encontro requirements.txt en el root del proyecto.
)

:: Crear .env desde .env.example si no existe
if exist .env.example (
    if not exist .env (
        copy .env.example .env >nul
        echo.
        echo [WARN] Se ha creado .env desde .env.example.
        echo        Edita el fichero .env con tus credenciales antes de continuar.
        echo        Presiona cualquier tecla cuando estes listo...
        pause >nul
    )
)

echo.
echo [4/4] Arrancando servidor...
echo.
echo  API  ^& Frontend: http://127.0.0.1:8000
echo  Docs (Swagger):   http://127.0.0.1:8000/docs
echo  Login:            http://127.0.0.1:8000/frontend/pages/login/login.html
echo.
echo  NOTA: FastAPI sirve el frontend estatico en /frontend
echo        NO es necesario ningun servidor adicional (http.server, etc.)
echo.
echo  Para parar el servidor: Ctrl+C en esta ventana
echo.

:: Abrir navegador tras 2 segundos (deja tiempo a uvicorn de arrancar)
start "" cmd /c "timeout /t 2 /nobreak >nul && start http://127.0.0.1:8000/"

:: Arrancar FastAPI con Uvicorn (bloquea esta ventana)
.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000

pause
