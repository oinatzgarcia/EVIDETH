param(
    [int]$Port = 8000
)

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host " ========================================" -ForegroundColor Cyan
Write-Host "   EVIDETH - Forensic Video System v2.0" -ForegroundColor Cyan
Write-Host " ========================================" -ForegroundColor Cyan
Write-Host ""

# Ir al root del repo (scripts/ esta un nivel abajo)
$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $RepoRoot

# ── 1. Comprobar Python ──────────────────────────────────────────
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "[ERROR] Python no encontrado." -ForegroundColor Red
    Write-Host "        Instala Python 3.x desde https://python.org" -ForegroundColor Red
    exit 1
}

# ── 2. Entorno virtual ───────────────────────────────────────────
Write-Host "[1/4] Verificando entorno virtual..." -ForegroundColor Yellow
if (-not (Test-Path ".venv\Scripts\python.exe")) {
    Write-Host "      Creando .venv ..." -ForegroundColor Gray
    python -m venv .venv
    Write-Host "      .venv creado correctamente." -ForegroundColor Green
} else {
    Write-Host "      .venv ya existe, omitiendo creacion." -ForegroundColor Green
}

$Py = ".venv\Scripts\python.exe"

# ── 3. Dependencias ──────────────────────────────────────────────
Write-Host ""
Write-Host "[2/4] Actualizando pip..." -ForegroundColor Yellow
& $Py -m pip install --upgrade pip setuptools wheel --quiet

Write-Host ""
Write-Host "[3/4] Instalando dependencias..." -ForegroundColor Yellow
if (Test-Path "requirements.txt") {
    & $Py -m pip install -r requirements.txt --quiet
    Write-Host "      Dependencias OK." -ForegroundColor Green
} else {
    Write-Host "[WARN] No se encontro requirements.txt" -ForegroundColor DarkYellow
}

# ── Crear .env si no existe ───────────────────────────────────────
if ((Test-Path ".env.example") -and (-not (Test-Path ".env"))) {
    Copy-Item ".env.example" ".env"
    Write-Host ""
    Write-Host "[WARN] Se ha creado .env desde .env.example." -ForegroundColor DarkYellow
    Write-Host "       Edita el fichero .env con tus credenciales y pulsa ENTER para continuar."
    Read-Host
}

# ── 4. Arrancar servidor ──────────────────────────────────────────
Write-Host ""
Write-Host "[4/4] Arrancando servidor..." -ForegroundColor Yellow
Write-Host ""
Write-Host "  API & Frontend : http://127.0.0.1:$Port" -ForegroundColor Cyan
Write-Host "  Docs (Swagger) : http://127.0.0.1:$Port/docs" -ForegroundColor Cyan
Write-Host "  Login          : http://127.0.0.1:$Port/" -ForegroundColor Cyan
Write-Host ""
Write-Host "  NOTA: FastAPI sirve el frontend en /frontend" -ForegroundColor DarkGray
Write-Host "        NO necesitas http.server ni ningun otro servidor adicional." -ForegroundColor DarkGray
Write-Host ""
Write-Host "  Para parar: Ctrl+C" -ForegroundColor DarkGray
Write-Host ""

# Abrir navegador tras 2s
Start-Job -ScriptBlock {
    param($p)
    Start-Sleep -Seconds 2
    Start-Process "http://127.0.0.1:$p/"
} -ArgumentList $Port | Out-Null

# Bloquear en Uvicorn
& $Py -m uvicorn app.main:app --reload --host 127.0.0.1 --port $Port
