import os
import subprocess

# Estructura de carpetas
folders = [
    "app/api/v1",
    "app/core",
    "app/db/migrations",
    "app/schemas",
    "app/utils",
    "frontend/assets/css",
    "frontend/assets/js",
    "frontend/assets/images",
    "frontend/components",
    "camera-simulator",
    "tests/unit",
    "tests/integration",
    "docs/planning/wireframes",
    "docs/architecture/sequence-diagrams",
    "docs/images",
    "docs/research",
    "scripts",
    "deployments/kubernetes",
    ".github/workflows"
]

# Crear carpetas
for folder in folders:
    os.makedirs(folder, exist_ok=True)
    print(f"✅ Creada: {folder}")

# Crear __init__.py
for root, dirs, files in os.walk("app"):
    open(os.path.join(root, "__init__.py"), 'a').close()
for root, dirs, files in os.walk("tests"):
    open(os.path.join(root, "__init__.py"), 'a').close()

# Crear .gitignore
with open(".gitignore", "w") as f:
    f.write("__pycache__/\n*.py[cod]\nvenv/\n.env\n*.mp4\n*.avi\n")

# Git operations
subprocess.run(["git", "add", "."])
subprocess.run(["git", "commit", "-m", "feat: create complete project structure"])
subprocess.run(["git", "push", "origin", "main"])

print("\n🚀 Estructura creada y subida a GitHub!")
