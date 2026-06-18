#!/bin/bash
# ============================================================
# setup_docker_local.sh
# Sets up a Docker environment on macOS where all heavy data
# (VM images, containers, volumes) is kept inside this folder.
# ============================================================

set -e

# Get absolute path of the project root
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "============================================"
echo " SecureX — Local Docker Setup"
echo "============================================"
echo "Note: Docker on Mac requires a lightweight VM."
echo "We will use 'colima' and configure it to store its heavy"
echo "VM disk and containers strictly inside this genai folder."
echo "============================================"

# 1. Install lightweight Docker CLI and Colima via Homebrew
echo ""
echo "[1/3] Installing colima and docker CLI..."
if ! command -v colima &> /dev/null || ! command -v docker &> /dev/null; then
    brew install colima docker docker-compose
else
    echo "✅ Colima and Docker CLI are already installed via brew."
fi

# 2. Set environment variables to isolate data
export LIMA_HOME="$PROJECT_ROOT/.lima"
export DOCKER_CONFIG="$PROJECT_ROOT/.docker"

mkdir -p "$LIMA_HOME"
mkdir -p "$DOCKER_CONFIG"

# 3. Start Colima (this provisions the VM inside genai/.lima)
echo ""
echo "[2/3] Starting Docker VM inside $LIMA_HOME..."
echo "This will download the Alpine Linux VM image (once) and start it."

# We use the default architecture (which will be aarch64 on M2)
colima start --cpu 2 --memory 4 --disk 20 || echo "Colima is already running or encountered an issue. Continuing..."

echo ""
echo "[3/3] Pulling MobSF Docker Image..."
docker pull opensecurity/mobile-security-framework-mobsf:latest

echo ""
echo "============================================"
echo " ✅ Docker Setup Complete!"
echo "============================================"
echo ""
echo "Your Docker VM and all containers are now stored in: $LIMA_HOME"
echo ""
echo "CRITICAL: Whenever you open a new terminal to run Docker commands"
echo "for this project (like docker compose up -d), you MUST first run:"
echo "  export LIMA_HOME=\"$(pwd)/.lima\""
echo "  export DOCKER_CONFIG=\"$(pwd)/.docker\""
echo ""
echo "To start MobSF now, run:"
echo "  export LIMA_HOME=\"$(pwd)/.lima\""
echo "  export DOCKER_CONFIG=\"$(pwd)/.docker\""
echo "  docker compose up -d"
echo "============================================"
