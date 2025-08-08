#!/bin/bash

echo "[*] Verificando e instalando herramientas necesarias para automatic.sh..."
sleep 1

# Verificar privilegios
if [ "$EUID" -ne 0 ]; then
  echo "[!] Ejecutá como root o con sudo."
  exit 1
fi

# Actualizar sistema y dependencias básicas
apt update && apt install -y curl git build-essential whois dnsutils python3-pip python3-setuptools cargo

# Verificar Go
if ! command -v go &>/dev/null; then
  echo "[!] Go no está instalado. Instalalo desde https://go.dev/doc/install y luego ejecutá este script de nuevo."
  exit 1
fi

# Verificar herramienta e instalar si falta
install_if_missing() {
  local cmd=$1
  local install_cmd=$2

  if ! command -v $cmd &>/dev/null; then
    echo "[+] Instalando $cmd..."
    eval "$install_cmd"
  else
    echo "[✔] $cmd ya está instalado."
  fi
}

# Go tools
install_if_missing subfinder 'go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest'
install_if_missing httpx 'go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest'
install_if_missing dnsx 'go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest'
install_if_missing ffuf 'go install -v github.com/ffuf/ffuf@latest'
install_if_missing assetfinder 'go install -v github.com/tomnomnom/assetfinder@latest'
install_if_missing gau 'go install -v github.com/lc/gau/v2/cmd/gau@latest'
install_if_missing nuclei 'go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest'
install_if_missing qsreplace 'go install github.com/tomnomnom/qsreplace@latest'

# Snap (amass)
if ! command -v amass &>/dev/null; then
  echo "[+] Instalando amass..."
  snap install amass
else
  echo "[✔] amass ya está instalado."
fi

# Cargo tool
install_if_missing rush 'cargo install rush-cli'

# Python tools
pip3 install uro freq --quiet

# Agregar bin de Go al PATH si no está
if [[ ":$PATH:" != *":$(go env GOPATH)/bin:"* ]]; then
  echo 'export PATH="$PATH:$(go env GOPATH)/bin"' >> ~/.bashrc
  echo "[*] PATH actualizado. Ejecutá: source ~/.bashrc"
fi

# Crear alias para auto_mod.sh
SCRIPT_PATH="$(pwd)/auto_mod.sh"

if [ -f "$SCRIPT_PATH" ]; then
  echo "[*] Agregando alias 'auto-scan' para ejecutar auto_mod.sh desde cualquier parte..."
  echo "alias auto-scan='bash $SCRIPT_PATH'" >> ~/.bashrc
  echo "[✔] Alias agregado. Ejecutá: source ~/.bashrc"
else
  echo "[!] No se encontró auto_mod.sh en $(pwd). Asegurate de colocarlo en esta carpeta antes de crear el alias."
fi

echo "[✔] Todas las herramientas están listas para usar."
