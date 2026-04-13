#!/bin/bash

echo "[*] Checking and installing tools required for AutomaticRec..."
sleep 1

# Check privileges
if [ "$EUID" -ne 0 ]; then
  echo "[!] Run as root or with sudo."
  exit 1
fi

# Update system and basic dependencies
apt update && apt install -y curl git build-essential whois dnsutils python3-pip python3-setuptools cargo

# Check Go
if ! command -v go &>/dev/null; then
  echo "[!] Go is not installed. Install it from https://go.dev/doc/install and run this script again."
  exit 1
fi

# Check tool and install if missing
install_if_missing() {
  local cmd=$1
  local install_cmd=$2

  if ! command -v $cmd &>/dev/null; then
    echo "[+] Installing $cmd..."
    eval "$install_cmd"
  else
    echo "[✔] $cmd is already installed."
  fi
}

# Go tools
install_if_missing subfinder 'go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest'
install_if_missing chaos 'go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest'
install_if_missing httpx 'go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest'
install_if_missing dnsx 'go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest'
install_if_missing ffuf 'go install -v github.com/ffuf/ffuf@latest'
install_if_missing assetfinder 'go install -v github.com/tomnomnom/assetfinder@latest'
install_if_missing nuclei 'go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest'
install_if_missing qsreplace 'go install github.com/tomnomnom/qsreplace@latest'

# Snap (amass)
if ! command -v amass &>/dev/null; then
  echo "[+] Installing amass..."
  snap install amass
else
  echo "[✔] amass is already installed."
fi

# Cargo tool
install_if_missing rush 'cargo install rush-cli'

# Python tools (waymore for URLs from Wayback, Common Crawl, etc.)
pip3 install uro freq waymore --quiet
if ! command -v waymore &>/dev/null; then
  echo "[+] Installing waymore..."
  pip3 install waymore
fi

# Add Go bin to PATH if not already
if [[ ":$PATH:" != *":$(go env GOPATH)/bin:"* ]]; then
  echo 'export PATH="$PATH:$(go env GOPATH)/bin"' >> ~/.bashrc
  echo "[*] PATH updated. Run: source ~/.bashrc"
fi

# AutomaticRec en PATH: /usr/bin/AutomaticRec (sin ./ ni .sh)
INSTALLER_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
INSTALL_ROOT="/opt/AutomaticRec"
BIN_LINK="/usr/bin/AutomaticRec"

if [[ ! -f "$INSTALLER_DIR/AutomaticRec.sh" || ! -f "$INSTALLER_DIR/recon_inverso.py" ]]; then
  echo "[!] No se encontró AutomaticRec.sh o recon_inverso.py en $INSTALLER_DIR"
  echo "[!] Ejecutá este script desde el clon del repo (donde están esos archivos)."
  exit 1
fi

echo "[*] Instalando AutomaticRec en $INSTALL_ROOT y enlace $BIN_LINK ..."
mkdir -p "$INSTALL_ROOT" /opt/Automatic
install -m 755 "$INSTALLER_DIR/AutomaticRec.sh" "$INSTALL_ROOT/AutomaticRec.sh"
install -m 644 "$INSTALLER_DIR/recon_inverso.py" "$INSTALL_ROOT/recon_inverso.py"
if [[ -f "$INSTALLER_DIR/AutomaticRec.conf" ]]; then
  install -m 644 "$INSTALLER_DIR/AutomaticRec.conf" "$INSTALL_ROOT/AutomaticRec.conf"
fi
install -m 644 "$INSTALLER_DIR/dic.txt" /opt/Automatic/dic.txt

ln -sfn "$INSTALL_ROOT/AutomaticRec.sh" "$BIN_LINK"
chmod a+x "$BIN_LINK" 2>/dev/null || true

echo "[✔] Listo: podés ejecutar desde cualquier directorio:"
echo "       AutomaticRec -u ejemplo.com -a"
echo "    (ruta instalada: $INSTALL_ROOT → $BIN_LINK)"

echo "[✔] All tools are ready to use."
