#!/bin/bash

echo "[*] Checking and installing tools required for automatic.sh..."
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

# Create alias for auto_mod.sh
SCRIPT_PATH="$(pwd)/auto_mod.sh"

if [ -f "$SCRIPT_PATH" ]; then
  echo "[*] Adding alias 'auto-scan' to run auto_mod.sh from anywhere..."
  echo "alias auto-scan='bash $SCRIPT_PATH'" >> ~/.bashrc
  echo "[✔] Alias added. Run: source ~/.bashrc"
else
  echo "[!] auto_mod.sh not found in $(pwd). Place it in this folder before creating the alias."
fi

echo "[✔] All tools are ready to use."
