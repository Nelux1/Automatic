#!/bin/bash
# Instala AutomaticRec y las herramientas que AutomaticRec.sh ejecuta de verdad.
# Todo queda bajo /opt/AutomaticRec. Al final comprueba que cada binario responda.
#
# Uso, desde el clon del repo:
#   sudo bash Install_requirements.sh
#
# Pensado para Debian, Ubuntu y Kali (apt).

set -euo pipefail

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "[!] Ejecutalo como root: sudo bash Install_requirements.sh" >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
export PATH="/usr/local/go/bin:/usr/local/bin:/opt/AutomaticRec/bin:${PATH}"

INSTALLER_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
INSTALL_ROOT="/opt/AutomaticRec"
BIN_DIR="$INSTALL_ROOT/bin"
VENV="$INSTALL_ROOT/venv"
BIN_LINK="/usr/bin/AutomaticRec"
GO_MIN="1.24"

for required in AutomaticRec.sh recon_inverso.py dic.txt requirements.txt; do
  if [[ ! -f "$INSTALLER_DIR/$required" ]]; then
    echo "[!] Falta $required en $INSTALLER_DIR" >&2
    echo "[!] Ejecutá este script desde el clon del repo." >&2
    exit 1
  fi
done

echo "[*] Paquetes del sistema..."
apt-get update
apt-get install -y \
  ca-certificates curl git build-essential \
  whois python3 python3-pip python3-venv \
  python3-dnspython python3-requests \
  file coreutils

if ! apt-get install -y dnsutils; then
  apt-get install -y bind9-dnsutils
fi

if ! command -v chromium >/dev/null 2>&1 \
  && ! command -v chromium-browser >/dev/null 2>&1 \
  && ! command -v google-chrome >/dev/null 2>&1 \
  && ! command -v google-chrome-stable >/dev/null 2>&1; then
  echo "[*] Navegador para los screenshots de httpx (-system-chrome)..."
  apt-get install -y chromium || apt-get install -y chromium-browser || \
    echo "[!] No se pudo instalar chromium. Los screenshots de httpx van a fallar; el resto del scan sigue."
fi

go_version_ge() {
  local have="$1" want="$2"
  [[ "$(printf '%s\n%s\n' "$want" "$have" | sort -V | head -n 1)" == "$want" ]]
}

current_go_version() {
  go env GOVERSION 2>/dev/null | sed 's/^go//'
}

install_official_go() {
  local arch ver tarball
  case "$(uname -m)" in
    x86_64) arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    *)
      echo "[!] Arquitectura no soportada para instalar Go: $(uname -m)" >&2
      return 1
      ;;
  esac
  ver="$(curl -fsSL 'https://go.dev/dl/?mode=json' | python3 -c 'import json,sys; rels=json.load(sys.stdin); print(next(r["version"] for r in rels if r.get("stable")))')"
  echo "[+] Instalando ${ver} en /usr/local/go ..."
  tarball="/tmp/${ver}.linux-${arch}.tar.gz"
  curl -fsSL "https://go.dev/dl/${ver}.linux-${arch}.tar.gz" -o "$tarball"
  rm -rf /usr/local/go
  tar -C /usr/local -xzf "$tarball"
  rm -f "$tarball"
  ln -sfn /usr/local/go/bin/go /usr/local/bin/go
  ln -sfn /usr/local/go/bin/gofmt /usr/local/bin/gofmt
  export PATH="/usr/local/go/bin:${PATH}"
  hash -r
}

if ! command -v go >/dev/null 2>&1; then
  install_official_go
elif ! go_version_ge "$(current_go_version)" "$GO_MIN"; then
  echo "[!] Go $(current_go_version) es anterior a ${GO_MIN}. Instalo el estable oficial."
  install_official_go
else
  echo "[✔] Go $(current_go_version)"
fi

mkdir -p "$BIN_DIR" "$INSTALL_ROOT/.gopath" "$INSTALL_ROOT/.gocache"
export GOBIN="$BIN_DIR"
export GOPATH="$INSTALL_ROOT/.gopath"
export GOCACHE="$INSTALL_ROOT/.gocache"

install_go_tool() {
  local name="$1"
  local module="$2"
  if [[ -x "$BIN_DIR/$name" ]]; then
    echo "[✔] $name ya está en $BIN_DIR"
    return 0
  fi
  echo "[+] Instalando $name ..."
  go install "$module"
  if [[ ! -x "$BIN_DIR/$name" ]]; then
    echo "[!] $name no quedó en $BIN_DIR (módulo: $module)" >&2
    return 1
  fi
}

# Binarios que AutomaticRec.sh invoca (enum, brute, URLs, nuclei, XSS, CORS, secrets).
install_go_tool assetfinder 'github.com/tomnomnom/assetfinder@latest'
install_go_tool subfinder 'github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest'
install_go_tool chaos 'github.com/projectdiscovery/chaos-client/cmd/chaos@latest'
install_go_tool httpx 'github.com/projectdiscovery/httpx/cmd/httpx@latest'
install_go_tool dnsx 'github.com/projectdiscovery/dnsx/cmd/dnsx@latest'
install_go_tool ffuf 'github.com/ffuf/ffuf@latest'
install_go_tool nuclei 'github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest'
install_go_tool qsreplace 'github.com/tomnomnom/qsreplace@latest'
install_go_tool freq 'github.com/takshal/freq@latest'
install_go_tool rush 'github.com/shenwei356/rush@latest'
install_go_tool urlfinder 'github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest'
install_go_tool amass 'github.com/owasp-amass/amass/v4/cmd/amass@latest'
install_go_tool trufflehog 'github.com/trufflesecurity/trufflehog/v3@latest'

echo "[*] Entorno Python de waymore y uro en $VENV ..."
if [[ ! -x "$VENV/bin/python3" ]]; then
  python3 -m venv "$VENV"
fi
"$VENV/bin/pip" install --upgrade pip
"$VENV/bin/pip" install waymore uro
ln -sfn "$VENV/bin/waymore" "$BIN_DIR/waymore"
ln -sfn "$VENV/bin/uro" "$BIN_DIR/uro"

if ! python3 -c 'import dns.resolver, dns.reversename, requests' >/dev/null 2>&1; then
  echo "[*] Los paquetes apt de Python no alcanzan. Instalo requirements.txt en el Python del sistema..."
  python3 -m pip install --break-system-packages -r "$INSTALLER_DIR/requirements.txt"
fi

echo "[*] Copiando AutomaticRec a $INSTALL_ROOT ..."
install -m 755 "$INSTALLER_DIR/AutomaticRec.sh" "$INSTALL_ROOT/AutomaticRec.sh"
install -m 644 "$INSTALLER_DIR/recon_inverso.py" "$INSTALL_ROOT/recon_inverso.py"
install -m 644 "$INSTALLER_DIR/requirements.txt" "$INSTALL_ROOT/requirements.txt"
install -m 644 "$INSTALLER_DIR/dic.txt" "$INSTALL_ROOT/dic.txt"
if [[ ! -f "$INSTALL_ROOT/AutomaticRec.conf" && -f "$INSTALLER_DIR/AutomaticRec.conf" ]]; then
  install -m 644 "$INSTALLER_DIR/AutomaticRec.conf" "$INSTALL_ROOT/AutomaticRec.conf"
fi
ln -sfn "$INSTALL_ROOT/AutomaticRec.sh" "$BIN_LINK"

# /usr/local/bin ya está en el PATH por defecto. El perfil antepone el directorio nuevo
# para que el httpx de ProjectDiscovery gane sobre un httpx de Python.
for name in assetfinder subfinder chaos httpx dnsx ffuf nuclei qsreplace freq rush urlfinder amass trufflehog waymore uro; do
  ln -sfn "$BIN_DIR/$name" "/usr/local/bin/$name"
done
chmod -R a+rX "$BIN_DIR" "$VENV" "$INSTALL_ROOT/AutomaticRec.sh" "$INSTALL_ROOT/recon_inverso.py" "$INSTALL_ROOT/dic.txt"

cat > /etc/profile.d/automaticrec.sh <<'EOF'
# Binarios instalados por Install_requirements.sh de AutomaticRec.
case ":${PATH}:" in
  *:/opt/AutomaticRec/bin:*) ;;
  *) PATH="/opt/AutomaticRec/bin:${PATH}" ;;
esac
export PATH
EOF
chmod 644 /etc/profile.d/automaticrec.sh

echo "[*] Plantillas de nuclei (el primer scan las necesita)..."
if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]]; then
  sudo -u "$SUDO_USER" -H "$BIN_DIR/nuclei" -update-templates || \
    echo "[!] No se pudieron bajar las plantillas de nuclei. Corré luego: nuclei -update-templates"
else
  "$BIN_DIR/nuclei" -update-templates || \
    echo "[!] No se pudieron bajar las plantillas de nuclei. Corré luego: nuclei -update-templates"
fi

hash -r
export PATH="/opt/AutomaticRec/bin:/usr/local/bin:${PATH}"

echo ""
echo "[*] Comprobando herramientas que usa AutomaticRec.sh ..."
missing=0
check_cmd() {
  local name="$1"
  local path
  path="$(command -v "$name" 2>/dev/null || true)"
  if [[ -n "$path" ]]; then
    echo "[✔] $name -> $path"
  else
    echo "[!] Falta $name" >&2
    missing=1
  fi
}

for cmd in python3 curl whois dig assetfinder subfinder chaos httpx dnsx ffuf nuclei qsreplace freq rush urlfinder amass trufflehog waymore uro; do
  check_cmd "$cmd"
done

httpx_path="$(command -v httpx 2>/dev/null || true)"
if [[ -n "$httpx_path" ]] && file "$httpx_path" | grep -qiE 'ELF|Mach-O'; then
  echo "[✔] httpx es el binario de ProjectDiscovery"
else
  echo "[!] httpx no es el binario nativo de ProjectDiscovery ($httpx_path)" >&2
  missing=1
fi

if waymore -h >/dev/null 2>&1; then
  echo "[✔] waymore arranca"
else
  echo "[!] waymore está instalado pero no arranca (waymore -h falló)" >&2
  missing=1
fi

if python3 -c 'import dns.resolver, dns.reversename, requests' >/dev/null 2>&1; then
  echo "[✔] python3 importa dnspython y requests"
else
  echo "[!] python3 no importa dnspython/requests; recon_inverso.py no va a correr" >&2
  missing=1
fi

for path in \
  "$INSTALL_ROOT/AutomaticRec.sh" \
  "$INSTALL_ROOT/recon_inverso.py" \
  "$INSTALL_ROOT/dic.txt" \
  "$BIN_LINK"
do
  if [[ -e "$path" ]]; then
    echo "[✔] $path"
  else
    echo "[!] Falta $path" >&2
    missing=1
  fi
done

if command -v chromium >/dev/null 2>&1 || command -v chromium-browser >/dev/null 2>&1 \
  || command -v google-chrome >/dev/null 2>&1 || command -v google-chrome-stable >/dev/null 2>&1; then
  echo "[✔] navegador para screenshots de httpx"
else
  echo "[!] Sin Chrome/Chromium: httpx -system-chrome no va a sacar screenshots"
fi

echo ""
if [[ "$missing" -ne 0 ]]; then
  echo "[!] La instalación quedó incompleta. Revisá los [!] de arriba." >&2
  exit 1
fi

echo "[✔] Listo. Abrí una terminal nueva y ejecutá:"
echo "       AutomaticRec -u ejemplo.com -a"
echo "    Archivos: $INSTALL_ROOT"
echo "    Binarios: $BIN_DIR  (también en /usr/local/bin)"
echo "    La key de Chaos, si la usás, va en ~/.config/automaticrec.conf"
echo "    Para actualizar el script sin reinstalar las herramientas:"
echo "       sudo bash $INSTALLER_DIR/Install_requirements.sh"
