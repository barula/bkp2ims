#!/bin/bash
set -euo pipefail

# ─────────────────────────────────────────────────────────────────────────────
# bkp2ims — instalador automático para Ubuntu Server 24.04 en Huawei Cloud
# Uso:
#   bash install.sh
#   bash install.sh --region sa-argentina-1 --project-id <id> --domain ejemplo.com
# ─────────────────────────────────────────────────────────────────────────────

REPO_URL="https://github.com/barula/bkp2ims.git"
INSTALL_DIR="/opt/bkp2ims"
METADATA_URL="http://169.254.169.254/openstack/latest/meta_data.json"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC} $*"; }
ok()      { echo -e "${GREEN}[OK]${NC}   $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
die()     { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

# ── Argumentos ────────────────────────────────────────────────────────────────
REGION=""
PROJECT_ID=""
DOMAIN=""        # opcional: dominio para HTTPS con Caddy

while [[ $# -gt 0 ]]; do
  case $1 in
    --region)     REGION="$2";     shift 2 ;;
    --project-id) PROJECT_ID="$2"; shift 2 ;;
    --domain)     DOMAIN="$2";     shift 2 ;;
    *) die "Argumento desconocido: $1" ;;
  esac
done

# ── Verificaciones iniciales ──────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || die "Ejecutar como root: sudo bash install.sh"

OS_ID=$(. /etc/os-release && echo "$ID")
OS_VER=$(. /etc/os-release && echo "$VERSION_ID")
[[ "$OS_ID" == "ubuntu" ]] || die "Este script requiere Ubuntu (detectado: $OS_ID)"
[[ "$OS_VER" == "24.04" ]] || warn "Optimizado para Ubuntu 24.04 (detectado: $OS_VER). Continuando de todas formas..."

echo ""
echo "══════════════════════════════════════════════════════"
echo "   bkp2ims — Instalador automático"
echo "══════════════════════════════════════════════════════"
echo ""

# ── Detectar región y project_id desde metadata HWC ──────────────────────────
info "Leyendo metadata de Huawei Cloud..."
META=$(curl -sf --connect-timeout 3 "$METADATA_URL" 2>/dev/null || true)

if [[ -n "$META" ]]; then
  [[ -z "$PROJECT_ID" ]] && PROJECT_ID=$(echo "$META" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("project_id",""))' 2>/dev/null || true)
  [[ -z "$REGION" ]]     && REGION=$(echo "$META"     | python3 -c 'import sys,json; m=json.load(sys.stdin); r=m.get("region_id","") or m.get("availability_zone","").rsplit("-",1)[0]; print(r)' 2>/dev/null || true)
  ok "Metadata leída correctamente"
else
  warn "No se pudo leer metadata (¿no es una ECS de HWC o sin agencia?)"
fi

# ── Solicitar datos faltantes ─────────────────────────────────────────────────
if [[ -z "$REGION" ]]; then
  read -rp "Región HWC [sa-argentina-1]: " REGION
  REGION="${REGION:-sa-argentina-1}"
fi

if [[ -z "$PROJECT_ID" ]]; then
  echo ""
  echo "  Project ID: Consola HWC → esquina superior derecha"
  echo "              → Mi credencial → columna 'ID de proyecto'"
  echo ""
  read -rp "Project ID HWC: " PROJECT_ID
  [[ -n "$PROJECT_ID" ]] || die "Project ID requerido"
fi

echo ""
info "Configuración:"
echo "  Región:     $REGION"
echo "  Project ID: $PROJECT_ID"
[[ -n "$DOMAIN" ]] && echo "  Dominio:    $DOMAIN"
echo ""

# ── 1. Dependencias del sistema ───────────────────────────────────────────────
info "Actualizando paquetes del sistema..."
apt-get update -qq
apt-get install -y -qq curl git python3 ca-certificates gnupg lsb-release

# ── 2. Docker ─────────────────────────────────────────────────────────────────
if command -v docker &>/dev/null; then
  ok "Docker ya instalado ($(docker --version | cut -d' ' -f3 | tr -d ','))"
else
  info "Instalando Docker..."
  curl -fsSL https://get.docker.com | sh -s -- --quiet
  systemctl enable --now docker
  ok "Docker instalado"
fi

docker compose version &>/dev/null || die "Docker Compose plugin no disponible"

# ── 3. Clonar repositorio ─────────────────────────────────────────────────────
if [[ -d "$INSTALL_DIR/.git" ]]; then
  info "Repositorio ya existe, actualizando..."
  git -C "$INSTALL_DIR" pull --ff-only
  ok "Repositorio actualizado"
elif [[ -d "$INSTALL_DIR" ]]; then
  warn "Directorio $INSTALL_DIR existe pero no es un repo git — limpiando..."
  rm -rf "$INSTALL_DIR"
  git clone "$REPO_URL" "$INSTALL_DIR"
  ok "Repositorio clonado"
else
  info "Clonando repositorio..."
  git clone "$REPO_URL" "$INSTALL_DIR"
  ok "Repositorio clonado en $INSTALL_DIR"
fi

# ── 4. Configurar docker-compose.yml ─────────────────────────────────────────
info "Configurando variables de entorno..."
COMPOSE_FILE="$INSTALL_DIR/docker-compose.yml"

# Reemplazar región y project_id
sed -i "s|HWC_REGION=.*|HWC_REGION=$REGION|"         "$COMPOSE_FILE"
sed -i "s|HWC_PROJECT_ID=.*|HWC_PROJECT_ID=$PROJECT_ID|" "$COMPOSE_FILE"

ok "docker-compose.yml configurado"

# ── 5. Configurar Caddyfile ───────────────────────────────────────────────────
CADDY_FILE="$INSTALL_DIR/Caddyfile"

if [[ -n "$DOMAIN" ]]; then
  info "Configurando Caddy con dominio $DOMAIN (HTTPS automático)..."
  cat > "$CADDY_FILE" <<EOF
$DOMAIN {
    reverse_proxy app:8000 {
        header_up X-Real-IP {remote_host}
        header_up X-Forwarded-For {remote_host}
        header_up X-Forwarded-Proto {scheme}
    }
    encode gzip
    header {
        X-Content-Type-Options nosniff
        X-Frame-Options DENY
        -Server
    }
    log {
        output stdout
        format console
    }
}
EOF
  ok "Caddyfile configurado para HTTPS en $DOMAIN"
else
  info "Usando configuración HTTP por IP (puerto 80)"
fi

# ── 6. Build y despliegue ─────────────────────────────────────────────────────
info "Construyendo imagen Docker..."
cd "$INSTALL_DIR"
docker compose build --quiet
ok "Imagen construida"

info "Iniciando servicios..."
docker compose up -d
ok "Servicios iniciados"

# ── 7. Verificación ───────────────────────────────────────────────────────────
info "Esperando que la app levante..."
ATTEMPTS=0
MAX=24
until curl -sf http://localhost:80/api/status &>/dev/null; do
  ATTEMPTS=$((ATTEMPTS + 1))
  [[ $ATTEMPTS -ge $MAX ]] && die "La app no respondió luego de $((MAX * 5)) segundos. Ver: docker compose -f $INSTALL_DIR/docker-compose.yml logs app"
  sleep 5
done

STATUS=$(curl -sf http://localhost:80/api/status)
API_OK=$(echo "$STATUS" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("ok",""))' 2>/dev/null || echo "")

echo ""
echo "══════════════════════════════════════════════════════"
if [[ "$API_OK" == "True" ]] || [[ "$API_OK" == "true" ]]; then
  echo -e "${GREEN}   ✓ bkp2ims instalado y funcionando correctamente${NC}"
else
  echo -e "${YELLOW}   ⚠ App respondiendo pero sin credenciales HWC válidas${NC}"
  echo "     Verificar que la ECS tenga una agencia IAM con permisos:"
  echo "     ECS FullAccess + IMS FullAccess + EVS FullAccess"
fi
echo ""
echo "   Instalado en: $INSTALL_DIR"
echo "   Región:       $REGION"
echo "   Project ID:   $PROJECT_ID"
[[ -n "$DOMAIN" ]] && echo "   URL:          https://$DOMAIN" || echo "   URL:          http://$(curl -sf http://169.254.169.254/openstack/latest/meta_data.json 2>/dev/null | python3 -c 'import sys,json; addrs=json.load(sys.stdin).get("network_interfaces",{}).get("public_ipv4",""); print(addrs)' 2>/dev/null || echo '<EIP-del-servidor>')"
echo ""
echo "   Comandos útiles:"
echo "     Ver logs:    docker compose -C $INSTALL_DIR logs -f app"
echo "     Reiniciar:   docker compose -C $INSTALL_DIR restart app"
echo "     Actualizar:  git -C $INSTALL_DIR pull && docker compose -C $INSTALL_DIR up --build -d app"
echo "══════════════════════════════════════════════════════"
echo ""
