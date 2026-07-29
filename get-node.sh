#!/bin/sh
# Installe un nœud Noctavault headless (nv-node seul, pas de GUI) sur un
# serveur dédié, et le fait tourner en service systemd persistant.
#
# Usage :
#   curl -fsSL https://raw.githubusercontent.com/USER/noctavault/main/get-node.sh | sh
#
# ou, depuis un clone existant :
#   ./get-node.sh
#
# Variables d'environnement optionnelles :
#   NOCTAVAULT_HOME=/chemin        (défaut : ~/.noctavault)
#   NOCTAVAULT_LISTEN=host:port    (défaut : 0.0.0.0:7777)
#   NOCTAVAULT_PEERS=host:port,... (pairs de bootstrap initiaux)
#
# Si `sudo` te redemande ton mot de passe et que ça bloque (stdin déjà
# utilisé par le pipe curl | sh), télécharge d'abord le script puis
# exécute-le normalement :
#   curl -fsSL .../get-node.sh -o get-node.sh && sh get-node.sh
set -e

REPO_URL="${NOCTAVAULT_REPO_URL:-https://github.com/USER/noctavault.git}"
INSTALL_DIR="${NOCTAVAULT_INSTALL_DIR:-$HOME/.local/bin}"
NOCTAVAULT_HOME="${NOCTAVAULT_HOME:-$HOME/.noctavault}"
NOCTAVAULT_LISTEN="${NOCTAVAULT_LISTEN:-0.0.0.0:7777}"

log() { printf '\033[1;36m==>\033[0m %s\n' "$1"; }
warn() { printf '\033[1;33m!!\033[0m %s\n' "$1" >&2; }
die() { printf '\033[1;31merreur:\033[0m %s\n' "$1" >&2; exit 1; }

need_root_prefix() {
    if [ "$(id -u)" = "0" ]; then
        echo ""
    elif command -v sudo >/dev/null 2>&1; then
        echo "sudo"
    else
        die "besoin des droits root (sudo introuvable) pour installer les paquets système / le service"
    fi
}

# Dépendances minimales : juste la compilation Rust + openssl. Pas de
# GTK/webkit/appindicator/librsvg (réservés à la GUI, voir get.sh) — un
# nœud headless n'a besoin que de nv-node.
install_system_deps() {
    sudo_cmd=$(need_root_prefix)

    if command -v pacman >/dev/null 2>&1; then
        log "détection : Arch Linux (pacman)"
        $sudo_cmd pacman -Syu --needed --noconfirm base-devel curl wget openssl
    elif command -v apt-get >/dev/null 2>&1; then
        log "détection : Debian/Ubuntu (apt)"
        $sudo_cmd apt-get update
        $sudo_cmd apt-get install -y build-essential curl wget pkg-config libssl-dev
    elif command -v dnf >/dev/null 2>&1; then
        log "détection : Fedora (dnf)"
        $sudo_cmd dnf install -y curl wget openssl-devel
        $sudo_cmd dnf group install -y "c-development"
    elif command -v zypper >/dev/null 2>&1; then
        log "détection : openSUSE (zypper)"
        $sudo_cmd zypper --non-interactive install curl wget libopenssl-devel
        $sudo_cmd zypper --non-interactive install -t pattern devel_basis
    elif command -v apk >/dev/null 2>&1; then
        log "détection : Alpine (apk)"
        $sudo_cmd apk add --no-cache build-base curl wget openssl
    else
        warn "distribution non reconnue : installe toi-même gcc/make, openssl-dev, curl, wget"
    fi
}

install_rust() {
    if command -v cargo >/dev/null 2>&1; then
        log "Rust déjà présent : $(cargo --version)"
        return
    fi
    log "installation de Rust via rustup"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    . "$HOME/.cargo/env"
}

fetch_source() {
    if [ -f "Cargo.toml" ] && grep -q "nv-node" Cargo.toml 2>/dev/null; then
        log "dépôt déjà présent dans le répertoire courant"
        SRC_DIR="$(pwd)"
        return
    fi
    if [ -d "noctavault" ] && [ -f "noctavault/Cargo.toml" ]; then
        SRC_DIR="$(pwd)/noctavault"
        return
    fi
    log "clonage du dépôt ($REPO_URL)"
    command -v git >/dev/null 2>&1 || die "git est requis pour cloner le dépôt"
    git clone --depth 1 "$REPO_URL" noctavault
    SRC_DIR="$(pwd)/noctavault"
}

build_and_install() {
    log "compilation de nv-node (release) — peut prendre plusieurs minutes"
    ( cd "$SRC_DIR" && cargo build --release -p nv-node )

    mkdir -p "$INSTALL_DIR"
    cp "$SRC_DIR/target/release/nv-node" "$INSTALL_DIR/nv-node"
    chmod +x "$INSTALL_DIR/nv-node"
    log "binaire installé dans $INSTALL_DIR/nv-node"

    case ":$PATH:" in
        *":$INSTALL_DIR:"*) ;;
        *) warn "$INSTALL_DIR n'est pas dans le PATH — ajoute-le à ton shell rc :" ;
           warn "  export PATH=\"$INSTALL_DIR:\$PATH\"" ;;
    esac
}

init_identity() {
    if [ -f "$NOCTAVAULT_HOME/identity.nvkey" ]; then
        log "identité déjà présente dans $NOCTAVAULT_HOME"
        return
    fi
    log "création de l'identité post-quantique dans $NOCTAVAULT_HOME"
    "$INSTALL_DIR/nv-node" --home "$NOCTAVAULT_HOME" init
    if [ -n "${NOCTAVAULT_PEERS:-}" ]; then
        # Amorce la config avec les pairs fournis ; le daemon les gardera.
        "$INSTALL_DIR/nv-node" --home "$NOCTAVAULT_HOME" status >/dev/null 2>&1 || true
    fi
}

# Service systemd système (persiste au reboot, pas de session utilisateur
# requise) plutôt qu'un service --user, adapté à un VPS.
setup_systemd_service() {
    if ! command -v systemctl >/dev/null 2>&1; then
        warn "systemctl introuvable : lance manuellement :"
        warn "  $INSTALL_DIR/nv-node --home $NOCTAVAULT_HOME daemon --listen $NOCTAVAULT_LISTEN"
        return
    fi
    sudo_cmd=$(need_root_prefix)
    service_user="$(id -un)"
    unit_path="/etc/systemd/system/nv-node-daemon.service"
    peers_arg=""
    if [ -n "${NOCTAVAULT_PEERS:-}" ]; then
        peers_arg=" --peers $NOCTAVAULT_PEERS"
    fi

    log "configuration du service systemd nv-node-daemon (utilisateur $service_user)"
    tmp_unit="$(mktemp)"
    cat > "$tmp_unit" <<EOF
[Unit]
Description=Nœud Noctavault (daemon headless)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$service_user
ExecStart=$INSTALL_DIR/nv-node --home $NOCTAVAULT_HOME daemon --listen $NOCTAVAULT_LISTEN$peers_arg
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    $sudo_cmd cp "$tmp_unit" "$unit_path"
    rm -f "$tmp_unit"
    $sudo_cmd systemctl daemon-reload
    $sudo_cmd systemctl enable --now nv-node-daemon.service
    log "service actif — vérifier : systemctl status nv-node-daemon"
}

main() {
    install_system_deps
    install_rust
    fetch_source
    build_and_install
    init_identity
    setup_systemd_service

    log "installation terminée"
    printf '\n'
    printf '  systemctl status nv-node-daemon        # état du service\n'
    printf '  journalctl -u nv-node-daemon -f         # logs en direct\n'
    printf '  nv-node --home %s id -o moi.nvid\n' "$NOCTAVAULT_HOME"
}

main "$@"
