#!/bin/sh
# Installe Noctavault : dépendances système + Rust (si absent), compile
# nv-node (CLI) et nv-app (GUI), installe les binaires dans ~/.local/bin.
#
# Usage :
#   curl -fsSL https://raw.githubusercontent.com/USER/noctavault/main/get.sh | sh
#
# ou, depuis un clone existant :
#   ./get.sh
#
# Si `sudo` te redemande ton mot de passe et que ça bloque (stdin déjà
# utilisé par le pipe curl | sh), télécharge d'abord le script puis
# exécute-le normalement :
#   curl -fsSL .../get.sh -o get.sh && sh get.sh
set -e

# À adapter une fois le dépôt rendu public (pas de remote configuré pour
# l'instant : le script clone alors ce dépôt si on ne s'y trouve pas déjà).
REPO_URL="${NOCTAVAULT_REPO_URL:-https://github.com/USER/noctavault.git}"
INSTALL_DIR="${NOCTAVAULT_INSTALL_DIR:-$HOME/.local/bin}"

log() { printf '\033[1;36m==>\033[0m %s\n' "$1"; }
warn() { printf '\033[1;33m!!\033[0m %s\n' "$1" >&2; }
die() { printf '\033[1;31merreur:\033[0m %s\n' "$1" >&2; exit 1; }

need_root_prefix() {
    if [ "$(id -u)" = "0" ]; then
        echo ""
    elif command -v sudo >/dev/null 2>&1; then
        echo "sudo"
    else
        die "besoin des droits root (sudo introuvable) pour installer les paquets système"
    fi
}

install_system_deps() {
    sudo_cmd=$(need_root_prefix)

    # Paquets alignés sur https://v2.tauri.app/start/prerequisites/
    # (webkit2gtk 4.1, pas 4.0 — requis par Tauri v2).
    if command -v pacman >/dev/null 2>&1; then
        log "détection : Arch Linux (pacman)"
        # -Syu (pas -Sy seul) : une mise à jour partielle de la base de
        # paquets sans mettre à jour le système est le piège classique
        # qui peut casser une install Arch.
        $sudo_cmd pacman -Syu --needed --noconfirm \
            base-devel curl wget file openssl \
            webkit2gtk-4.1 appmenu-gtk-module libappindicator-gtk3 \
            librsvg xdotool
    elif command -v apt-get >/dev/null 2>&1; then
        log "détection : Debian/Ubuntu (apt)"
        $sudo_cmd apt-get update
        $sudo_cmd apt-get install -y \
            libwebkit2gtk-4.1-dev build-essential curl wget file \
            libxdo-dev libssl-dev libayatana-appindicator3-dev librsvg2-dev
    elif command -v dnf >/dev/null 2>&1; then
        log "détection : Fedora (dnf)"
        $sudo_cmd dnf install -y \
            webkit2gtk4.1-devel openssl-devel curl wget file \
            libappindicator-gtk3-devel librsvg2-devel libxdo-devel
        $sudo_cmd dnf group install -y "c-development"
    elif command -v zypper >/dev/null 2>&1; then
        log "détection : openSUSE (zypper)"
        $sudo_cmd zypper --non-interactive install \
            webkit2gtk3-devel libopenssl-devel curl wget file \
            libappindicator3-1 librsvg-devel
        $sudo_cmd zypper --non-interactive install -t pattern devel_basis
    elif command -v apk >/dev/null 2>&1; then
        log "détection : Alpine (apk)"
        $sudo_cmd apk add --no-cache \
            build-base webkit2gtk-4.1-dev curl wget file openssl \
            libayatana-appindicator-dev librsvg
    else
        warn "distribution non reconnue : dépendances système à installer à la main"
        warn "(webkit2gtk 4.1, gtk3, libappindicator, librsvg, openssl, outils de compilation)"
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
    log "compilation (release) — peut prendre plusieurs minutes"
    ( cd "$SRC_DIR" && cargo build --release -p nv-node -p nv-app )

    mkdir -p "$INSTALL_DIR"
    cp "$SRC_DIR/target/release/nv-node" "$INSTALL_DIR/nv-node"
    cp "$SRC_DIR/target/release/nv-app" "$INSTALL_DIR/nv-app"
    chmod +x "$INSTALL_DIR/nv-node" "$INSTALL_DIR/nv-app"
    log "binaires installés dans $INSTALL_DIR"

    case ":$PATH:" in
        *":$INSTALL_DIR:"*) ;;
        *) warn "$INSTALL_DIR n'est pas dans le PATH — ajoute-le à ton shell rc :" ;
           warn "  export PATH=\"$INSTALL_DIR:\$PATH\"" ;;
    esac
}

main() {
    install_system_deps
    install_rust
    fetch_source
    build_and_install

    log "installation terminée"
    printf '\n'
    printf '  nv-node --home ~/.noctavault init     # créer son identité\n'
    printf '  nv-node --home ~/.noctavault id -o moi.nvid\n'
    printf '  nv-app                                 # lancer la GUI\n'
}

main "$@"
