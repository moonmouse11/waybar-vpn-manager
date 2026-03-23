#!/usr/bin/env bash
set -e

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="$HOME/.config/waybar/vpn-manager"
WAYBAR_SCRIPTS="$HOME/.config/waybar/scripts"

echo "==> waybar-vpn-manager installer"
echo ""

# ── Dependencies ──────────────────────────────────────────────────────────────

echo "==> Installing dependencies..."
sudo pacman -S --needed --noconfirm python wireguard-tools openresolv socat

# ── sudoers rule ──────────────────────────────────────────────────────────────

SUDOERS_FILE="/etc/sudoers.d/vpn-manager"
if [[ ! -f "$SUDOERS_FILE" ]]; then
    echo "==> Creating sudoers rule for wg-quick..."
    echo "$USER ALL=(ALL) NOPASSWD: /usr/bin/wg-quick, /usr/bin/cp, /usr/bin/chmod" \
        | sudo tee "$SUDOERS_FILE" > /dev/null
    sudo chmod 440 "$SUDOERS_FILE"
else
    echo "==> sudoers rule already exists, skipping."
fi

# ── /etc/wireguard permissions ────────────────────────────────────────────────

echo "==> Setting /etc/wireguard directory permissions..."
sudo mkdir -p /etc/wireguard
sudo chmod o+rx /etc/wireguard

# ── Fix resolvconf ────────────────────────────────────────────────────────────

if [[ -L /etc/resolv.conf ]]; then
    echo "==> Fixing /etc/resolv.conf for openresolv..."
    sudo rm /etc/resolv.conf
    sudo resolvconf -u
fi

# ── Copy files ────────────────────────────────────────────────────────────────

echo "==> Installing to $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"
cp -r "$REPO_DIR/src" "$INSTALL_DIR/"

echo "==> Installing waybar scripts to $WAYBAR_SCRIPTS..."
mkdir -p "$WAYBAR_SCRIPTS"
cp "$REPO_DIR/waybar/vpn-status.sh" "$WAYBAR_SCRIPTS/vpn-status.sh"
cp "$REPO_DIR/waybar/vpn-menu.sh"   "$WAYBAR_SCRIPTS/vpn-menu.sh"
chmod +x "$WAYBAR_SCRIPTS/vpn-status.sh" "$WAYBAR_SCRIPTS/vpn-menu.sh"

# ── Waybar config hint ────────────────────────────────────────────────────────

echo ""
echo "==> Done! Add this to your ~/.config/waybar/config.jsonc:"
echo ""
cat <<'EOF'
  "custom/vpn": {
    "exec": "~/.config/waybar/scripts/vpn-status.sh",
    "return-type": "json",
    "interval": 3,
    "signal": 11,
    "on-click": "~/.config/waybar/scripts/vpn-menu.sh",
  },
EOF
echo ""
echo "Then run: omarchy-restart-waybar"
