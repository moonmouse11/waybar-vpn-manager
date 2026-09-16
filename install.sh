#!/usr/bin/env bash
set -e

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="$HOME/.config/waybar/vpn-manager"
WAYBAR_SCRIPTS="$HOME/.config/waybar/scripts"

echo "==> waybar-vpn-manager installer"
echo ""

# ── Dependencies ──────────────────────────────────────────────────────────────

echo "==> Installing dependencies..."
sudo pacman -S --needed --noconfirm python wireguard-tools openvpn openresolv socat

# ── sudoers rule ──────────────────────────────────────────────────────────────

SUDOERS_FILE="/etc/sudoers.d/vpn-manager"
# Managed by this installer: rewrite on every run so upgrades pick up new rules.
# Rules are narrowed to the exact call patterns used by the providers:
#   wg-quick up/down <profile>, openvpn --config/--daemon/--writepid,
#   mkdir/rm/cp/chmod only under /run/openvpn, /etc/wireguard, /etc/openvpn/client,
#   systemctl enable/disable wg-quick@*, happ-killswitch (root-owned script).
# `kill <pid>` stays broad (arbitrary numeric PIDs cannot be pattern-matched).
# If a narrowed rule ever blocks a legit call, fall back to the broad form:
#   ... NOPASSWD: /usr/bin/wg-quick, /usr/bin/openvpn, /usr/bin/kill, /usr/bin/mkdir, /usr/bin/rm, /usr/bin/cp, /usr/bin/chmod, ...
echo "==> Writing sudoers rule..."
echo "$USER ALL=(ALL) NOPASSWD: /usr/bin/wg-quick, /usr/bin/openvpn --config * --daemon --writepid /run/openvpn/client-*.pid, /usr/bin/kill, /usr/bin/mkdir -p /run/openvpn, /usr/bin/rm -f /run/openvpn/client-*.pid, /usr/bin/rm -f /etc/wireguard/*.conf, /usr/bin/cp * /etc/wireguard/*, /usr/bin/cp * /etc/openvpn/client/*, /usr/bin/chmod 600 /etc/wireguard/*, /usr/bin/chmod 600 /etc/openvpn/client/*, /usr/bin/systemctl enable wg-quick@*, /usr/bin/systemctl disable wg-quick@*, /usr/local/bin/happ-killswitch" \
    | sudo tee "$SUDOERS_FILE" > /dev/null
sudo chmod 440 "$SUDOERS_FILE"
sudo visudo -cf "$SUDOERS_FILE" > /dev/null && echo "==> sudoers rule validated"

# ── killswitch script (root-owned, driven via the NOPASSWD sudoers rule) ─────

echo "==> Installing happ-killswitch to /usr/local/bin..."
sudo cp "$REPO_DIR/scripts/happ-killswitch" /usr/local/bin/happ-killswitch
sudo chown root:root /usr/local/bin/happ-killswitch
sudo chmod 755 /usr/local/bin/happ-killswitch
# Remove the user-writable copy if it exists (superseded by the root-owned one)
rm -f "$HOME/.local/bin/happ-killswitch"

# ── /etc/wireguard permissions ────────────────────────────────────────────────

echo "==> Setting /etc/wireguard directory permissions..."
sudo mkdir -p /etc/wireguard
sudo chmod o+rx /etc/wireguard

# ── /etc/openvpn/client directory ─────────────────────────────────────────────

echo "==> Creating /etc/openvpn/client directory..."
sudo mkdir -p /etc/openvpn/client
sudo chmod 755 /etc/openvpn/client

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
