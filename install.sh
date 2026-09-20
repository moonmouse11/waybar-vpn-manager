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
#   cat on the same config globs (menu-imported configs are root:0600 — the
#   background ping sweep reads endpoints via 'sudo -n cat'),
#   systemctl enable/disable wg-quick@*, happ-killswitch (root-owned script).
# `kill <pid>` stays broad (arbitrary numeric PIDs cannot be pattern-matched).
# THREAT MODEL: sudoers matches command arguments lexically and `*` spans
# `/` and `..`, so `sudo -n cat /etc/wireguard/../../../etc/shadow` matches
# the cat rules below — i.e. the cat entries are equivalent to root read
# access, and together with the unbounded `cp *` source they allow reading
# back any root file the user could copy there. Accepted deliberately: this
# installer targets a single-user machine whose owner already runs it with
# full interactive sudo (pacman, tee into /etc/sudoers.d, ...), so the owner
# is root-equivalent anyway; the rules only remove a password prompt. Remove
# the two cat entries if that trade-off is unacceptable.
# If a narrowed rule ever blocks a legit call, fall back to the broad form:
#   ... NOPASSWD: /usr/bin/wg-quick, /usr/bin/openvpn, /usr/bin/kill, /usr/bin/mkdir, /usr/bin/rm, /usr/bin/cp, /usr/bin/chmod, ...
echo "==> Writing sudoers rule..."
echo "$USER ALL=(ALL) NOPASSWD: /usr/bin/wg-quick, /usr/bin/openvpn --config * --daemon --writepid /run/openvpn/client-*.pid, /usr/bin/kill, /usr/bin/mkdir -p /run/openvpn, /usr/bin/rm -f /run/openvpn/client-*.pid, /usr/bin/rm -f /etc/wireguard/*.conf, /usr/bin/cp * /etc/wireguard/*, /usr/bin/cp * /etc/openvpn/client/*, /usr/bin/chmod 600 /etc/wireguard/*, /usr/bin/chmod 600 /etc/openvpn/client/*, /usr/bin/cat /etc/wireguard/*, /usr/bin/cat /etc/openvpn/client/*, /usr/bin/systemctl enable wg-quick@*, /usr/bin/systemctl disable wg-quick@*, /usr/local/bin/happ-killswitch" \
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

# ── Omarchy integration: waybar module + keybinding ──────────────────────────
# Edits the user's waybar config BEFORE any files are copied/sudoers written,
# so a broken config.jsonc aborts the install without side effects.

WAYBAR_CONFIG="$HOME/.config/waybar/config.jsonc"
if [[ -f "$WAYBAR_CONFIG" ]] && ! grep -q '"custom/vpn"' "$WAYBAR_CONFIG"; then
    echo "==> Adding custom/vpn module to $WAYBAR_CONFIG"
    python3 - "$WAYBAR_CONFIG" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
text = path.read_text()
module = '''  "custom/vpn": {
    "exec": "~/.config/waybar/scripts/vpn-status.sh",
    "return-type": "json",
    "interval": 3,
    "signal": 11,
    "on-click": "~/.config/waybar/scripts/vpn-menu.sh"
  }'''
lines = text.splitlines(keepends=True)
for i, line in enumerate(lines):
    if '"modules-right"' in line and '[' in line:
        indent = line[: len(line) - len(line.lstrip())] + "  "
        lines.insert(i + 1, f'{indent}"custom/vpn",\n')
        break
text = "".join(lines).rstrip()
if not text.endswith("}"):
    print(f"error: could not update {path}: expected a JSON object ending with '}}'", file=sys.stderr)
    sys.exit(1)
path.write_text(text[:-1] + f",\n{module}\n}}\n")
PY
    echo "==> Module inserted."
else
    echo "==> waybar module already present or config missing, skipping."
fi

BINDINGS="$HOME/.config/hypr/bindings.conf"
if [[ -f "$BINDINGS" ]] && ! grep -q 'waybar-vpn-manager' "$BINDINGS"; then
    echo "==> Adding SUPER+Shift+V binding to $BINDINGS"
    cat >> "$BINDINGS" <<'EOF'

# >>> waybar-vpn-manager
bindd = SUPER SHIFT, V, VPN menu, exec, ~/.config/waybar/scripts/vpn-menu.sh
# <<< waybar-vpn-manager
EOF
else
    echo "==> keybinding already present or bindings.conf missing, skipping."
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

# ── Final hints ───────────────────────────────────────────────────────────────

echo ""
echo "==> Done!"
echo "    - waybar module:  inserted automatically (or already present)"
echo "    - keybinding:     SUPER+Shift+V opens the VPN menu"
echo ""
echo "    Restart the components:"
echo "      omarchy restart waybar"
echo "      hyprctl reload   (or just log out/in)"
