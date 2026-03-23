install:
	@bash install.sh

uninstall:
	rm -rf ~/.config/waybar/vpn-manager
	rm -f ~/.config/waybar/scripts/vpn-status.sh
	rm -f ~/.config/waybar/scripts/vpn-menu.sh
	sudo rm -f /etc/sudoers.d/vpn-manager
	@echo "Uninstalled. Remove the custom/vpn block from your waybar config manually."

.PHONY: install uninstall
