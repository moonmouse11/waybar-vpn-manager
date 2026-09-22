install:
	@bash install.sh

uninstall:
	rm -rf ~/.config/waybar/vpn-manager
	rm -f ~/.config/waybar/scripts/vpn-status.sh
	rm -f ~/.config/waybar/scripts/vpn-menu.sh
	sudo rm -f /etc/sudoers.d/vpn-manager
	@echo "Uninstalled. Remove the custom/vpn block from your waybar config manually."

# Lint + test in a container: no host /tmp, /run, /etc/wireguard mounts and
# no network — see Dockerfile.test for why (real happd socket / VPN state
# must never be reachable from a test run).
test-docker-build:
	docker build -t waybar-vpn-manager-test -f Dockerfile.test .

test-docker:
	docker run --rm --network none -v "$$PWD":/repo:ro -w /repo waybar-vpn-manager-test

.PHONY: install uninstall test-docker-build test-docker
