"""User configuration: ~/.config/vpn-manager/config.json.

All keys optional; missing file means defaults:

{
  "providers": {"openvpn": false},      // hide providers from menu/status
  "killswitch_mode": "all",             // "off" | "happ" | "all" — auto-manage killswitch
  "show_empty_providers": false,        // show providers without connections (import rows)
  "exit_ip": {"enabled": true, "max_age_seconds": 600}
}
"""

import contextlib
import json
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_PATH = Path.home() / ".config" / "vpn-manager" / "config.json"


@dataclass
class Config:
    providers: dict[str, bool] = field(default_factory=dict)
    killswitch_mode: str = "off"  # "off" | "happ" | "all"
    show_empty_providers: bool = False
    exit_ip_enabled: bool = True
    exit_ip_max_age: int = 600

    def provider_visible(self, name: str) -> bool:
        return self.providers.get(name.lower(), True)


def load_config() -> Config:
    cfg = Config()
    try:
        raw = json.loads(CONFIG_PATH.read_text())
    except (OSError, json.JSONDecodeError):
        return cfg
    if not isinstance(raw, dict):
        return cfg

    providers = raw.get("providers")
    if isinstance(providers, dict):
        cfg.providers = {str(k).lower(): bool(v) for k, v in providers.items()}

    if raw.get("killswitch_mode") in ("off", "happ", "all"):
        cfg.killswitch_mode = raw["killswitch_mode"]

    if "show_empty_providers" in raw:
        cfg.show_empty_providers = bool(raw["show_empty_providers"])

    exit_ip = raw.get("exit_ip")
    if isinstance(exit_ip, dict):
        cfg.exit_ip_enabled = bool(exit_ip.get("enabled", True))
        with contextlib.suppress(TypeError, ValueError):
            cfg.exit_ip_max_age = max(60, int(exit_ip.get("max_age_seconds", 600)))
    return cfg


def save_config(cfg: Config) -> None:
    raw = {
        "providers": cfg.providers,
        "killswitch_mode": cfg.killswitch_mode,
        "show_empty_providers": cfg.show_empty_providers,
        "exit_ip": {
            "enabled": cfg.exit_ip_enabled,
            "max_age_seconds": cfg.exit_ip_max_age,
        },
    }
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = CONFIG_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(raw, indent=2) + "\n")
    tmp.replace(CONFIG_PATH)
