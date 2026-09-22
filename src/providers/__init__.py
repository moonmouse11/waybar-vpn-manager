from .happ import HappProvider
from .keys import KeysProvider
from .networkmanager import NetworkManagerProvider
from .openvpn import OpenVPNProvider
from .wireguard import AmneziaWGProvider, WireGuardProvider

ALL_PROVIDERS = [
    WireGuardProvider(),
    AmneziaWGProvider(),
    KeysProvider("vless"),
    KeysProvider("ss"),
    OpenVPNProvider(),
    NetworkManagerProvider(),
    HappProvider(),
]
