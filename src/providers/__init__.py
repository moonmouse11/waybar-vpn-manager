from .happ import HappProvider
from .networkmanager import NetworkManagerProvider
from .openvpn import OpenVPNProvider
from .outline import OutlineProvider
from .wireguard import WireGuardProvider

ALL_PROVIDERS = [
    WireGuardProvider(),
    OutlineProvider(),
    OpenVPNProvider(),
    NetworkManagerProvider(),
    HappProvider(),
]
