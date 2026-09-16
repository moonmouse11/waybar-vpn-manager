from .happ import HappProvider
from .openvpn import OpenVPNProvider
from .outline import OutlineProvider
from .wireguard import WireGuardProvider

ALL_PROVIDERS = [
    WireGuardProvider(),
    OutlineProvider(),
    OpenVPNProvider(),
    HappProvider(),
]
