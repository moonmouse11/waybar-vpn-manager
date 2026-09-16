from .openvpn import OpenVPNProvider
from .wireguard import WireGuardProvider
from .outline import OutlineProvider
from .happ import HappProvider

ALL_PROVIDERS = [
    WireGuardProvider(),
    OutlineProvider(),
    OpenVPNProvider(),
    HappProvider(),
]
