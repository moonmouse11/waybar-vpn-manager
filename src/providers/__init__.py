from .openvpn import OpenVPNProvider
from .wireguard import WireGuardProvider
from .outline import OutlineProvider

ALL_PROVIDERS = [
    WireGuardProvider(),
    OutlineProvider(),
    OpenVPNProvider(),
]
