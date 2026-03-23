from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class VPNConnection:
    name: str
    provider: str
    active: bool
    interface: Optional[str] = None
    config_path: Optional[str] = None


@dataclass
class ActionResult:
    success: bool
    message: str


class VPNProvider(ABC):

    @property
    @abstractmethod
    def name(self) -> str:
        """Display name of the provider, e.g. 'WireGuard'"""
        ...

    @abstractmethod
    def connections(self) -> list[VPNConnection]:
        """Return all known connections (active and inactive)"""
        ...

    @abstractmethod
    def connect(self, connection: VPNConnection) -> ActionResult:
        ...

    @abstractmethod
    def disconnect(self, connection: VPNConnection) -> ActionResult:
        ...

    @abstractmethod
    def import_config(self, path: str) -> ActionResult:
        """Import a config file and register it as a new connection"""
        ...
