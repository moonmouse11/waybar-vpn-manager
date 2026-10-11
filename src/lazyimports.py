"""Heavy stdlib modules, registered to load on first use.

Waybar runs `--status` every 3 s, and importing everything up front cost
~180 ms of a ~240 ms run — mostly urllib.request (http.client, ssl, email),
which the status path never calls. LazyLoader registers each module in
sys.modules now and executes it on the first attribute access.

How to use one: import the parent package (`import urllib`, `import
concurrent`, `import http`) and `import lazyimports` — never `import urllib.request`:
an import statement reads the module's __spec__, which loads it.
tests/test_lazyimports.py fails if a plain import sneaks back into the
status path.
"""

import importlib.util
import sys
from types import ModuleType


def lazy(name: str) -> ModuleType:
    """Register `name` to load on first attribute access (no-op if loaded)."""
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.find_spec(name)
    if spec is None or spec.loader is None:
        raise ImportError(name)
    spec.loader = importlib.util.LazyLoader(spec.loader)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    parent, _, child = name.rpartition(".")
    if parent:
        setattr(sys.modules[parent], child, module)  # so `urllib.request` resolves
    return module


lazy("urllib.request")
lazy("http.client")
lazy("concurrent.futures")
statistics = lazy("statistics")
