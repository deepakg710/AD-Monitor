"""Helper for importing windows/native-host/native_host.py in automated tests."""
from __future__ import annotations

import importlib.util
from pathlib import Path


def load_native_host_module():
    path = Path(__file__).resolve().parent / "native-host" / "native_host.py"
    spec = importlib.util.spec_from_file_location("admonitor_native_host", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load native_host.py from {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod
