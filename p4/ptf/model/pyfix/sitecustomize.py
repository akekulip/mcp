"""Repoint the `google` namespace package at the SDE's protobuf 3.20.3.

Debian ships `/usr/lib/python3/dist-packages/protobuf-*-nspkg.pth`, which runs during site.py
and PINS `google.__path__` to dist-packages. That happens before PYTHONPATH is consulted, so
the SDE's own protobuf 3.20.3 is never reached and `bfruntime_pb2` fails on
`from google.protobuf.internal import builder` (added in 3.20). sitecustomize is imported at
the END of site.py, so it can put the SDE's copy back in front.
"""
import os
import sys

_SDE = os.environ.get("SDE_INSTALL", "/home/philip/bf-sde-9.13.1/install")
_G = os.path.join(_SDE, "lib", "python3.8", "site-packages", "google")
if os.path.isdir(_G):
    try:
        import google
        if _G not in list(google.__path__):
            google.__path__.insert(0, _G)
        sys.modules.pop("google.protobuf", None)
    except Exception:
        pass
