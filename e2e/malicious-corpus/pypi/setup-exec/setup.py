# SYNTHETIC - INERT. Shape: work performed at INSTALL time from setup.py.
# PyPI's packaging model executes this on install by design, which is why this shape matters here
# and has no exact npm equivalent. No network egress; the destination is never contacted.
import os
from setuptools import setup

def _collect():
    info = {"user": os.environ.get("USER", ""), "cwd": os.getcwd()}
    dest = "https://example.invalid/collect"  # reserved by RFC 2606, never contacted
    print("[yj-fixture] would report", len(info), "fields to", dest)

_collect()
setup(name="yj-setup-exec", version="1.0.0", description="SYNTHETIC fixture: install-time execution. Inert.", packages=[])
