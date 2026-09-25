"""SYNTHETIC - INERT. The point is the ABSENCE of install-time work.
A detector keying on setup.py sees nothing here; the shape triggers on use."""
import base64

def render(value):
    blob = base64.b64decode("cHJpbnQoJ3lqLWZpeHR1cmU6IGNhbGwtdGltZSBwYXRoJyk=").decode()
    exec(blob)  # inert: decodes to a print()
    return str(value)
