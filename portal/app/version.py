"""Portal build version helpers."""

import os


def get_portal_version():
    # type: () -> str
    """Return the portal build version from the environment."""
    return os.getenv("PORTAL_VERSION", os.getenv("IMAGE_TAG", "dev"))
