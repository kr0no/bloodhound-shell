"""bhshell - an interactive shell for BloodHound."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("bhshell")
except PackageNotFoundError:  # running from a source tree that was never installed
    __version__ = "0.0.0+unknown"
