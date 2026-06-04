"""sast — thin launcher for the Insomnia SAST binary.

`pip install sast` lays down only this tiny pure-Python launcher. The actual
SAST engine is a prebuilt, self-contained binary that is fetched on first run
from insom.ai, matched to your OS, checksum-verified, and cached. Subsequent
runs exec the cached binary directly.
"""

__version__ = "0.1.0"
