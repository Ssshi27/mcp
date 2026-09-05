"""网络终端 MCP Server。"""

from .core import SessionManager
from .version import __version__, version_info

__all__ = ["SessionManager", "__version__", "version_info"]
