"""Network Terminal MCP 的单一版本信息源。"""

from __future__ import annotations

from typing import Any

__version__ = "1.0.0"
RELEASE_DATE = "2026-09-05"

CHANGES = [
    "提供通用的持久 SSH/串口会话与本机只读 TCP 镜像。",
    "所有设备写入要求同一 session 存在实际连接的镜像观察客户端。",
    "串口在镜像客户端实际连接后才执行登录 bootstrap。",
    "凭据仅在内存中使用，输出和异常均经过脱敏。",
]

KNOWN_LIMITATIONS = [
    "SSH 连接和主机指纹验证发生在镜像建立之前；会话就绪后的设备写入仍必须有实时观察客户端。",
    "图形凭据输入依赖平台可用的 tkinter；无图形环境需要调用方提供独立的安全凭据通道。",
    "只读观察流程要求 Windows 上的 MobaXterm 实际连接同一会话的本机镜像端口。",
    "镜像只提供观察能力，客户端输入不会转发到设备。",
    "会话和凭据仅驻留 MCP Server 内存，服务重启后需要重新连接。",
]


def version_info() -> dict[str, Any]:
    """返回可安全公开的版本、变更与限制。"""

    return {
        "name": "network-terminal",
        "version": __version__,
        "release_date": RELEASE_DATE,
        "changes": list(CHANGES),
        "known_limitations": list(KNOWN_LIMITATIONS),
    }
