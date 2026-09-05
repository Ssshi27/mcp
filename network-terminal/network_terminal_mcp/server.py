"""通过 stdio 暴露网络终端 MCP Server。"""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
import sys
from typing import Any, AsyncIterator, Callable

from mcp.server.mcpserver import MCPServer

if __package__ in {None, ""}:
    # 允许 MCP 客户端直接以脚本路径启动，同时不依赖工作目录。
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from network_terminal_mcp.core import SessionManager
    from network_terminal_mcp.version import __version__, version_info
else:
    from .core import SessionManager
    from .version import __version__, version_info

_MANAGER = SessionManager()


@asynccontextmanager
async def _lifespan(_server: MCPServer[Any]) -> AsyncIterator[dict[str, Any]]:
    """服务退出时幂等关闭全部会话、镜像和内存凭据。"""

    try:
        yield {"manager": _MANAGER}
    finally:
        _MANAGER.close_all()


server = MCPServer(
    name="network-terminal",
    description="持久 SSH/串口网络终端；控制与只读可视镜像分离。",
    version=__version__,
    lifespan=_lifespan,
)


def _call(function: Callable[..., dict[str, Any]], *args: Any, **kwargs: Any) -> dict[str, Any]:
    """统一把异常转换为已脱敏的结构化返回。"""

    try:
        result = function(*args, **kwargs)
    except Exception as exc:  # MCP 边界必须返回安全错误，不能泄漏凭据
        result = {"status": "error", "error": f"{type(exc).__name__}: {exc}"}
    return _MANAGER.sanitize_value(result)


@server.tool()
def terminal_version() -> dict[str, Any]:
    """返回当前 MCP 版本、本版改进和已知限制。"""

    return version_info()


@server.tool()
def terminal_prompt_credential(
    label: str = "设备登录",
    prompt_enable_password: bool = False,
) -> dict[str, Any]:
    """通过 tkinter 隐藏窗口采集密码，仅返回内存凭据 ID。"""

    return _call(_MANAGER.prompt_credential, label, prompt_enable_password)


@server.tool()
def terminal_connect(
    transport: str,
    username: str,
    credential_id: str,
    host: str | None = None,
    port: int = 22,
    host_key_sha256: str | None = None,
    legacy_ssh_rsa: bool = False,
    serial_device: str | None = None,
    baudrate: int = 115200,
    xonxoff: bool = True,
    timeout: float = 20.0,
) -> dict[str, Any]:
    """建立持久 SSH 或串口会话；串口先等待同一 session 的镜像观察者再 bootstrap。"""

    return _call(
        _MANAGER.connect,
        transport=transport,
        username=username,
        credential_id=credential_id,
        host=host,
        port=port,
        host_key_sha256=host_key_sha256,
        legacy_ssh_rsa=legacy_ssh_rsa,
        serial_device=serial_device,
        baudrate=baudrate,
        xonxoff=xonxoff,
        timeout=timeout,
    )


@server.tool()
def terminal_exec(
    session_id: str,
    command: str,
    timeout: float = 20.0,
    confirmation_token: str | None = None,
) -> dict[str, Any]:
    """仅在该会话有已连接只读镜像观察者时执行命令；不发起人工确认。"""

    return _call(_MANAGER.execute, session_id, command, timeout, confirmation_token)


@server.tool()
def terminal_send_raw(session_id: str, action: str) -> dict[str, Any]:
    """仅在该会话有已连接只读镜像观察者时发送白名单控制键。"""

    return _call(_MANAGER.send_raw, session_id, action)


@server.tool()
def terminal_read(
    session_id: str,
    offset: int | None = None,
    max_bytes: int = 65536,
) -> dict[str, Any]:
    """按绝对 offset 非消费式读取脱敏环形缓冲，支持多个观察者。"""

    return _call(_MANAGER.read, session_id, offset, max_bytes)


@server.tool()
def terminal_expect(
    session_id: str,
    pattern: str,
    offset: int | None = None,
    timeout: float = 20.0,
) -> dict[str, Any]:
    """等待脱敏缓冲出现正则表达式，不消费任何观察者的数据。"""

    return _call(_MANAGER.expect, session_id, pattern, offset, timeout)


@server.tool()
def terminal_state(session_id: str | None = None) -> dict[str, Any]:
    """返回一个或全部会话状态，不包含凭据或原始敏感输出。"""

    return _call(_MANAGER.state, session_id)


@server.tool()
def terminal_mirror(
    session_id: str,
    launch_mobaxterm: bool = False,
    mobaxterm_path: str = "",
) -> dict[str, Any]:
    """启动 127.0.0.1 随机端口只读镜像；可显式提供 MobaXterm 路径作为 Windows 便利功能。"""

    return _call(_MANAGER.mirror, session_id, launch_mobaxterm, mobaxterm_path)


@server.tool()
def terminal_close(session_id: str) -> dict[str, Any]:
    """幂等关闭指定会话及其镜像。"""

    return _call(_MANAGER.close, session_id)


def main() -> None:
    """以 stdio 传输运行，不写 stdout 日志。"""

    server.run(transport="stdio")


if __name__ == "__main__":
    main()
