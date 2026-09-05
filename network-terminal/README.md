# Network Terminal MCP

面向 Kiro 的持久 SSH/串口终端 MCP Server。它把 Agent 的设备控制与 MobaXterm 的人工只读观察隔离：所有设备写入只有在同一会话存在真实连接的 MobaXterm 镜像客户端时才会执行。

## 安全模型

- SSH 在认证前必须校验 `SHA256:` 主机指纹；旧 `ssh-rsa` 兼容只能显式按会话开启。
- 凭据由隐藏输入框采集，只保留在 MCP 内存中；缓冲、镜像和 MCP 返回均会脱敏。
- 镜像只监听 `127.0.0.1`，MobaXterm 客户端输入被主动丢弃，不能控制设备。
- 串口连接在 MobaXterm 实际连接之前不发送任何 bootstrap 字节。
- `terminal_exec` 不逐命令确认，但命令、控制键和自动翻页均要求同一 session 的实时镜像客户端。

## 安装

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install --upgrade pip
.\.venv\Scripts\python -m pip install -r requirements.txt
```

将 [mcp.example.json](mcp.example.json) 中的占位路径替换为实际绝对路径后，合并到 Kiro 的 `.kiro/settings/mcp.json`。示例默认不自动批准任何工具；如要启用 `terminal_exec` 自动批准，必须先确认该权限允许 Agent 执行广泛的设备命令。

在连接会话后，调用 `terminal_mirror` 并显式提供 `MobaXterm.exe` 路径。只有 MobaXterm 已实际连入返回的本机端口，`mirror_clients >= 1` 且 `operator_visible=true` 时，控制操作才会被接受。

## 运行

```powershell
.\.venv\Scripts\python -m network_terminal_mcp.server
```

服务使用 stdio MCP 协议；不要向 stdout 写入应用日志。

## 限制

此发布版要求使用 Windows MobaXterm 作为只读观察客户端。它不包含设备厂商命令、真实设备拓扑、测试资产、凭据或本机配置。

## 许可证

本项目采用 [MIT License](LICENSE)。
