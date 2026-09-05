# MCP Collection

这是一个可扩展的 MCP 集合仓库。每个 MCP 位于自己的一级子目录，拥有独立的文档、依赖和配置示例；新增 MCP 时只需新增同级目录，不应改动已有 MCP 的运行入口。

## 目录结构

`	ext
mcp/
├── network-terminal/      # 持久 SSH/串口终端 MCP
└── <future-mcp>/          # 后续 MCP 的独立目录
`

## 已包含 MCP

- [
etwork-terminal](network-terminal/README.md)：通过持久 SSH 或串口操作已授权网络设备，并强制要求同一会话有实际连接的 MobaXterm 只读观察客户端。

每个子目录中的 mcp.example.json 都是独立配置模板。不要将凭据、本机绝对路径、真实网络资产或工作区私有配置提交到本仓库。