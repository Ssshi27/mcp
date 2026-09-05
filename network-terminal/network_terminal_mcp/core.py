"""持久网络终端会话、绝对偏移缓冲与命令安全策略。"""

from __future__ import annotations

import os
import re
import secrets
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Pattern

from .transports import PendingHostKey, SerialOptions, open_serial, open_ssh

BUFFER_LIMIT = 1024 * 1024
PROMPT_RE = re.compile(
    r"^(?:[$#]|[A-Za-z0-9_.:/@~-]+(?:\([^\r\n)]{1,80}\))?[>#$])\s*$",
    re.MULTILINE,
)
LOGIN_RE = re.compile(r"(?:login|username)\s*:\s*$", re.IGNORECASE | re.MULTILINE)
PASSWORD_RE = re.compile(r"password\s*:\s*$", re.IGNORECASE | re.MULTILINE)
MORE_RE = re.compile(r"(?:--+\s*more\s*-+|<---\s*more\s*--->|\bmore\b.*(?:space|空格))", re.IGNORECASE)
ANSI_RE = re.compile(rb"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")

COMMAND_SPLIT_RE = re.compile(r"\s*(?:&&|\|\||[;|])\s*")
COMMAND_PREFIX = r"^(?:(?:(?:sudo|doas)(?:\s+-\S+)*\s+)?)"
DELETE_COMMAND_RE = re.compile(
    COMMAND_PREFIX
    + r"(?:rm|rmdir|unlink|shred|del|erase|rd|remove-item)(?:\s|$)|"
    + COMMAND_PREFIX
    + r"git\s+(?:rm|clean)(?:\s|$)|"
    + COMMAND_PREFIX
    + r"find\b.*(?:-delete|-exec\s+(?:rm|rmdir|unlink)\b)",
    re.IGNORECASE,
)
CONFIG_PATH_PATTERN = (
    r"(?:/etc(?:[/\\][^\s\"'<>|;]*)?|/usr/local/etc(?:[/\\][^\s\"'<>|;]*)?|"
    r"(?:[A-Za-z]:[/\\])?[^\s\"'<>|;]*\.(?:conf|cfg|ini|toml|ya?ml|properties|service|rc|def))"
)
CONFIG_PATH_RE = re.compile(CONFIG_PATH_PATTERN, re.IGNORECASE)
CONFIG_REDIRECT_RE = re.compile(r"(?<!<)>{1,2}\s*" + CONFIG_PATH_PATTERN, re.IGNORECASE)
CONFIG_MUTATOR_RE = re.compile(
    COMMAND_PREFIX
    + r"(?:vi|vim|nvim|nano|emacs|ed|tee|touch|truncate|chmod|chown|chgrp|"
    r"set-content|add-content|clear-content|out-file|new-item)(?:\s|$)|"
    + COMMAND_PREFIX
    + r"(?:sed|perl)\b.*(?:^|\s)-i(?:\S*)?",
    re.IGNORECASE,
)
CONFIG_MOVE_RE = re.compile(
    COMMAND_PREFIX + r"(?:mv|move|move-item|rename-item)(?:\s|$)",
    re.IGNORECASE,
)
CONFIG_COPY_RE = re.compile(
    COMMAND_PREFIX + r"(?:cp|copy|copy-item|install)(?:\s|$)",
    re.IGNORECASE,
)
DEVICE_CONFIG_WRITE_RE = re.compile(
    COMMAND_PREFIX
    + r"(?:write(?:\s+memory)?|save|copy\s+(?:running-config|run)\s+"
    r"(?:startup-config|start)|configure\s+replace|rollback\s+configuration)(?:\s|$)",
    re.IGNORECASE,
)
RAW_ACTIONS = {"ENTER": b"\r", "SPACE": b" ", "TAB": b"\t", "CTRL_C": b"\x03", "CTRL_Z": b"\x1a"}


def command_confirmation_reason(command: str) -> str | None:
    """按命令文本识别仅需人工确认的删除与配置写入操作。"""

    segments = [segment for segment in COMMAND_SPLIT_RE.split(command.strip()) if segment]
    for segment in segments:
        if DELETE_COMMAND_RE.search(segment):
            return "命令涉及文件、目录或配置删除，需要一次性确认"
        if DEVICE_CONFIG_WRITE_RE.search(segment):
            return "命令将保存、覆盖或回滚设备配置，需要一次性确认"
        config_paths = CONFIG_PATH_RE.findall(segment)
        if not config_paths:
            continue
        if CONFIG_REDIRECT_RE.search(segment) or CONFIG_MUTATOR_RE.search(segment):
            return "命令将修改配置文件，需要一次性确认"
        if CONFIG_MOVE_RE.search(segment):
            return "命令将移动或重命名配置文件，需要一次性确认"
        if CONFIG_COPY_RE.search(segment):
            arguments = re.findall(r'"[^"]*"|\'[^\']*\'|\S+', segment)
            destination = arguments[-1].strip("\"'") if arguments else ""
            if CONFIG_PATH_RE.fullmatch(destination):
                return "命令将覆盖或创建配置文件，需要一次性确认"
    return None


@dataclass
class Credential:
    """仅驻留内存的凭据。"""

    password: str
    enable_password: str

    def clear(self) -> None:
        self.password = ""
        self.enable_password = ""


@dataclass
class Confirmation:
    """绑定会话和完整命令的一次性短期确认。"""

    session_id: str
    command: str
    expires_at: float


class StreamRedactor:
    """跨 chunk 隐藏已知凭据，仅保留可能构成秘密的末尾前缀。"""

    def __init__(self, secrets_: list[str]) -> None:
        self._secrets = sorted(
            {value.encode("utf-8") for value in secrets_ if value},
            key=len,
            reverse=True,
        )
        self._pending = b""

    def feed(self, chunk: bytes) -> bytes:
        if not chunk:
            return b""
        if not self._secrets:
            return chunk
        # 先替换完整秘密，再仅滞留仍可能在下一 chunk 中补全的后缀。
        data = self._replace(self._pending + chunk)
        self._pending = b""
        keep = 0
        for secret in self._secrets:
            upper = min(len(data), len(secret) - 1)
            for length in range(upper, 0, -1):
                if data.endswith(secret[:length]):
                    keep = max(keep, length)
                    break
        if keep:
            data, self._pending = data[:-keep], data[-keep:]
        return data

    def finish(self) -> bytes:
        # 未补全的秘密前缀也不原样输出，避免退出边界泄漏敏感片段。
        visible, self._pending = self._pending, b""
        return b"***" if visible else b""

    def _replace(self, data: bytes) -> bytes:
        for secret in self._secrets:
            data = data.replace(secret, b"***")
        return data


class AbsoluteRingBuffer:
    """容量固定为 1 MiB、以单调绝对 byte offset 定位的环形缓冲。"""

    def __init__(self, limit: int = BUFFER_LIMIT) -> None:
        self.limit = limit
        self._data = bytearray()
        self.base_offset = 0
        self.end_offset = 0

    def append(self, data: bytes) -> None:
        if not data:
            return
        self._data.extend(data)
        self.end_offset += len(data)
        overflow = len(self._data) - self.limit
        if overflow > 0:
            del self._data[:overflow]
            self.base_offset += overflow

    def read(self, offset: int | None, max_bytes: int | None = None) -> tuple[int, bytes, bool]:
        requested = self.base_offset if offset is None else max(0, offset)
        truncated = requested < self.base_offset
        start = max(requested, self.base_offset)
        index = start - self.base_offset
        data = bytes(self._data[index:])
        if max_bytes is not None:
            data = data[:max_bytes]
        return start, data, truncated

    def snapshot(self) -> bytes:
        return bytes(self._data)


class TerminalSession:
    """一个持久设备会话严格对应一个 reader 线程。"""

    def __init__(
        self,
        session_id: str,
        transport_kind: str,
        transport: Any,
        username: str,
        password: str,
        enable_password: str,
        target: str,
    ) -> None:
        self.session_id = session_id
        self.transport_kind = transport_kind
        self.transport = transport
        self.username = username
        self.target = target
        self._password = password
        self._enable_password = enable_password
        self._redactor = StreamRedactor([password, enable_password])
        self._buffer = AbsoluteRingBuffer()
        self._condition = threading.Condition()
        self._observers: list[Callable[[bytes], None]] = []
        self._stop = threading.Event()
        self._reader: threading.Thread | None = None
        self.command_lock = threading.Lock()
        self.write_lock = threading.Lock()
        self.status = "connecting"
        self.created_at = time.time()
        self.last_activity = self.created_at
        self.last_error: str | None = None
        self._last_more_at = 0.0
        self._mirror: Any | None = None
        self._serial_bootstrap_pending = transport_kind == "serial"
        self._bootstrap_lock = threading.Lock()
        self._bootstrap_thread: threading.Thread | None = None

    def start(self) -> None:
        if self._reader is not None:
            raise RuntimeError("每个会话只能创建一个 reader 线程")
        self._reader = threading.Thread(
            target=self._reader_loop,
            name=f"terminal-reader-{self.session_id}",
            daemon=True,
        )
        self._reader.start()

    def mark_ready(self) -> None:
        self.status = "ready"

    def _reader_loop(self) -> None:
        try:
            while not self._stop.is_set():
                chunk = self.transport.read()
                if chunk:
                    self.last_activity = time.time()
                    visible = self._clean_output(self._redactor.feed(chunk))
                    self._append(visible)
                    tail = visible.decode("utf-8", errors="replace")[-300:]
                    now = time.monotonic()
                    if MORE_RE.search(tail) and now - self._last_more_at >= 0.2:
                        # 自动翻页也是设备写入；仅在该会话有实时镜像观察者时执行。
                        if self._mirror_client_count() > 0:
                            with self.write_lock:
                                if self.transport.is_open() and self._mirror_client_count() > 0:
                                    self.transport.write(b" ")
                            self._last_more_at = now
                elif not self.transport.is_open():
                    if not self._stop.is_set():
                        self.status = "disconnected"
                    break
        except Exception as exc:
            self.last_error = self.redact_text(f"{type(exc).__name__}: {exc}")
            if not self._stop.is_set():
                self.status = "error"
        finally:
            self._append(self._clean_output(self._redactor.finish()))
            with self._condition:
                self._condition.notify_all()

    @staticmethod
    def _clean_output(data: bytes) -> bytes:
        data = ANSI_RE.sub(b"", data)
        while b"\x08" in data:
            updated = re.sub(rb"[^\r\n]\x08", b"", data)
            if updated == data:
                break
            data = updated
        return data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")

    def _append(self, data: bytes) -> None:
        if not data:
            return
        with self._condition:
            self._buffer.append(data)
            observers = tuple(self._observers)
            self._condition.notify_all()
        for observer in observers:
            try:
                observer(data)
            except Exception:
                # 观察者故障不能影响 reader；镜像自身负责回收客户端。
                continue

    def add_observer(self, observer: Callable[[bytes], None]) -> None:
        with self._condition:
            if observer not in self._observers:
                self._observers.append(observer)

    def remove_observer(self, observer: Callable[[bytes], None]) -> None:
        with self._condition:
            if observer in self._observers:
                self._observers.remove(observer)

    def snapshot_bytes(self) -> bytes:
        with self._condition:
            return self._buffer.snapshot()

    @property
    def end_offset(self) -> int:
        with self._condition:
            return self._buffer.end_offset

    def redact_text(self, value: str) -> str:
        for secret_ in (self._password, self._enable_password):
            if secret_:
                value = value.replace(secret_, "***")
        return value

    def _write(self, data: bytes) -> None:
        with self.write_lock:
            if not self.transport.is_open():
                raise RuntimeError("设备传输已关闭")
            self.transport.write(data)
            self.last_activity = time.time()

    def type_text(self, text: str, enter: bool, key_delay: float = 0.03) -> None:
        with self.write_lock:
            if not self.transport.is_open():
                raise RuntimeError("设备传输已关闭")
            for character in text:
                self.transport.write(character.encode("utf-8"))
                if key_delay > 0:
                    time.sleep(key_delay)
            if enter:
                self.transport.write(b"\r")
            self.last_activity = time.time()

    def _read_locked(self, offset: int | None, max_bytes: int | None) -> dict[str, Any]:
        start, data, truncated = self._buffer.read(offset, max_bytes)
        return {
            "offset": start,
            "next_offset": start + len(data),
            "base_offset": self._buffer.base_offset,
            "end_offset": self._buffer.end_offset,
            "truncated": truncated,
            "output": data.decode("utf-8", errors="replace"),
        }

    def read(self, offset: int | None, max_bytes: int = 65536) -> dict[str, Any]:
        if not 1 <= max_bytes <= BUFFER_LIMIT:
            raise ValueError("max_bytes 必须在 1 到 1048576 之间")
        with self._condition:
            return self._read_locked(offset, max_bytes)

    def wait_any(
        self,
        patterns: dict[str, Pattern[str]],
        offset: int,
        timeout: float,
        idle_timeout: float | None = None,
    ) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        last_end = -1
        last_change = time.monotonic()
        with self._condition:
            while True:
                result = self._read_locked(offset, BUFFER_LIMIT)
                output = result["output"]
                for name, pattern in patterns.items():
                    if pattern.search(output):
                        result.update(matched=True, match=name)
                        return result
                current_end = int(result["end_offset"])
                if current_end != last_end:
                    last_end = current_end
                    last_change = time.monotonic()
                if idle_timeout is not None and output and time.monotonic() - last_change >= idle_timeout:
                    result.update(matched=False, match="idle")
                    return result
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    result.update(matched=False, match=None)
                    return result
                if self.status in {"closed", "disconnected", "error"}:
                    result.update(matched=False, match=self.status)
                    return result
                wait_for = min(remaining, 0.2 if idle_timeout is not None else remaining)
                self._condition.wait(wait_for)

    def expect(self, pattern: str, offset: int | None, timeout: float) -> dict[str, Any]:
        if not pattern or len(pattern) > 1000:
            raise ValueError("pattern 长度必须为 1 到 1000")
        if not 0 < timeout <= 300:
            raise ValueError("timeout 必须在 0 到 300 秒之间")
        compiled = re.compile(pattern, re.MULTILINE)
        start = self.end_offset if offset is None else offset
        result = self.wait_any({"pattern": compiled}, start, timeout)
        result["status"] = "matched" if result["matched"] else "timeout"
        return result

    def bootstrap_serial(self, timeout: float) -> None:
        self._require_visible_mirror()
        start = self.end_offset
        self._visible_write(b"\x03\r")
        opening = self.wait_any({"prompt": PROMPT_RE, "login": LOGIN_RE}, start, timeout)
        if opening["match"] == "login":
            start = self.end_offset
            self._visible_type_text(self.username, enter=True)
            password_prompt = self.wait_any({"password": PASSWORD_RE}, start, timeout)
            if password_prompt["match"] != "password":
                raise RuntimeError("串口未返回密码提示符")
            start = self.end_offset
            self._visible_write(self._password.encode("utf-8") + b"\r")
            ready = self.wait_any({"prompt": PROMPT_RE}, start, timeout)
            if ready["match"] != "prompt":
                raise RuntimeError("串口认证后未识别到设备提示符")
        elif opening["match"] != "prompt":
            start = self.end_offset
            self._visible_write(b"\r")
            ready = self.wait_any({"prompt": PROMPT_RE}, start, timeout)
            if ready["match"] != "prompt":
                raise RuntimeError("串口未识别到 login/password 或设备提示符")

    def on_mirror_client_connected(self, timeout: float = 20.0, wait: bool = False) -> None:
        """镜像客户端实际连入后，才启动一次串口登录 bootstrap。"""

        if not self._serial_bootstrap_pending:
            return
        with self._bootstrap_lock:
            if not self._serial_bootstrap_pending:
                return
            if self._bootstrap_thread is None or not self._bootstrap_thread.is_alive():
                self.status = "bootstrapping"
                self._bootstrap_thread = threading.Thread(
                    target=self._bootstrap_serial_after_observer,
                    args=(timeout,),
                    name=f"terminal-bootstrap-{self.session_id}",
                    daemon=True,
                )
                self._bootstrap_thread.start()
            thread = self._bootstrap_thread
        if wait and thread is not None:
            thread.join(timeout=max(timeout + 1.0, 2.0))

    def _bootstrap_serial_after_observer(self, timeout: float) -> None:
        try:
            self.bootstrap_serial(timeout)
            self._serial_bootstrap_pending = False
            self.mark_ready()
        except Exception as exc:
            self.last_error = self.redact_text(f"{type(exc).__name__}: {exc}")
            self.status = "error"

    def _mirror_client_count(self) -> int:
        mirror = self._mirror
        if mirror is None:
            return 0
        with mirror._clients_lock:
            return len(mirror._clients)

    def _require_visible_mirror(self) -> None:
        if self._mirror_client_count() < 1:
            raise RuntimeError(
                "未检测到该会话的只读镜像观察客户端；必须先打开 MobaXterm 并实际连接镜像后才能操作设备"
            )

    def _visible_write(self, data: bytes) -> None:
        self._require_visible_mirror()
        self._write(data)

    def _visible_type_text(self, text: str, enter: bool, key_delay: float = 0.03) -> None:
        with self.write_lock:
            if not self.transport.is_open():
                raise RuntimeError("设备传输已关闭")
            for character in text:
                self._require_visible_mirror()
                self.transport.write(character.encode("utf-8"))
                if key_delay > 0:
                    time.sleep(key_delay)
            if enter:
                self._require_visible_mirror()
                self.transport.write(b"\r")
            self.last_activity = time.time()

    def execute(self, command: str, timeout: float) -> dict[str, Any]:
        if not 0 < timeout <= 300:
            raise ValueError("timeout 必须在 0 到 300 秒之间")
        help_query = command.rstrip().endswith("?")
        with self.command_lock:
            self._require_visible_mirror()
            start = self.end_offset
            self._visible_type_text(command, enter=not help_query)
            patterns = {"prompt": PROMPT_RE, "password": PASSWORD_RE}
            result = self.wait_any(
                patterns,
                start,
                timeout,
                idle_timeout=0.6 if help_query else None,
            )
            if result["match"] == "password":
                if not self._enable_password:
                    result["status"] = "password_required"
                    return result
                resume = self.end_offset
                self._visible_write(self._enable_password.encode("utf-8") + b"\r")
                result = self.wait_any({"prompt": PROMPT_RE}, resume, timeout)
            if help_query:
                # 部分设备的行内帮助不会执行；待读取稳定后以 Ctrl+C 清除残留输入。
                self._visible_write(b"\x03")
                resume = self.end_offset
                self.wait_any({"prompt": PROMPT_RE}, resume, min(timeout, 5.0), idle_timeout=0.5)
                result = self.read(start, BUFFER_LIMIT)
                result.update(matched=True, match="help_complete")
            result["status"] = "completed" if result.get("match") in {"prompt", "help_complete"} else "timeout"
            return result

    def send_raw(self, action: str) -> dict[str, Any]:
        normalized = action.strip().upper()
        if normalized not in RAW_ACTIONS:
            raise ValueError("action 仅允许 ENTER/SPACE/TAB/CTRL_C/CTRL_Z")
        with self.command_lock:
            self._visible_write(RAW_ACTIONS[normalized])
        return {"status": "sent", "action": normalized, "offset": self.end_offset}

    def start_mirror(self, launch_mobaxterm: bool, mobaxterm_path: str) -> dict[str, Any]:
        from .mirror import MirrorServer

        if self._mirror is None:
            self._mirror = MirrorServer(self)
        port = self._mirror.start()
        if launch_mobaxterm:
            self._mirror.launch_mobaxterm(mobaxterm_path)
            deadline = time.monotonic() + 10.0
            while self._mirror_client_count() < 1 and time.monotonic() < deadline:
                time.sleep(0.05)
        mirror_clients = self._mirror_client_count()
        if mirror_clients:
            self.on_mirror_client_connected(wait=True)
        mirror_clients = self._mirror_client_count()
        return {
            "status": "ready" if self.status == "ready" else ("error" if self.status == "error" else "waiting_for_observer"),
            "host": "127.0.0.1",
            "port": port,
            "read_only": True,
            "mobaxterm_launched": launch_mobaxterm,
            "mirror_clients": mirror_clients,
            "operator_visible": mirror_clients > 0,
        }

    def state(self) -> dict[str, Any]:
        mirror_clients = self._mirror_client_count()
        with self._condition:
            return {
                "session_id": self.session_id,
                "transport": self.transport_kind,
                "target": self.target,
                "username": self.username,
                "status": self.status,
                "base_offset": self._buffer.base_offset,
                "end_offset": self._buffer.end_offset,
                "reader_alive": bool(self._reader and self._reader.is_alive()),
                "mirror_port": None if self._mirror is None else self._mirror.port,
                "mirror_clients": mirror_clients,
                "operator_visible": mirror_clients > 0,
                "last_activity": self.last_activity,
                "last_error": self.last_error,
            }

    def close(self) -> None:
        if self.status == "closed":
            return
        # 只在观察者仍连接时发送退出命令；不可见时直接关闭传输，禁止隐藏操作设备。
        if self.transport.is_open() and self._mirror_client_count() > 0:
            try:
                with self.command_lock:
                    self._visible_write(b"\x03")
                    exits = 3 if self.transport_kind == "serial" else 1
                    for _ in range(exits):
                        self._visible_write(b"exit\r" if self.transport_kind == "serial" else b"exit\n")
                        time.sleep(0.15)
            except Exception:
                pass
        self._stop.set()
        if self._mirror is not None:
            self._mirror.close()
        self.transport.close()
        if self._reader is not None and self._reader is not threading.current_thread():
            self._reader.join(timeout=1.0)
        self._password = ""
        self._enable_password = ""
        self.status = "closed"
        with self._condition:
            self._condition.notify_all()


class SessionManager:
    """管理凭据和会话，并作为 MCP 工具的业务入口。"""

    def __init__(self) -> None:
        self._credentials: dict[str, Credential] = {}
        self._sessions: dict[str, TerminalSession] = {}
        self._confirmations: dict[str, Confirmation] = {}
        self._lock = threading.RLock()
        self._closed = False

    def prompt_credential(self, label: str, prompt_enable_password: bool = False) -> dict[str, Any]:
        """使用当前平台可用的 tkinter 图形对话框采集凭据。"""

        try:
            import tkinter as tk
            from tkinter import simpledialog

            root = tk.Tk()
        except Exception as exc:
            raise RuntimeError("当前环境无法使用安全的图形凭据输入；请由调用方提供独立凭据通道") from exc
        root.withdraw()
        try:
            root.attributes("-topmost", True)
        except Exception:
            pass
        try:
            password = simpledialog.askstring(label, "设备密码：", show="*", parent=root)
            if password is None:
                return {"status": "cancelled"}
            enable_password = password
            if prompt_enable_password:
                entered = simpledialog.askstring(label, "特权密码：", show="*", parent=root)
                if entered is None:
                    return {"status": "cancelled"}
                enable_password = entered
        finally:
            root.destroy()
        credential_id = "cred_" + secrets.token_urlsafe(18)
        with self._lock:
            self._ensure_open()
            self._credentials[credential_id] = Credential(password, enable_password)
        return {"status": "stored_in_memory", "credential_id": credential_id}

    def connect(
        self,
        *,
        transport: str,
        username: str,
        credential_id: str,
        host: str | None,
        port: int,
        host_key_sha256: str | None,
        legacy_ssh_rsa: bool,
        serial_device: str | None,
        baudrate: int,
        xonxoff: bool,
        timeout: float,
    ) -> dict[str, Any]:
        if not username or "\n" in username or "\r" in username:
            raise ValueError("username 不能为空或包含换行")
        if not 0 < timeout <= 300:
            raise ValueError("timeout 必须在 0 到 300 秒之间")
        with self._lock:
            self._ensure_open()
            credential = self._credentials.get(credential_id)
            if credential is None:
                raise KeyError("credential_id 不存在或已失效")
            password = credential.password
            enable_password = credential.enable_password
        kind = transport.strip().lower()
        fingerprint: str | None = None
        if kind == "ssh":
            if not host:
                raise ValueError("SSH 连接需要 host")
            if not 1 <= port <= 65535:
                raise ValueError("port 必须在 1 到 65535 之间")
            try:
                device_transport, fingerprint = open_ssh(
                    host=host,
                    port=port,
                    username=username,
                    password=password,
                    expected_fingerprint=host_key_sha256,
                    legacy_ssh_rsa=legacy_ssh_rsa,
                    timeout=timeout,
                )
            except PendingHostKey as pending:
                return {
                    "status": "pending_host_key",
                    "host": host,
                    "port": port,
                    "host_key_sha256": pending.fingerprint,
                    "authenticated": False,
                    "connection_closed": True,
                }
            target = f"{host}:{port}"
        elif kind == "serial":
            if not serial_device:
                raise ValueError("串口连接需要 serial_device")
            if not 50 <= baudrate <= 4_000_000:
                raise ValueError("baudrate 超出支持范围")
            device_transport = open_serial(
                SerialOptions(device=serial_device, baudrate=baudrate, xonxoff=xonxoff)
            )
            target = serial_device
        else:
            raise ValueError("transport 仅允许 ssh 或 serial")

        session_id = "term_" + uuid.uuid4().hex
        session = TerminalSession(
            session_id,
            kind,
            device_transport,
            username,
            password,
            enable_password,
            target,
        )
        try:
            session.start()
            if kind == "serial":
                # 串口连接阶段只打开底层传输并启动 reader，不发送任何登录或控制字节。
                # bootstrap 由同一 session 的真实镜像客户端连接事件触发。
                session.status = "awaiting_observer"
            else:
                start = session.end_offset
                session.wait_any({"prompt": PROMPT_RE, "password": PASSWORD_RE}, start, timeout, idle_timeout=1.0)
                session.mark_ready()
        except Exception:
            session.close()
            raise
        with self._lock:
            self._ensure_open()
            self._sessions[session_id] = session
            removed = self._credentials.pop(credential_id, None)
            if removed is not None:
                removed.clear()
        result = session.state()
        result["status"] = session.status
        if fingerprint:
            result["host_key_sha256"] = fingerprint
        return result

    @staticmethod
    def _validate_command(command: str) -> str:
        if not command or not command.strip():
            raise ValueError("command 不能为空")
        if len(command) > 2048 or any(character in command for character in "\r\n\x00"):
            raise ValueError("每次只允许一条不含换行或 NUL 的命令，最长 2048 字符")
        return command

    def _authorize_command(
        self,
        session_id: str,
        command: str,
        confirmation_token: str | None,
    ) -> dict[str, Any] | None:
        """兼容旧参数并直接授权；MCP 不再发起任何人工命令确认。"""

        _ = session_id, command, confirmation_token
        return None

    def execute(
        self,
        session_id: str,
        command: str,
        timeout: float,
        confirmation_token: str | None,
    ) -> dict[str, Any]:
        command = self._validate_command(command)
        session = self._get_session(session_id)
        confirmation = self._authorize_command(session_id, command, confirmation_token)
        if confirmation is not None:
            return confirmation
        result = session.execute(command, timeout)
        return self.sanitize_value(result)

    def send_raw(self, session_id: str, action: str) -> dict[str, Any]:
        return self._get_session(session_id).send_raw(action)

    def read(self, session_id: str, offset: int | None, max_bytes: int) -> dict[str, Any]:
        return self._get_session(session_id).read(offset, max_bytes)

    def expect(self, session_id: str, pattern: str, offset: int | None, timeout: float) -> dict[str, Any]:
        return self._get_session(session_id).expect(pattern, offset, timeout)

    def mirror(self, session_id: str, launch_mobaxterm: bool, mobaxterm_path: str) -> dict[str, Any]:
        return self._get_session(session_id).start_mirror(launch_mobaxterm, mobaxterm_path)

    def state(self, session_id: str | None) -> dict[str, Any]:
        if session_id is not None:
            return self._get_session(session_id).state()
        with self._lock:
            sessions = list(self._sessions.values())
        return {"status": "ok", "sessions": [session.state() for session in sessions]}

    def close(self, session_id: str) -> dict[str, Any]:
        with self._lock:
            session = self._sessions.pop(session_id, None)
            tokens = [token for token, item in self._confirmations.items() if item.session_id == session_id]
            for token in tokens:
                self._confirmations.pop(token, None)
        if session is None:
            return {"status": "closed", "session_id": session_id, "already_closed": True}
        session.close()
        return {"status": "closed", "session_id": session_id, "already_closed": False}

    def _get_session(self, session_id: str) -> TerminalSession:
        with self._lock:
            session = self._sessions.get(session_id)
        if session is None:
            raise KeyError("session_id 不存在或已关闭")
        return session

    def sanitize_text(self, value: str) -> str:
        with self._lock:
            secrets_ = [secret_ for item in self._credentials.values() for secret_ in (item.password, item.enable_password)]
            sessions = list(self._sessions.values())
        for secret_ in secrets_:
            if secret_:
                value = value.replace(secret_, "***")
        for session in sessions:
            value = session.redact_text(value)
        return value

    def sanitize_value(self, value: Any) -> Any:
        if isinstance(value, str):
            return self.sanitize_text(value)
        if isinstance(value, dict):
            return {key: self.sanitize_value(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self.sanitize_value(item) for item in value]
        if isinstance(value, tuple):
            return tuple(self.sanitize_value(item) for item in value)
        return value

    def _ensure_open(self) -> None:
        if self._closed:
            raise RuntimeError("SessionManager 已关闭")

    def close_all(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            sessions = list(self._sessions.values())
            credentials = list(self._credentials.values())
            self._sessions.clear()
            self._credentials.clear()
            self._confirmations.clear()
        for session in sessions:
            session.close()
        for credential in credentials:
            credential.clear()
