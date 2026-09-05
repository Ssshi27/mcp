"""SSH 与串口传输层；凭据只在内存中参与认证。"""

from __future__ import annotations

import base64
import hashlib
import socket
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

import paramiko
import serial


class PendingHostKey(RuntimeError):
    """SSH 主机密钥尚未被调用方确认。"""

    def __init__(self, fingerprint: str) -> None:
        super().__init__("SSH 主机密钥待确认")
        self.fingerprint = fingerprint


class TransportBase(ABC):
    """供唯一 reader 线程使用的最小传输接口。"""

    @abstractmethod
    def read(self, size: int = 65535) -> bytes:
        """读取一段数据；超时返回空字节。"""

    @abstractmethod
    def write(self, data: bytes) -> None:
        """写入设备。"""

    @abstractmethod
    def is_open(self) -> bool:
        """传输是否仍可用。"""

    @abstractmethod
    def close(self) -> None:
        """幂等关闭传输。"""


class SSHTransport(TransportBase):
    """已完成主机密钥验证和认证的 SSH Shell。"""

    def __init__(
        self,
        sock: socket.socket,
        transport: paramiko.Transport,
        channel: paramiko.Channel,
    ) -> None:
        self._sock = sock
        self._transport = transport
        self._channel = channel
        self._closed = threading.Event()
        self._channel.settimeout(0.2)

    def read(self, size: int = 65535) -> bytes:
        if self._closed.is_set():
            return b""
        try:
            return self._channel.recv(size)
        except socket.timeout:
            return b""
        except (EOFError, OSError):
            self.close()
            return b""

    def write(self, data: bytes) -> None:
        if not self.is_open():
            raise RuntimeError("SSH 会话已关闭")
        self._channel.sendall(data)

    def is_open(self) -> bool:
        return (
            not self._closed.is_set()
            and not self._channel.closed
            and self._transport.is_active()
        )

    def close(self) -> None:
        if self._closed.is_set():
            return
        self._closed.set()
        try:
            self._channel.close()
        except Exception:
            pass
        try:
            self._transport.close()
        except Exception:
            pass
        try:
            self._sock.close()
        except OSError:
            pass


@dataclass(frozen=True)
class SerialOptions:
    """串口默认值固定为 115200 8N1、XON/XOFF。"""

    device: str
    baudrate: int = 115200
    xonxoff: bool = True
    read_timeout: float = 0.2
    write_timeout: float = 2.0


class SerialTransport(TransportBase):
    """pyserial 的线程安全薄封装。"""

    def __init__(self, options: SerialOptions) -> None:
        self._port = serial.Serial(
            port=options.device,
            baudrate=options.baudrate,
            bytesize=serial.EIGHTBITS,
            parity=serial.PARITY_NONE,
            stopbits=serial.STOPBITS_ONE,
            timeout=options.read_timeout,
            write_timeout=options.write_timeout,
            xonxoff=options.xonxoff,
            rtscts=False,
            dsrdtr=False,
        )
        self._closed = threading.Event()

    def read(self, size: int = 65535) -> bytes:
        if self._closed.is_set():
            return b""
        try:
            available = self._port.in_waiting
            return self._port.read(min(size, available or 1))
        except (OSError, serial.SerialException):
            self.close()
            return b""

    def write(self, data: bytes) -> None:
        if not self.is_open():
            raise RuntimeError("串口会话已关闭")
        self._port.write(data)
        self._port.flush()

    def is_open(self) -> bool:
        return not self._closed.is_set() and self._port.is_open

    def close(self) -> None:
        if self._closed.is_set():
            return
        self._closed.set()
        try:
            self._port.close()
        except (OSError, serial.SerialException):
            pass


def _fingerprint(key: paramiko.PKey) -> str:
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def open_ssh(
    *,
    host: str,
    port: int,
    username: str,
    password: str,
    expected_fingerprint: str | None,
    legacy_ssh_rsa: bool,
    timeout: float,
) -> tuple[SSHTransport, str]:
    """认证前核验 SHA256 指纹；未知指纹会关闭连接并返回待确认状态。"""

    sock: socket.socket | None = None
    transport: paramiko.Transport | None = None
    channel: paramiko.Channel | None = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        transport = paramiko.Transport(sock)
        if legacy_ssh_rsa:
            # 只修改当前 Transport 实例，不触碰 Paramiko 或系统全局算法策略。
            security = transport.get_security_options()
            key_types = list(security.key_types)
            if "ssh-rsa" not in key_types:
                key_types.append("ssh-rsa")
                security.key_types = tuple(key_types)
        transport.start_client(timeout=timeout)
        actual_fingerprint = _fingerprint(transport.get_remote_server_key())
        if not expected_fingerprint:
            raise PendingHostKey(actual_fingerprint)
        if not secrets_compare(actual_fingerprint, expected_fingerprint):
            raise RuntimeError(
                f"SSH 主机密钥指纹不匹配；期望 {expected_fingerprint}，实际 {actual_fingerprint}"
            )
        # 只有固定指纹验证成功后才允许发送认证信息。
        try:
            transport.auth_password(username=username, password=password, fallback=False)
        except paramiko.BadAuthenticationType as exc:
            if "keyboard-interactive" not in exc.allowed_types:
                raise

            def keyboard_handler(
                _title: str,
                _instructions: str,
                prompts: list[tuple[str, bool]],
            ) -> list[str]:
                return [password if not echo else "" for _prompt, echo in prompts]

            transport.auth_interactive(username, keyboard_handler)
        transport.set_keepalive(30)
        channel = transport.open_session(timeout=timeout)
        channel.get_pty(term="xterm", width=200, height=1000)
        channel.invoke_shell()
        return SSHTransport(sock, transport, channel), actual_fingerprint
    except Exception:
        if channel is not None:
            channel.close()
        if transport is not None:
            transport.close()
        if sock is not None:
            sock.close()
        raise


def secrets_compare(actual: str, expected: str) -> bool:
    """以常量时间比较规范化后的 SHA256 指纹。"""

    import hmac

    return hmac.compare_digest(actual.strip(), expected.strip())


def open_serial(options: SerialOptions) -> SerialTransport:
    """打开串口；调用方负责登录提示符交互。"""

    return SerialTransport(options)
