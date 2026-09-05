"""面向 MobaXterm 的本机只读 TCP 镜像。"""

from __future__ import annotations

import queue
import socket
import subprocess
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .core import TerminalSession


@dataclass(eq=False)
class _Client:
    """慢客户端拥有独立队列，绝不阻塞设备 reader。"""

    sock: socket.socket
    pending: queue.Queue[bytes] = field(default_factory=lambda: queue.Queue(maxsize=256))
    closed: threading.Event = field(default_factory=threading.Event)

    def close(self) -> None:
        if self.closed.is_set():
            return
        self.closed.set()
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass


class MirrorServer:
    """仅监听 127.0.0.1 的脱敏终端广播服务。"""

    def __init__(self, session: "TerminalSession") -> None:
        self._session = session
        self._listener: socket.socket | None = None
        self._clients: set[_Client] = set()
        self._clients_lock = threading.Lock()
        self._ingress: queue.Queue[bytes] = queue.Queue(maxsize=1024)
        self._overflow = threading.Event()
        self._closed = threading.Event()
        self._accept_thread: threading.Thread | None = None
        self._broadcast_thread: threading.Thread | None = None
        self._moba_process: subprocess.Popen[bytes] | None = None
        self.port: int | None = None

    def start(self) -> int:
        if self.port is not None:
            return self.port
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(8)
        listener.settimeout(0.5)
        self._listener = listener
        self.port = int(listener.getsockname()[1])
        self._session.add_observer(self.broadcast)
        self._accept_thread = threading.Thread(
            target=self._accept_loop,
            name=f"terminal-mirror-accept-{self.port}",
            daemon=True,
        )
        self._broadcast_thread = threading.Thread(
            target=self._broadcast_loop,
            name=f"terminal-mirror-broadcast-{self.port}",
            daemon=True,
        )
        self._accept_thread.start()
        self._broadcast_thread.start()
        return self.port

    def _accept_loop(self) -> None:
        assert self._listener is not None
        while not self._closed.is_set():
            try:
                sock, _address = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            sock.settimeout(1.0)
            client = _Client(sock)
            # 与 broadcast 使用同一把锁，保证“当前缓冲”先于后续流进入队列。
            with self._clients_lock:
                snapshot = self._session.snapshot_bytes()
                try:
                    if snapshot:
                        client.pending.put_nowait(snapshot)
                    self._clients.add(client)
                except queue.Full:
                    client.close()
                    continue
            threading.Thread(target=self._writer, args=(client,), daemon=True).start()
            threading.Thread(target=self._discard_input, args=(client,), daemon=True).start()
            self._session.on_mirror_client_connected()

    def _writer(self, client: _Client) -> None:
        try:
            while not self._closed.is_set() and not client.closed.is_set():
                try:
                    chunk = client.pending.get(timeout=0.5)
                except queue.Empty:
                    continue
                client.sock.sendall(chunk)
        except OSError:
            pass
        finally:
            self._drop(client)

    def _discard_input(self, client: _Client) -> None:
        """主动读取并丢弃镜像端输入，镜像永远不能控制设备。"""

        try:
            while not self._closed.is_set() and not client.closed.is_set():
                try:
                    data = client.sock.recv(4096)
                except socket.timeout:
                    continue
                if not data:
                    break
        except OSError:
            pass
        finally:
            self._drop(client)

    def _drop(self, client: _Client) -> None:
        client.close()
        with self._clients_lock:
            self._clients.discard(client)

    def broadcast(self, chunk: bytes) -> None:
        """reader 只做无等待入队；拥塞时令观察者重连并从当前快照恢复。"""

        try:
            self._ingress.put_nowait(chunk)
        except queue.Full:
            self._overflow.set()

    def _broadcast_loop(self) -> None:
        """在独立线程分发，客户端锁和队列压力永不传回设备 reader。"""

        while not self._closed.is_set():
            try:
                chunk = self._ingress.get(timeout=0.5)
            except queue.Empty:
                continue
            stale: list[_Client] = []
            with self._clients_lock:
                if self._overflow.is_set():
                    stale.extend(self._clients)
                    self._clients.clear()
                    self._overflow.clear()
                else:
                    for client in self._clients:
                        try:
                            client.pending.put_nowait(chunk)
                        except queue.Full:
                            stale.append(client)
                    for client in stale:
                        self._clients.discard(client)
            for client in stale:
                client.close()

    def launch_mobaxterm(self, executable: str) -> None:
        if self.port is None:
            raise RuntimeError("镜像尚未启动")
        path = Path(executable)
        if not path.is_file():
            raise FileNotFoundError(f"未找到 MobaXterm：{path}")
        target = f"telnet 127.0.0.1 {self.port}"
        self._moba_process = subprocess.Popen(
            [str(path), "-newtab", target],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
        )

    def close(self) -> None:
        if self._closed.is_set():
            return
        self._closed.set()
        self._session.remove_observer(self.broadcast)
        if self._listener is not None:
            try:
                self._listener.close()
            except OSError:
                pass
        with self._clients_lock:
            clients = list(self._clients)
            self._clients.clear()
        for client in clients:
            client.close()
        if self._accept_thread is not None:
            self._accept_thread.join(timeout=1.0)
        if self._broadcast_thread is not None:
            self._broadcast_thread.join(timeout=1.0)
