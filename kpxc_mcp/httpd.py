"""MCP over HTTP on loopback (the Streamable HTTP transport, JSON replies only).

One process serves every agent, and only while it is used: systemd starts it on the first connection
(socket activation) and it exits after KPXC_MCP_IDLE_EXIT seconds without a request, so between uses no
process runs at all. The stdio server costs one Python process (~19 MB) per agent session for the whole session.

Loopback HTTP is reachable by every local process and by web pages, which stdio was not. So a request needs
the bearer token from ~/.config/kpxc-mcp/http_token (0600, created on first start), the Host header must be
the loopback address (DNS rebinding), and any request carrying an Origin header (a browser) is refused.
"""

import hmac
import json
import os
import secrets
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import context
from .server import reply

DEFAULT_PORT = 47321
MAX_BODY = 1 << 20


def token_path():
    return Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "kpxc-mcp" / "http_token"


def load_token():
    """The bearer token, created on first use. Never printed: `kpxc-mcp claude-config` writes it where needed."""
    path = token_path()
    try:
        token = path.read_text().strip()
        if token:
            return token
    except FileNotFoundError:
        pass
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    token = secrets.token_urlsafe(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(token + "\n")
    return token


def _hex_port(addr):
    return int(addr.rsplit(":", 1)[1], 16)


def peer_pid(client_port, server_port):
    """PID of the local process (same user) holding the client end of a loopback TCP connection, or None."""
    inode = None
    for table in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            lines = open(table).read().splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            f = line.split()
            if _hex_port(f[1]) == client_port and _hex_port(f[2]) == server_port and int(f[7]) == os.getuid():
                inode = f[9]
                break
        if inode:
            break
    if not inode:
        return None
    target = f"socket:[{inode}]"
    for pid in os.listdir("/proc"):
        if not pid.isdigit() or int(pid) == os.getpid():
            continue
        try:
            for fd in os.listdir(f"/proc/{pid}/fd"):
                if os.readlink(f"/proc/{pid}/fd/{fd}") == target:
                    return int(pid)
        except OSError:
            continue
    return None


def peer_cwd(client_port, server_port):
    pid = peer_pid(client_port, server_port)
    if pid is None:
        return None
    try:
        return os.readlink(f"/proc/{pid}/cwd")
    except OSError:
        return None


class Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, sock_or_addr, token, idle_exit):
        self.token = token
        self.idle_exit = idle_exit
        self.busy = 0
        self.last = time.monotonic()
        self.lock = threading.Lock()
        if isinstance(sock_or_addr, socket.socket):
            super().__init__(sock_or_addr.getsockname()[:2], Handler, bind_and_activate=False)
            self.socket.close()
            self.socket = sock_or_addr
        else:
            super().__init__(sock_or_addr, Handler)
        self.port = self.socket.getsockname()[1]

    def handle_error(self, request, client_address):
        # a client that hangs up mid-request (or a port probe) is not worth a traceback
        if isinstance(sys.exc_info()[1], (ConnectionError, TimeoutError)):
            return
        super().handle_error(request, client_address)

    def begin(self):
        with self.lock:
            self.busy += 1

    def end(self):
        with self.lock:
            self.busy -= 1
            self.last = time.monotonic()

    def idle_for(self):
        with self.lock:
            return 0 if self.busy else time.monotonic() - self.last

    def watch_idle(self):
        if self.idle_exit <= 0:
            return
        while True:
            time.sleep(min(5, self.idle_exit / 4))
            if self.idle_for() >= self.idle_exit:
                self.shutdown()
                return


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "kpxc-mcp"

    def log_message(self, fmt, *args):
        pass

    def _send(self, code, body=None):
        data = json.dumps(body).encode() if body is not None else b""
        self.send_response(code)
        if body is not None:
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _allowed(self):
        if self.headers.get("Origin") is not None:
            return 403
        host = self.headers.get("Host", "")
        if host not in (f"127.0.0.1:{self.server.port}", f"localhost:{self.server.port}"):
            return 403
        auth = self.headers.get("Authorization", "")
        if not hmac.compare_digest(auth.encode(), f"Bearer {self.server.token}".encode()):
            return 401
        return None

    def do_GET(self):
        self._send(self._allowed() or 405)

    def do_DELETE(self):
        self._send(self._allowed() or 405)

    def do_POST(self):
        self.server.begin()
        try:
            if (code := self._allowed()) is not None:
                return self._send(code)
            length = int(self.headers.get("Content-Length") or 0)
            if length <= 0 or length > MAX_BODY:
                return self._send(400)
            try:
                msg = json.loads(self.rfile.read(length))
            except ValueError:
                return self._send(400, {"jsonrpc": "2.0", "id": None,
                                        "error": {"code": -32700, "message": "parse error"}})
            context.set_caller(peer_cwd(self.client_address[1], self.server.port))
            if isinstance(msg, list):
                out = [r for r in map(reply, msg) if r is not None]
            else:
                out = reply(msg)
            if not out:
                return self._send(202)
            self._send(200, out)
        finally:
            self.server.end()


def listen_socket():
    """The socket systemd passed (LISTEN_FDS), or None."""
    if os.environ.get("LISTEN_PID") == str(os.getpid()) and os.environ.get("LISTEN_FDS") == "1":
        return socket.socket(fileno=3)
    return None


def serve_http():
    token = load_token()
    idle = float(os.environ.get("KPXC_MCP_IDLE_EXIT", "120"))
    sock = listen_socket()
    port = int(os.environ.get("KPXC_MCP_PORT", DEFAULT_PORT))
    server = Server(sock if sock is not None else ("127.0.0.1", port), token, idle)
    threading.Thread(target=server.watch_idle, daemon=True).start()
    print(f"kpxc-mcp: serving on 127.0.0.1:{server.port}, exits after {idle:g}s idle", file=sys.stderr)
    server.serve_forever()


def claude_config(path=None, name="kpxc"):
    """Point Claude Code's user-scope MCP entry at the HTTP server, token included, without printing the token."""
    path = Path(path or Path.home() / ".claude.json")
    data = json.loads(path.read_text())
    port = int(os.environ.get("KPXC_MCP_PORT", DEFAULT_PORT))
    data.setdefault("mcpServers", {})[name] = {
        "type": "http",
        "url": f"http://127.0.0.1:{port}/mcp",
        "headers": {"Authorization": f"Bearer {load_token()}"},
    }
    tmp = path.with_name(path.name + ".kpxc-tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)
    return f"{path}: mcpServers.{name} -> http://127.0.0.1:{port}/mcp"
