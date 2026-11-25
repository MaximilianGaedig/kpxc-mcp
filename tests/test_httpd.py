import http.client
import json
import os
import socket
import threading
import time

import pytest

from kpxc_mcp import httpd


@pytest.fixture
def server(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    srv = httpd.Server(("127.0.0.1", 0), httpd.load_token(), idle_exit=0)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv
    srv.shutdown()


def post(srv, body, token=None, host=None, origin=None):
    c = http.client.HTTPConnection("127.0.0.1", srv.port, timeout=10)
    h = {"Content-Type": "application/json", "Host": host or f"127.0.0.1:{srv.port}"}
    if token is not None:
        h["Authorization"] = f"Bearer {token}"
    if origin:
        h["Origin"] = origin
    c.request("POST", "/mcp", body=json.dumps(body), headers=h)
    r = c.getresponse()
    data = r.read()
    return r.status, (json.loads(data) if data else None)


INIT = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}}


def test_token_file_is_private(server):
    assert os.stat(httpd.token_path()).st_mode & 0o077 == 0


def test_tools_list_with_token(server):
    status, body = post(server, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, token=server.token)
    assert status == 200
    assert {t["name"] for t in body["result"]["tools"]} == {"request_login", "run_with_secrets", "find_entries"}


def test_no_or_wrong_token_is_refused(server):
    assert post(server, INIT)[0] == 401
    assert post(server, INIT, token="nope")[0] == 401


def test_browser_origin_is_refused(server):
    assert post(server, INIT, token=server.token, origin="https://evil.example")[0] == 403


def test_rebound_host_is_refused(server):
    assert post(server, INIT, token=server.token, host=f"evil.example:{server.port}")[0] == 403


def test_notification_gets_202(server):
    assert post(server, {"jsonrpc": "2.0", "method": "notifications/initialized"}, token=server.token)[0] == 202


def test_peer_cwd_is_the_calling_process(server):
    s = socket.create_connection(("127.0.0.1", server.port))
    try:
        assert httpd.peer_pid(s.getsockname()[1], server.port) is None  # our own pid is skipped
        assert httpd.peer_cwd(s.getsockname()[1], server.port) is None
    finally:
        s.close()


def test_peer_cwd_of_another_process(server, tmp_path):
    import subprocess
    import sys
    code = ("import socket,sys,time; s=socket.create_connection(('127.0.0.1',int(sys.argv[1]))); "
            "print(s.getsockname()[1],flush=True); time.sleep(5)")
    p = subprocess.Popen([sys.executable, "-c", code, str(server.port)], cwd=tmp_path, stdout=subprocess.PIPE,
                         text=True)
    try:
        port = int(p.stdout.readline())
        assert httpd.peer_pid(port, server.port) == p.pid
        assert httpd.peer_cwd(port, server.port) == str(tmp_path)
    finally:
        p.kill()


def test_exits_when_idle(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    srv = httpd.Server(("127.0.0.1", 0), httpd.load_token(), idle_exit=0.4)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    threading.Thread(target=srv.watch_idle, daemon=True).start()
    assert post(srv, INIT, token=srv.token)[0] == 200
    t.join(timeout=5)
    assert not t.is_alive()


def test_claude_config_keeps_other_keys(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    cfg = tmp_path / "claude.json"
    cfg.write_text(json.dumps({"other": 1, "mcpServers": {"x": {"type": "stdio"}, "kpxc": {"type": "stdio"}}}))
    httpd.claude_config(cfg)
    data = json.loads(cfg.read_text())
    assert data["other"] == 1 and data["mcpServers"]["x"] == {"type": "stdio"}
    assert data["mcpServers"]["kpxc"]["type"] == "http"
    assert data["mcpServers"]["kpxc"]["headers"]["Authorization"] == f"Bearer {httpd.load_token()}"
