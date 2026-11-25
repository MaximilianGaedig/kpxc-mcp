"""Phone approval over Matrix against a fake homeserver, and the race between phone and desktop."""

import json
import os
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote

import pytest

from kpxc_mcp import approve, matrix

BOT = "@kpxc:hs.test"
ME = "@me:hs.test"
ROOM = "!r:hs.test"


class FakeHomeserver:
    def __init__(self):
        self.events = []  # (event_id, sender, type, content)
        self.on_message = None  # called with the request message body; may add reactions
        self.encrypted_rooms = set()
        self.created = []
        self.tokens = {"bot-token": BOT}
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _reply(self, code, obj):
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(obj).encode())

            def _user(self):
                return fake.tokens.get(self.headers.get("Authorization", "").removeprefix("Bearer "))

            def do_GET(self):
                if not self._user():
                    return self._reply(401, {"errcode": "M_UNKNOWN_TOKEN"})
                path = unquote(self.path.split("?")[0])
                if path == "/_matrix/client/v3/account/whoami":
                    return self._reply(200, {"user_id": self._user()})
                if m := re.match(r"/_matrix/client/v1/rooms/(.+)/relations/(.+)/m.annotation$", path):
                    chunk = [{"sender": s, "type": t, "content": c} for _, s, t, c in fake.events
                             if t == "m.reaction" and c["m.relates_to"]["event_id"] == m.group(2)]
                    return self._reply(200, {"chunk": chunk})
                if m := re.match(r"/_matrix/client/v3/rooms/(.+)/state/m.room.encryption/$", path):
                    if m.group(1) in fake.encrypted_rooms:
                        return self._reply(200, {"algorithm": "m.megolm.v1.aes-sha2"})
                    return self._reply(404, {"errcode": "M_NOT_FOUND"})
                self._reply(404, {})

            def do_PUT(self):
                user = self._user()
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                m = re.match(r"/_matrix/client/v3/rooms/(.+)/send/([^/]+)/", unquote(self.path))
                event_id = f"$e{len(fake.events)}"
                fake.events.append((event_id, user, m.group(2), body))
                self._reply(200, {"event_id": event_id})
                if m.group(2) == "m.room.message" and "m.new_content" not in body and fake.on_message:
                    fake.on_message(event_id, body["body"])

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                fake.created.append(body)
                self._reply(200, {"room_id": "!new:hs.test"})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def react(self, event_id, key, sender=ME, delay=0.0):
        def go():
            time.sleep(delay)
            self.events.append((f"$r{len(self.events)}", sender, "m.reaction",
                                {"m.relates_to": {"rel_type": "m.annotation", "event_id": event_id, "key": key}}))
        threading.Thread(target=go, daemon=True).start()

    def edits(self):
        return [c["m.new_content"]["body"] for _, _, t, c in self.events if "m.new_content" in c]


@pytest.fixture
def hs(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.setattr(matrix, "POLL_INTERVAL", 0.05)
    fake = FakeHomeserver()
    d = tmp_path / "kpxc-mcp"
    d.mkdir()
    (d / "matrix.json").write_text(json.dumps({"homeserver": fake.url, "room_id": ROOM, "approver": ME}))
    (d / "matrix_token").write_text("bot-token")
    os.chmod(d / "matrix_token", 0o600)
    yield fake
    fake.server.shutdown()


@pytest.fixture
def no_desktop(monkeypatch):
    monkeypatch.setattr(approve.Desktop, "available", staticmethod(lambda: False))


def test_allow_from_phone_ignores_bot_and_strangers(hs, no_desktop):
    def on_message(event_id, body):
        assert "github.com" in body and "✅" in body
        hs.react(event_id, "✅", sender="@stranger:hs.test")
        hs.react(event_id, "✅", delay=0.3)

    hs.on_message = on_message
    t0 = time.monotonic()
    assert approve.confirm("An agent asks to fill a login into https://github.com/login") is True
    assert time.monotonic() - t0 >= 0.3  # the bot's own ✅ and the stranger's did not count
    bot_reactions = [c["m.relates_to"]["key"] for _, s, t, c in hs.events if t == "m.reaction" and s == BOT]
    assert bot_reactions == ["✅", "❌"]
    assert hs.edits()[-1].endswith("→ Allowed from the phone.")


def test_deny_from_phone(hs, no_desktop):
    hs.on_message = lambda event_id, body: hs.react(event_id, "❌")
    assert approve.confirm("run gh") is False
    assert hs.edits()[-1].endswith("→ Denied from the phone.")


def test_choose_by_number_with_or_without_variation_selector(hs, no_desktop):
    hs.on_message = lambda event_id, body: hs.react(event_id, "2⃣")  # 2⃣ without U+FE0F
    options = [("u1", "Work — me@work"), ("u2", "Private — me@home")]
    assert approve.choose("pick", options) == "u2"
    message = next(c["body"] for _, _, t, c in hs.events if t == "m.room.message")
    assert "1️⃣ Work — me@work" in message and "2️⃣ Private — me@home" in message


def test_phone_timeout_is_no_answer(hs, no_desktop, monkeypatch):
    monkeypatch.setattr(approve, "TIMEOUT", 0.3)
    assert approve.confirm("x") is False
    assert hs.edits()[-1].endswith("→ Expired.")


class FakeDesktop:
    def __init__(self, answer=None, delay=0.0, raises=False):
        self.answer, self.delay, self.raises = answer, delay, raises
        self.withdrawn = threading.Event()

    def ask(self, text, options):
        if self.withdrawn.wait(self.delay):
            raise approve.NoAnswer("withdrawn")
        if self.raises:
            raise approve.NoAnswer("no display")
        return self.answer

    def withdraw(self):
        self.withdrawn.set()


@pytest.fixture
def desktop(monkeypatch):
    holder = {}

    def install(fake):
        holder["d"] = fake
        monkeypatch.setattr(approve.Desktop, "available", staticmethod(lambda: True))
        monkeypatch.setattr(approve, "Desktop", type("D", (), {"available": staticmethod(lambda: True),
                                                               "__new__": lambda cls: fake}))
        return fake

    return install


def test_phone_answer_withdraws_desktop(hs, desktop):
    d = desktop(FakeDesktop(answer="allow", delay=5))
    hs.on_message = lambda event_id, body: hs.react(event_id, "👍", delay=0.2)
    assert approve.confirm("x") is True
    assert d.withdrawn.is_set()


def test_desktop_deny_wins_and_phone_message_is_closed(hs, desktop):
    desktop(FakeDesktop(answer=None, delay=0.3))
    assert approve.confirm("x") is False
    for _ in range(40):
        if hs.edits():
            break
        time.sleep(0.05)
    assert hs.edits()[-1].endswith("→ Answered on the desktop.")


def test_broken_desktop_leaves_the_decision_to_the_phone(hs, desktop):
    desktop(FakeDesktop(raises=True))
    hs.on_message = lambda event_id, body: hs.react(event_id, "✅", delay=0.2)
    assert approve.confirm("x") is True


def test_no_channel_denies(tmp_path, monkeypatch, no_desktop):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    assert approve.confirm("x") is False


def test_setup_creates_unencrypted_dm(hs, tmp_path):
    os.remove(tmp_path / "kpxc-mcp/matrix.json")
    bot, room = matrix.setup(hs.url, ME)
    assert (bot, room) == (BOT, "!new:hs.test")
    assert hs.created[0]["invite"] == [ME] and hs.created[0]["is_direct"] is True
    assert json.loads((tmp_path / "kpxc-mcp/matrix.json").read_text())["approver"] == ME


def test_setup_refuses_encrypted_room_and_loose_token(hs, tmp_path):
    hs.encrypted_rooms.add("!new:hs.test")
    with pytest.raises(SystemExit, match="encryption"):
        matrix.setup(hs.url, ME)
    os.chmod(tmp_path / "kpxc-mcp/matrix_token", 0o644)
    with pytest.raises(SystemExit, match="chmod 600"):
        matrix.setup(hs.url, ME)


def test_login_stores_only_the_token_privately(hs, tmp_path, monkeypatch):
    import getpass
    monkeypatch.setattr(getpass, "getpass", lambda prompt: "hunter2")
    sent = {}

    def fake_request(self, method, path, body=None):
        sent.update(method=method, path=path, body=body)
        return {"access_token": "tok-123", "user_id": BOT}

    monkeypatch.setattr(matrix.Client, "request", fake_request)
    os.remove(tmp_path / "kpxc-mcp/matrix_token")
    assert matrix.login(hs.url, "kpxc") == BOT
    token = tmp_path / "kpxc-mcp/matrix_token"
    assert token.read_text() == "tok-123" and (token.stat().st_mode & 0o777) == 0o600
    assert sent["body"]["password"] == "hunter2" and sent["path"] == "/_matrix/client/v3/login"
    assert "hunter2" not in token.read_text()


def test_ssh_client_reads_token_server_side(monkeypatch, tmp_path):
    import subprocess
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
    calls = []

    def fake_run(args, input, **kw):
        calls.append((args, input))
        return subprocess.CompletedProcess(args, 0, stdout='{"event_id": "$x"}\n200', stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    c = matrix.SshClient("https://hs.test", "matrix-host", "/srv/bot_token")
    assert c.send(ROOM, "m.room.message", {"body": "hi"}) == "$x"
    args, stdin = calls[0]
    assert args[0] == "ssh" and "matrix-host" in args and "BatchMode=yes" in args
    remote = args[-1]
    assert "sudo -n cat /srv/bot_token" in remote and "-H @<(printf" in remote
    assert "user_id=" not in remote  # a plain bot token, never appservice masquerading
    assert json.loads(stdin) == {"body": "hi"}

    monkeypatch.setattr(subprocess, "run", lambda args, input, **kw: subprocess.CompletedProcess(
        args, 0, stdout='{"errcode": "M_FORBIDDEN"}\n403', stderr=""))
    with pytest.raises(RuntimeError, match="HTTP 403"):
        c.annotations(ROOM, "$x")


def test_slow_keepassxc_dialog_is_relayed_and_closed(hs, monkeypatch):
    monkeypatch.setattr(approve, "NOTICE_AFTER", 0.05)
    with approve.desktop_dialog_notice("KeePassXC asks on the desktop"):
        time.sleep(0.3)
    sent = [c["body"] for _, s, t, c in hs.events if t == "m.room.message" and "m.new_content" not in c]
    assert sent == ["KeePassXC asks on the desktop"]
    assert hs.edits() == ["KeePassXC asks on the desktop\n\n→ KeePassXC answered on the desktop."]


def test_fast_keepassxc_reply_posts_nothing(hs, monkeypatch):
    monkeypatch.setattr(approve, "NOTICE_AFTER", 0.5)
    with approve.desktop_dialog_notice("KeePassXC asks on the desktop"):
        pass
    time.sleep(0.6)
    assert hs.events == []


def test_unanswered_dialog_notice_says_so(hs, monkeypatch):
    monkeypatch.setattr(approve, "NOTICE_AFTER", 0.05)
    with pytest.raises(TimeoutError), approve.desktop_dialog_notice("locked"):
        time.sleep(0.3)
        raise TimeoutError
    assert hs.edits() == ["locked\n\n→ Nobody answered KeePassXC's dialog; the request gave up."]
