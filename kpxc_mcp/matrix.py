"""Approve requests from the phone: a bot posts the request to a DM and the user's own reaction decides.

Config (written by `kpxc-mcp matrix-setup`): $XDG_CONFIG_HOME/kpxc-mcp/matrix.json with homeserver, room_id and
approver (the only account whose reactions count). The bot's access token sits next to it in `matrix_token` (mode
600), put there by the user. The room must stay unencrypted: the server reads reactions over the plain API.
"""

import json
import os
import threading
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from urllib.parse import quote

ALLOW = {"✅", "✔️", "✔", "👍"}
DENY = {"❌", "✖️", "👎"}
NUMBERS = [f"{i}️⃣" for i in range(1, 10)]  # 1️⃣ .. 9️⃣
POLL_INTERVAL = 1.5


def config_dir():
    return Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "kpxc-mcp"


class Client:
    def __init__(self, homeserver, token):
        self.homeserver = homeserver.rstrip("/")
        self.token = token

    def request(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(f"{self.homeserver}{path}", data=data, method=method,
                                     headers={"Authorization": f"Bearer {self.token}",
                                              "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"Matrix {method} {path.split('?')[0]}: HTTP {e.code}") from None

    def send(self, room_id, event_type, content):
        path = f"/_matrix/client/v3/rooms/{quote(room_id)}/send/{event_type}/{uuid.uuid4().hex}"
        return self.request("PUT", path, content)["event_id"]

    def annotations(self, room_id, event_id):
        path = (f"/_matrix/client/v1/rooms/{quote(room_id)}/relations/{quote(event_id)}/m.annotation"
                f"?limit=100")
        return self.request("GET", path).get("chunk", [])


class SshClient(Client):
    """Calls the homeserver from a server that keeps the bot's access token, so the token never reaches this machine.

    The token file is read there with `sudo -n` and handed to curl through a file descriptor, so it shows up in no
    process list. Use a plain bot token: an appservice as_token could act as any user in its namespace. One
    multiplexed ssh connection is reused for the polling.
    """

    def __init__(self, homeserver, ssh_host, token_file):
        super().__init__(homeserver, "")
        self.ssh_host = ssh_host
        self.token_file = token_file
        control = Path(os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")) / "kpxc-mcp"
        control.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.ssh = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "ControlMaster=auto",
                    "-o", f"ControlPath={control}/ssh-%C", "-o", "ControlPersist=120"]

    def request(self, method, path, body=None):
        import shlex
        import subprocess
        data = "--data-binary @-" if body is not None else ""
        script = (
            "set -eu; "
            f"T=$(sudo -n cat {shlex.quote(self.token_file)} | tr -d '[:space:]'); "
            f"curl -s -m 20 -X {shlex.quote(method)} -H @<(printf 'Authorization: Bearer %s\\n' \"$T\") "
            f"-H 'Content-Type: application/json' {data} -w '\\n%{{http_code}}' "
            f"{shlex.quote(self.homeserver + path)}")
        proc = subprocess.run([*self.ssh, self.ssh_host, "bash -c " + shlex.quote(script)],
                              input=json.dumps(body) if body is not None else "", capture_output=True, text=True,
                              timeout=40)
        if proc.returncode != 0:
            raise RuntimeError(f"ssh {self.ssh_host} failed ({proc.returncode})")
        payload, _, status = proc.stdout.rpartition("\n")
        if not status.startswith("2"):
            raise RuntimeError(f"Matrix {method} {path.split('?')[0]}: HTTP {status}")
        return json.loads(payload) if payload.strip() else {}


def _strip_variation(key):
    return key.replace("️", "")


class Approver:
    def __init__(self, client, room_id, approver):
        self.client = client
        self.room_id = room_id
        self.approver = approver
        self.stop = threading.Event()
        self.event_id = None

    @classmethod
    def from_config(cls):
        try:
            cfg = json.loads((config_dir() / "matrix.json").read_text())
            if "ssh_host" in cfg:
                client = SshClient(cfg["homeserver"], cfg["ssh_host"], cfg["token_file"])
            else:
                client = Client(cfg["homeserver"], (config_dir() / "matrix_token").read_text().strip())
        except FileNotFoundError:
            return None
        return cls(client, cfg["room_id"], cfg["approver"])

    def ask(self, text, options, timeout=None):
        from .approve import TIMEOUT, NoAnswer
        timeout = timeout or TIMEOUT
        if len(options) == 1:
            label = f"\n\n{options[0][1]}" if options[0][1] else ""
            body = f"{text}{label}\n\nReact ✅ to allow or ❌ to deny (expires in {timeout // 60} min)."
            keys = {_strip_variation(k): options[0][0] for k in ALLOW}
            offered = ["✅", "❌"]
        else:
            shown = options[:len(NUMBERS)]
            lines = "\n".join(f"{NUMBERS[i]} {label}" for i, (_, label) in enumerate(shown))
            body = (f"{text}\n\n{lines}\n\nReact with the number to allow that entry, or ❌ to deny "
                    f"(expires in {timeout // 60} min).")
            keys = {_strip_variation(NUMBERS[i]): key for i, (key, _) in enumerate(shown)}
            offered = [NUMBERS[i] for i in range(len(shown))] + ["❌"]
        deny = {_strip_variation(k) for k in DENY}

        self.event_id = self.client.send(self.room_id, "m.room.message", {"msgtype": "m.text", "body": body})
        # the bot reacts first, so on the phone answering is one tap on an existing reaction
        for key in offered:
            self.client.send(self.room_id, "m.reaction",
                             {"m.relates_to": {"rel_type": "m.annotation", "event_id": self.event_id, "key": key}})

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline and not self.stop.is_set():
            for ev in self.client.annotations(self.room_id, self.event_id):
                if ev.get("sender") != self.approver:
                    continue
                key = _strip_variation(ev.get("content", {}).get("m.relates_to", {}).get("key", ""))
                if key in deny:
                    self._close(body, "Denied from the phone.")
                    return None
                if key in keys:
                    self._close(body, "Allowed from the phone.")
                    return keys[key]
            self.stop.wait(POLL_INTERVAL)
        if self.stop.is_set():
            self._close(body, "Answered on the desktop.")
        else:
            self._close(body, "Expired.")
        raise NoAnswer("no reaction from the phone")

    def withdraw(self):
        self.stop.set()

    def notify(self, body):
        """Post a message nobody has to answer here (a dialog waiting on the desktop); `resolve` edits in the outcome."""
        self.body = body
        self.event_id = self.client.send(self.room_id, "m.room.message", {"msgtype": "m.text", "body": body})

    def resolve(self, outcome):
        self._close(self.body, outcome)

    def _close(self, body, outcome):
        new = f"{body}\n\n→ {outcome}"
        try:
            self.client.send(self.room_id, "m.room.message", {
                "msgtype": "m.text", "body": f"* {new}", "m.new_content": {"msgtype": "m.text", "body": new},
                "m.relates_to": {"rel_type": "m.replace", "event_id": self.event_id}})
        except RuntimeError:
            pass  # cosmetic only


def login(homeserver, user):
    """Log the bot in with a password typed into the terminal and store only the access token (mode 600)."""
    import getpass
    password = getpass.getpass(f"Password for {user}: ")
    reply = Client(homeserver, "").request("POST", "/_matrix/client/v3/login", {
        "type": "m.login.password", "identifier": {"type": "m.id.user", "user": user}, "password": password,
        "initial_device_display_name": "kpxc-mcp approvals"})
    path = config_dir() / "matrix_token"
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(reply["access_token"])
    return reply["user_id"]


def setup(homeserver, approver):
    """Create the unencrypted DM between the bot and `approver` and write matrix.json."""
    token_file = config_dir() / "matrix_token"
    if not token_file.exists():
        raise SystemExit(f"put the bot's access token in {token_file} first (chmod 600)")
    if token_file.stat().st_mode & 0o077:
        raise SystemExit(f"{token_file} must be readable only by you: chmod 600 {token_file}")
    client = Client(homeserver, token_file.read_text().strip())
    bot = client.request("GET", "/_matrix/client/v3/account/whoami")["user_id"]
    room_id = client.request("POST", "/_matrix/client/v3/createRoom", {
        "preset": "trusted_private_chat", "is_direct": True, "invite": [approver],
        "name": "kpxc-mcp approvals", "topic": "React to allow or deny agent requests for KeePassXC logins",
    })["room_id"]
    try:
        client.request("GET", f"/_matrix/client/v3/rooms/{quote(room_id)}/state/m.room.encryption/")
        raise SystemExit(f"the server enabled encryption in {room_id}; reactions would be unreadable. Turn off "
                         "encryption-by-default for private chats or create an unencrypted room by hand")
    except RuntimeError:
        pass  # 404: unencrypted, as needed
    (config_dir() / "matrix.json").write_text(json.dumps(
        {"homeserver": homeserver, "room_id": room_id, "approver": approver, "bot": bot}, indent=2) + "\n")
    return bot, room_id
