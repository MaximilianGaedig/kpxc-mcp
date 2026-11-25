"""Client for KeePassXC's browser-integration protocol (the one KeePassXC-Browser speaks).

Protocol reference: keepassxc src/browser/BrowserAction.cpp and BrowserMessageBuilder.cpp. Plain JSON over a unix
socket; every request after change-public-keys is a NaCl box (X25519 + XSalsa20-Poly1305) and the reply uses the
request nonce incremented by one (sodium_increment, little endian).
"""

import base64
import json
import os
import re
import socket
from pathlib import Path

from nacl.public import Box, PrivateKey, PublicKey
from nacl.utils import random as random_bytes

SOCKET_NAME = "org.keepassxc.KeePassXC.BrowserServer"
REPLY_TIMEOUT = 180  # KeePassXC holds the reply while its access or unlock dialog is open


class KeePassXCError(Exception):
    def __init__(self, message, code=None):
        super().__init__(message)
        self.code = code


# errorCode values from BrowserShared.h that callers branch on
ERROR_DATABASE_NOT_OPENED = "1"
ERROR_ACTION_CANCELLED_OR_DENIED = "6"
ERROR_ASSOCIATION_FAILED = "8"
ERROR_NO_LOGINS_FOUND = "15"
ERROR_ACCESS_TO_ALL_ENTRIES_DENIED = "19"

UUID_HEX = re.compile(r"^[0-9a-fA-F]{32}$")


def b64(data):
    return base64.b64encode(data).decode()


def unb64(text):
    return base64.b64decode(text)


def increment_nonce(nonce):
    n = bytearray(nonce)
    for i in range(len(n)):
        n[i] = (n[i] + 1) & 0xFF
        if n[i]:
            break
    return bytes(n)


def socket_path():
    if override := os.environ.get("KPXC_MCP_SOCKET"):
        return override
    runtime = Path(os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}"))
    for candidate in (runtime / "app/org.keepassxc.KeePassXC" / SOCKET_NAME, runtime / SOCKET_NAME):
        if candidate.exists():
            return str(candidate)
    raise KeePassXCError("KeePassXC is not running or browser integration is off (no socket found)")


def state_path():
    base = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local/state"))
    return base / "kpxc-mcp" / "association.json"


def load_association():
    try:
        return json.loads(state_path().read_text())
    except FileNotFoundError:
        return None


def save_association(assoc):
    path = state_path()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(assoc, f)


class Connection:
    def __init__(self, path=None):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(REPLY_TIMEOUT)
        self.sock.connect(path or socket_path())
        self.buf = b""
        self.client_id = b64(random_bytes(24))
        self.key = PrivateKey.generate()
        self.box = None
        self._exchange_keys()

    def close(self):
        self.sock.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def _send(self, obj):
        self.sock.sendall(json.dumps(obj).encode())

    def _recv(self, action):
        """Next reply for `action`; KeePassXC also pushes unsolicited notices (database-locked etc.) to every client."""
        decoder = json.JSONDecoder()
        while True:
            text = self.buf.decode(errors="replace").lstrip()
            if text:
                try:
                    obj, end = decoder.raw_decode(text)
                except json.JSONDecodeError:
                    obj = None
                if obj is not None:
                    self.buf = text[end:].encode()
                    if obj.get("action") == action:
                        return obj
                    continue
            chunk = self.sock.recv(65536)
            if not chunk:
                raise KeePassXCError("KeePassXC closed the connection")
            self.buf += chunk

    def _exchange_keys(self):
        nonce = random_bytes(24)
        self._send({
            "action": "change-public-keys",
            "publicKey": b64(bytes(self.key.public_key)),
            "nonce": b64(nonce),
            "clientID": self.client_id,
        })
        reply = self._recv("change-public-keys")
        self._raise_on_error(reply)
        if unb64(reply["nonce"]) != increment_nonce(nonce):
            raise KeePassXCError("nonce mismatch in key exchange")
        self.box = Box(self.key, PublicKey(unb64(reply["publicKey"])))

    @staticmethod
    def _raise_on_error(reply):
        if "errorCode" in reply:
            raise KeePassXCError(reply.get("error", "KeePassXC error"), str(reply["errorCode"]))

    def request(self, action, trigger_unlock=True, **params):
        nonce = random_bytes(24)
        inner = json.dumps({"action": action, **params}).encode()
        self._send({
            "action": action,
            "message": b64(self.box.encrypt(inner, nonce).ciphertext),
            "nonce": b64(nonce),
            "clientID": self.client_id,
            "triggerUnlock": "true" if trigger_unlock else "false",
        })
        reply = self._recv(action)
        self._raise_on_error(reply)
        reply_nonce = unb64(reply["nonce"])
        if reply_nonce != increment_nonce(nonce):
            raise KeePassXCError("nonce mismatch in reply")
        message = json.loads(self.box.decrypt(unb64(reply["message"]), reply_nonce))
        if message.get("success") != "true":
            raise KeePassXCError(message.get("error", "request failed"), message.get("errorCode"))
        return message

    def associate(self):
        """Pair with the open database. KeePassXC shows a dialog where the user approves and names the connection."""
        id_key = b64(bytes(PrivateKey.generate().public_key))
        reply = self.request("associate", key=b64(bytes(self.key.public_key)), idKey=id_key)
        assoc = {"id": reply["id"], "idKey": id_key}
        self.test_associate(assoc)
        return assoc

    def test_associate(self, assoc):
        self.request("test-associate", id=assoc["id"], key=assoc["idKey"])

    def is_locked(self):
        """True when the database is locked; asks without triggerUnlock, so KeePassXC shows no unlock dialog."""
        try:
            self.request("get-databasehash", trigger_unlock=False)
        except KeePassXCError as e:
            if e.code == ERROR_DATABASE_NOT_OPENED:
                return True
            raise
        return False

    def get_logins(self, assoc, url):
        """Entries matching `url`. KeePassXC asks the user for access unless the entry already allows this host."""
        try:
            reply = self.request("get-logins", url=url, keys=[{"id": assoc["id"], "key": assoc["idKey"]}])
        except KeePassXCError as e:
            if e.code == ERROR_NO_LOGINS_FOUND:
                return []
            raise
        return reply.get("entries", [])

    def get_totp(self, uuid):
        return self.request("get-totp", uuid=uuid).get("totp", "")

    def group_paths(self):
        """Every group as an entry-path prefix ("" for the root, else "A/B"), as Entry::path() builds it."""
        reply = self.request("get-database-groups")
        paths = []

        def walk(group, prefix):
            paths.append(prefix)
            for child in group.get("children", []):
                walk(child, f"{prefix}/{child['name']}" if prefix else child["name"])

        for root in reply.get("groups", {}).get("groups", []):
            walk(root, "")
        return paths

    def list_entries(self):
        """Title, uuid and URL of every entry, no secrets. Needs KeePassXC's 'Allow get-database-entries request'
        (Browser Integration → Advanced); None while that is off."""
        try:
            return self.request("get-database-entries").get("entries", [])
        except KeePassXCError as e:
            if e.code == ERROR_ACCESS_TO_ALL_ENTRIES_DENIED:
                return None
            raise

    def find_entries(self, assoc, selector):
        """Entries for an agent-given selector instead of a site URL, through KeePassXC's own lookup schemes
        (keepassxc://by-uuid/ and keepassxc://by-path/ in BrowserService::shouldIncludeEntry):

          32 hex digits     the entry's UUID
          "Group/Title"     the entry's path, groups below the root separated by /
          "Title"           an exact title anywhere in the database

        Every hit comes through get-logins, so KeePassXC's access dialog guards it like a site lookup."""
        selector = selector.strip()
        if UUID_HEX.match(selector):
            return self.get_logins(assoc, f"keepassxc://by-uuid/{selector.lower()}")
        if "/" in selector:
            return self.get_logins(assoc, f"keepassxc://by-path/{selector.strip('/')}")
        listed = self.list_entries()
        if listed is not None:
            found = []
            for item in listed:
                if item.get("title") == selector:
                    found += self.get_logins(assoc, f"keepassxc://by-uuid/{item['uuid']}")
            return found
        found = []
        for prefix in self.group_paths():
            found += self.get_logins(assoc, f"keepassxc://by-path/{prefix + '/' if prefix else ''}{selector}")
        return found


def connect_associated():
    """Open a connection that has passed test-associate. Raises with a hint when pairing is missing."""
    assoc = load_association()
    if not assoc:
        raise KeePassXCError("not paired with KeePassXC yet: run `kpxc-mcp associate` and approve it in KeePassXC")
    conn = Connection()
    try:
        conn.test_associate(assoc)
    except KeePassXCError:
        conn.close()
        raise KeePassXCError("KeePassXC no longer knows this pairing (other database?): run `kpxc-mcp associate`")
    return conn, assoc


def string_fields(entry):
    """KPH: attributes of an entry as a dict (KeePassXC returns them as a list of one-key objects)."""
    fields = {}
    for item in entry.get("stringFields", []):
        fields.update(item)
    return fields
