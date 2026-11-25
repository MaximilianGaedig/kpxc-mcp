"""Minimal stand-in for KeePassXC's browser server, following BrowserAction.cpp, for tests."""

import base64
import json
import os
import socket
import tempfile
import threading
import time

from nacl.public import Box, PrivateKey, PublicKey

from kpxc_mcp.keepassxc import increment_nonce


def b64(b):
    return base64.b64encode(b).decode()


class MockKeePassXC:
    def __init__(self, entries=None, approve_association=True):
        self.entries = entries or {}  # url prefix -> list of entry dicts; "path" ("Group/Title") and "url" are mock-only
        self.allow_list_entries = False  # KeePassXC's "Allow get-database-entries request", off by default
        self.totp = {}  # uuid -> code
        self.approve_association = approve_association
        self.replay_nonce = False  # answer with the request nonce instead of nonce + 1
        self.locked = False  # BrowserAction::processClientMessage: locked + no triggerUnlock -> error 1
        self.dialog_seconds = 0.0  # get-logins waits this long, as while KeePassXC's access dialog is open
        self.keys = {}  # id -> idKey
        self.requests = []
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "sock")
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(self.path)
        self.server.listen()
        threading.Thread(target=self._accept, daemon=True).start()

    def close(self):
        self.server.close()

    def _accept(self):
        while True:
            try:
                conn, _ = self.server.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        try:
            self._serve_client(conn)
        except (BrokenPipeError, ConnectionResetError):
            pass  # the client gave up while a request was held (an unanswered dialog)

    def _serve_client(self, conn):
        server_key = PrivateKey.generate()
        box = None
        associated = False
        decoder = json.JSONDecoder()
        buf = ""
        # KeePassXC pushes notices to every client; the client must skip them
        conn.sendall(json.dumps({"action": "database-unlocked"}).encode())
        while True:
            data = conn.recv(65536)
            if not data:
                return
            buf += data.decode()
            while buf.strip():
                msg, end = decoder.raw_decode(buf.lstrip())
                buf = buf.lstrip()[end:]
                action = msg["action"]
                nonce = base64.b64decode(msg["nonce"])
                reply_nonce = nonce if self.replay_nonce else increment_nonce(nonce)
                if action == "change-public-keys":
                    box = Box(server_key, PublicKey(base64.b64decode(msg["publicKey"])))
                    conn.sendall(json.dumps({"action": action, "publicKey": b64(bytes(server_key.public_key)),
                                             "nonce": b64(reply_nonce), "success": "true"}).encode())
                    continue
                if self.locked and msg.get("triggerUnlock") != "true":
                    conn.sendall(json.dumps({"action": action, "errorCode": "1", "error": "mock"}).encode())
                    continue
                inner = json.loads(box.decrypt(base64.b64decode(msg["message"]), nonce))
                self.requests.append(inner)
                result, error = self._handle(inner, associated)
                if error:
                    conn.sendall(json.dumps({"action": action, "errorCode": error, "error": "mock"}).encode())
                    continue
                if inner["action"] in ("associate", "test-associate"):
                    associated = True
                body = json.dumps({"success": "true", "nonce": b64(reply_nonce), **result}).encode()
                conn.sendall(json.dumps({"action": action, "message": b64(box.encrypt(body, reply_nonce).ciphertext),
                                         "nonce": b64(reply_nonce)}).encode())

    def _all(self):
        seen = {}
        for entries in self.entries.values():
            for e in entries:
                seen.setdefault(e["uuid"], e)
        return list(seen.values())

    @staticmethod
    def _path(e):
        return e.get("path", e["name"])

    def _handle(self, req, associated):
        action = req["action"]
        if action == "get-databasehash":
            return {"hash": "h"}, None
        if action == "associate":
            if not self.approve_association:
                return None, "6"
            new_id = f"mock-{len(self.keys)}"
            self.keys[new_id] = req["idKey"]
            return {"id": new_id, "hash": "h"}, None
        if action == "test-associate":
            if self.keys.get(req["id"]) != req["key"]:
                return None, "8"
            return {"id": req["id"], "hash": "h"}, None
        if not associated:
            return None, "8"
        if action == "get-logins":
            time.sleep(self.dialog_seconds)
            if req["url"].startswith("keepassxc://"):  # BrowserService::shouldIncludeEntry
                kind, _, key = req["url"][len("keepassxc://"):].partition("/")
                hits = [e for e in self._all() if (kind == "by-uuid" and e["uuid"] == key) or
                        (kind == "by-path" and self._path(e) == key)]
                if hits:
                    return {"count": len(hits), "entries": hits, "hash": "h", "id": "x"}, None
                return None, "15"
            for prefix, entries in self.entries.items():
                if req["url"].startswith(prefix):
                    return {"count": len(entries), "entries": entries, "hash": "h", "id": "x"}, None
            return None, "15"
        if action == "get-database-groups":
            root = {"name": "Root", "uuid": "r", "children": []}
            for e in self._all():
                node = root
                for name in self._path(e).split("/")[:-1]:
                    child = next((c for c in node["children"] if c["name"] == name), None)
                    if not child:
                        child = {"name": name, "uuid": name, "children": []}
                        node["children"].append(child)
                    node = child
            return {"groups": {"groups": [root]}}, None
        if action == "get-database-entries":
            if not self.allow_list_entries:
                return None, "19"
            return {"entries": [{"title": e["name"], "uuid": e["uuid"], "url": e.get("url", "")}
                                for e in self._all()]}, None
        if action == "get-totp":
            return {"totp": self.totp.get(req["uuid"], "")}, None
        return None, "12"
