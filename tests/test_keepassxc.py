import os
import stat

import pytest

from kpxc_mcp.keepassxc import (Connection, KeePassXCError, connect_associated, increment_nonce, load_association,
                                state_path, string_fields)


def test_increment_nonce_is_little_endian_with_carry():
    assert increment_nonce(b"\xff\x00") == b"\x00\x01"
    assert increment_nonce(b"\x01\x00") == b"\x02\x00"


def test_replayed_nonce_rejected(kpxc):
    kpxc.replay_nonce = True
    with pytest.raises(KeePassXCError, match="nonce mismatch"):
        Connection()


def test_replayed_nonce_rejected_on_requests(paired):
    paired.entries["https://example.com"] = [{"uuid": "u1", "name": "Ex", "login": "me", "password": "pw"}]
    conn, assoc = connect_associated()
    with conn:
        paired.replay_nonce = True
        with pytest.raises(KeePassXCError, match="nonce mismatch"):
            conn.get_logins(assoc, "https://example.com")


def test_associate_stores_pairing_privately(paired):
    assoc = load_association()
    assert assoc["id"] == "mock-0" and assoc["idKey"]
    assert stat.S_IMODE(os.stat(state_path()).st_mode) == 0o600


def test_associate_denied(kpxc):
    kpxc.approve_association = False
    with Connection() as conn, pytest.raises(KeePassXCError) as e:
        conn.associate()
    assert e.value.code == "6"


def test_unpaired_gives_hint(kpxc):
    with pytest.raises(KeePassXCError, match="kpxc-mcp associate"):
        connect_associated()


def test_stale_pairing_gives_hint(paired):
    paired.keys.clear()
    with pytest.raises(KeePassXCError, match="no longer knows"):
        connect_associated()


def test_get_logins_and_totp(paired):
    paired.entries["https://example.com"] = [{"uuid": "u1", "name": "Ex", "login": "me", "password": "pw",
                                              "stringFields": [{"KPH: agent-hosts": "a b"}]}]
    paired.totp["u1"] = "123456"
    conn, assoc = connect_associated()
    with conn:
        entries = conn.get_logins(assoc, "https://example.com/login")
        assert [e["uuid"] for e in entries] == ["u1"]
        assert string_fields(entries[0]) == {"KPH: agent-hosts": "a b"}
        assert conn.get_logins(assoc, "https://other.example/") == []
        assert conn.get_totp("u1") == "123456"
    # the pairing keys, not the session key, identify the client
    assert paired.requests[-2]["keys"] == [{"id": assoc["id"], "key": assoc["idKey"]}]


def test_lock_check_shows_no_unlock_dialog(paired):
    from kpxc_mcp.keepassxc import Connection
    with Connection() as conn:
        assert conn.is_locked() is False
    paired.locked = True
    with Connection() as conn:
        assert conn.is_locked() is True
    assert paired.requests[-1]["action"] == "get-databasehash"


def test_unanswered_dialog_times_out(paired, monkeypatch):
    from kpxc_mcp import keepassxc
    monkeypatch.setattr(keepassxc, "REPLY_TIMEOUT", 0.3)
    paired.dialog_seconds = 1
    conn, assoc = keepassxc.connect_associated()
    with conn, pytest.raises(TimeoutError):
        conn.get_logins(assoc, "https://example.com/")


def test_find_entries_tool_lists_titles_never_secrets(paired):
    from kpxc_mcp.server import find_entries
    paired.entries["https://www.example.net"] = [{"uuid": "a" * 32, "name": "Camera", "login": "me", "password": "pw-x",
                                               "url": "https://www.example.net"}]
    assert find_entries("camera")["status"] == "unavailable"  # KeePassXC's listing switch is off by default
    paired.allow_list_entries = True
    result = find_entries("CAMERA")
    assert result["entries"] == [{"title": "Camera", "url": "https://www.example.net", "uuid": "a" * 32}]
    assert "pw-x" not in str(result) and "'me'" not in str(result)
