"""Approvals the user chose to remember ("Allow always"), so the same request does not prompt again.

A remembered approval is keyed on what the prompt showed and the user can recognise:
  run_with_secrets  the program's name plus the exact set of (entry UUID, field) it receives
  request_login     the site's origin plus the entry UUID
The arguments of a remembered program can differ between runs; the entry's KPH: policy (commands, hosts) and the
forbidden-command checks still apply to every run. `kpxc-mcp forget` drops them all.
Stored next to the pairing, mode 600; the agent cannot write it (the server is the only writer).
"""

import json
import os
from pathlib import Path


def path():
    base = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local/state"))
    return base / "kpxc-mcp" / "remembered.json"


def _load():
    try:
        return json.loads(path().read_text())
    except (OSError, ValueError):
        return []


def _key(kind, **fields):
    return {"kind": kind, **fields}


def command_key(program, grants):
    """grants: iterable of (entry uuid, field)."""
    return _key("command", program=os.path.basename(program), grants=sorted([list(g) for g in grants]))


def login_key(origin, uuid):
    return _key("login", origin=origin, uuid=uuid)


def is_remembered(key):
    return key in _load()


def remember(key):
    items = [i for i in _load() if i != key]
    items.append(key)
    p = path()
    p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = p.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(items, f, indent=1)
    tmp.replace(p)


def forget():
    try:
        n = len(_load())
        path().unlink()
        return n
    except FileNotFoundError:
        return 0
