"""MCP server over stdio (newline-delimited JSON-RPC 2.0)."""

import json
import sys
import traceback

from . import __version__, context
from .browser import request_login
from .keepassxc import KeePassXCError, connect_associated
from .runner import PolicyError, run_with_secrets

TOOLS = [
    {
        "name": "request_login",
        "description": (
            "Fill the login form of a browser tab from the user's KeePassXC. The user approves each request in "
            "KeePassXC and a desktop prompt; the credentials go straight into the page and are never returned. "
            "Call it when the tab shows a sign-in form, then click the page's own sign-in button. For "
            "username-first sign-ins call it again on the password step. mode 'totp' fills a one-time code field."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "tab": {"type": "string", "description": "DevTools target id, or a unique part of the tab's URL"},
                "mode": {"type": "string", "enum": ["login", "totp"], "default": "login"},
                "entry": {"type": "string", "description": (
                    "pick the entry instead of matching the tab's site: exact title, 'Group/Title' path or UUID "
                    "(see find_entries); for logins stored under another URL")},
            },
            "required": ["tab"],
        },
    },
    {
        "name": "run_with_secrets",
        "description": (
            "Run a command (no shell) with KeePassXC secrets in environment variables, e.g. GH_TOKEN for gh or a "
            "curl --variable/--expand-header token. Only commands and hosts listed in the entry's 'KPH: agent-commands' "
            "and 'KPH: agent-hosts' attributes are allowed, the user approves each run, and secret values are "
            "removed from the output."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "argv": {"type": "array", "items": {"type": "string"}, "minItems": 1},
                "env": {
                    "type": "object",
                    "description": "VARIABLE -> KeePassXC entry lookup",
                    "additionalProperties": {
                        "type": "object",
                        "properties": {
                            "url": {"type": "string", "description": "URL the entry is stored under"},
                            "entry": {"type": "string", "description": (
                                "exact title, 'Group/Title' path or UUID; alone it replaces url, with url it "
                                "picks among several matches")},
                            "field": {"type": "string", "enum": ["password", "username", "totp"], "description": (
                                "which field to inject; must be listed in the entry's 'KPH: agent-field' "
                                "(default: the first listed, else password)")},
                        },
                    },
                },
                "cwd": {"type": "string"},
                "timeout": {"type": "number", "default": 120},
            },
            "required": ["argv", "env"],
        },
    },
    {
        "name": "find_entries",
        "description": (
            "Find KeePassXC entries by part of their title or URL. Returns title, URL and UUID only, never a "
            "secret; pass the UUID as `entry` to the other tools. Works only while the user allows "
            "get-database-entries in KeePassXC (Browser Integration → Advanced)."),
        "inputSchema": {
            "type": "object",
            "properties": {"query": {"type": "string", "minLength": 2}},
            "required": ["query"],
        },
    },
]


def find_entries(query):
    query = query.strip().lower()
    if len(query) < 2:
        raise LookupError("query needs at least 2 characters")
    conn, _ = connect_associated()
    with conn:
        listed = conn.list_entries()
    if listed is None:
        return {"status": "unavailable", "reason": (
            "KeePassXC refuses to list entries: the user can tick 'Allow get-database-entries request' in Browser "
            "Integration → Advanced, or tell you the entry's title or Group/Title path")}
    hits = [{"title": e.get("title", ""), "url": e.get("url", ""), "uuid": e.get("uuid", "")} for e in listed
            if query in e.get("title", "").lower() or query in e.get("url", "").lower()]
    return {"status": "ok", "entries": hits[:50], "truncated": len(hits) > 50}


def call_tool(name, args):
    if name == "request_login":
        return request_login(args["tab"], args.get("mode", "login"), args.get("entry") or None)
    if name == "find_entries":
        return find_entries(args["query"])
    if name == "run_with_secrets":
        return run_with_secrets(args["argv"], args["env"], args.get("cwd") or context.default_cwd(),
                                float(args.get("timeout", 120)))
    raise KeyError(name)


def handle(msg):
    method = msg.get("method")
    if method == "initialize":
        return {
            "protocolVersion": msg.get("params", {}).get("protocolVersion", "2025-06-18"),
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "kpxc-mcp", "version": __version__},
        }
    if method == "ping":
        return {}
    if method == "tools/list":
        return {"tools": TOOLS}
    if method == "tools/call":
        params = msg.get("params", {})
        try:
            result, is_error = call_tool(params.get("name"), params.get("arguments") or {}), False
        except (KeePassXCError, PolicyError, LookupError, OSError, RuntimeError) as e:
            result, is_error = {"status": "error", "reason": str(e)}, True
        return {"content": [{"type": "text", "text": json.dumps(result)}], "isError": is_error}
    raise NotImplementedError(method)


def reply(msg):
    """The JSON-RPC reply to one message, or None for a notification."""
    if "id" not in msg:
        return None
    try:
        return {"jsonrpc": "2.0", "id": msg["id"], "result": handle(msg)}
    except NotImplementedError as e:
        return {"jsonrpc": "2.0", "id": msg["id"], "error": {"code": -32601, "message": f"unknown method {e}"}}
    except Exception as e:  # never let a bad call kill the server; the traceback goes to stderr only
        traceback.print_exc(file=sys.stderr)
        return {"jsonrpc": "2.0", "id": msg["id"], "error": {"code": -32603, "message": type(e).__name__}}


def serve():
    for line in sys.stdin:
        if not line.strip():
            continue
        out = reply(json.loads(line))
        if out is None:
            continue
        sys.stdout.write(json.dumps(out) + "\n")
        sys.stdout.flush()
