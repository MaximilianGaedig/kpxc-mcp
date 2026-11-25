"""kpxc-mcp serve | http | claude-config | associate | status | forget | matrix-login <homeserver> <bot-user> | matrix-setup <homeserver> <approver-mxid>"""

import sys

from .keepassxc import Connection, KeePassXCError, connect_associated, save_association


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "serve"
    try:
        if cmd == "serve":
            from .server import serve
            serve()
        elif cmd == "http":
            from .httpd import serve_http
            serve_http()
        elif cmd == "claude-config":
            from .httpd import claude_config
            print(claude_config())
        elif cmd == "associate":
            print("Approve the request in KeePassXC and give the connection a name (e.g. kpxc-mcp).")
            with Connection() as conn:
                save_association(conn.associate())
            print("Paired.")
        elif cmd == "status":
            conn, _ = connect_associated()
            conn.close()
            print("Paired and KeePassXC is reachable.")
        elif cmd == "forget":
            from .remember import forget
            print(f"Forgot {forget()} remembered approvals.")
        elif cmd == "matrix-login" and len(sys.argv) == 4:
            from .matrix import login
            print(f"Logged in as {login(sys.argv[2], sys.argv[3])}; token saved.")
        elif cmd == "matrix-setup" and len(sys.argv) == 4:
            from .matrix import setup
            bot, room = setup(sys.argv[2], sys.argv[3])
            print(f"{bot} invited {sys.argv[3]} to {room}. Accept the invite on your phone.")
        else:
            print(__doc__, file=sys.stderr)
            return 2
    except KeePassXCError as e:
        print(f"kpxc-mcp: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
