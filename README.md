# kpxc-mcp

An MCP server that lets an agent (Claude Code, Claude in Chrome sessions, anything that speaks MCP) use logins and
tokens from KeePassXC without the agent seeing them. It is the KeePassXC counterpart of 1Password for Claude.

- **`request_login(tab, mode)`**: looks up the tab's site in KeePassXC, asks you which entry to use, and fills the
  username and password (or a one-time code with `mode: "totp"`) straight into the page over the DevTools
  protocol. The agent gets back `filled`, `denied`, `no_login`, `no_field` or `origin_changed`, never a value. It
  does not submit; the agent clicks the page's own button. One approval covers a login and the one-time code that
  follows it: same tab, same site, same entry, within 3 minutes, once. For a login stored under another URL, the
  agent passes `entry` (title, `Group/Title` or UUID); the prompt then says the agent picked the entry.
- **`run_with_secrets(argv, env)`**: runs a command without a shell, with entries injected as environment variables
  (`GH_TOKEN` for `gh`, or `curl --variable %TOK --expand-header 'Authorization: Bearer {{TOK}}'`). Each entry must
  opt in, the command and hosts are checked against the entry, you approve each run, and the secret (plain, URL,
  hex and base64 forms) is removed from the output. Each variable names its entry by `url` (site match), `entry`
  (title, `Group/Title` path or UUID) or both, and may pick a `field` the entry allows.
- **`find_entries(query)`**: titles, URLs and UUIDs of entries whose title or URL contains `query`, no secrets. Only
  while you tick "Allow get-database-entries request" (Browser Integration → Advanced); without it, an exact title
  still works for `entry`, found by walking the group tree with KeePassXC's `keepassxc://by-path/` lookup.

  KeePassXC up to at least 2.8.0-beta1 segfaults when a `by-uuid`/`by-path` lookup hits an entry without a URL
  (keepassxreboot/keepassxc#13865, fixed by PR #13887). Use `entry` only with a KeePassXC that carries that fix.

## Setup

1. KeePassXC: browser integration on (Settings → Browser Integration), and keep "Return advanced string fields
   which start with 'KPH: '" ticked (the default) so command policies can be read.
2. Brave or Chromium with `--remote-debugging-port=9222` on loopback (override with `KPXC_MCP_CDP`).
3. Build and pair once (KeePassXC asks you to approve and name the connection):

   ```bash
   nix build -o ~/.cache/kpxc-mcp .
   ~/.cache/kpxc-mcp/bin/kpxc-mcp associate
   ```

4. Register it with Claude Code. Either as one shared HTTP server that runs only while it is used (recommended),
   or as a stdio server, which is one process per agent session for the whole session.

   **HTTP, started on demand.** systemd listens on `127.0.0.1:47321` and starts `kpxc-mcp http` on the first
   connection; the server exits after `KPXC_MCP_IDLE_EXIT` seconds (default 120) without a request, so nothing
   runs between uses. User units:

   ```ini
   # ~/.config/systemd/user/kpxc-mcp.socket
   [Socket]
   ListenStream=127.0.0.1:47321
   [Install]
   WantedBy=sockets.target

   # ~/.config/systemd/user/kpxc-mcp.service
   [Service]
   ExecStart=%h/.cache/kpxc-mcp/bin/kpxc-mcp http
   ```

   ```bash
   systemctl --user enable --now kpxc-mcp.socket
   ~/.cache/kpxc-mcp/bin/kpxc-mcp claude-config   # writes the http entry and token into ~/.claude.json
   ```

   Loopback HTTP is reachable by every local process and by web pages, so each request needs the bearer token from
   `~/.config/kpxc-mcp/http_token` (mode 600, created on first start), the `Host` header must be the loopback
   address, and requests that carry an `Origin` header (browsers) are refused. `run_with_secrets` runs in the
   calling agent's working directory unless it passes `cwd`.

   **stdio:**

   ```bash
   claude mcp add --scope user kpxc -- ~/.cache/kpxc-mcp/bin/kpxc-mcp serve
   ```

## Approving from the phone (Matrix)

Every prompt also goes to a Matrix DM from a bot account. The bot pre-reacts ✅/❌ (or 1️⃣…9️⃣ when several entries
match), so answering on the phone is one tap. Only reactions from the configured approver count, and the first
answer on either the phone or the desktop wins. The other prompt is withdrawn and the message is edited with the
outcome. When nobody answers within two minutes, the request is denied.

One-time setup:

1. Create a bot account on your homeserver, then run `kpxc-mcp matrix-login https://<homeserver> <bot>`. It
   asks for the password and stores only the access token in `~/.config/kpxc-mcp/matrix_token` (mode 600).
2. Run `kpxc-mcp matrix-setup https://<homeserver> @<you>:<server>`. This creates an unencrypted DM with you (the
   server has to read your reactions) and writes `~/.config/kpxc-mcp/matrix.json`.
3. Accept the invite.

**Or keep the token on a server:** if a server you reach by ssh already holds a bot's access token, kpxc-mcp can
make the Matrix calls there. The token file is read with `sudo -n` and never leaves the server. Use a plain bot
token, not an appservice `as_token`: an `as_token` can act as every user in its namespace, including you. Write
`~/.config/kpxc-mcp/matrix.json` by hand:

```json
{"homeserver": "https://matrix.example.org", "ssh_host": "my-server",
 "token_file": "/srv/matrix-bot/access_token",
 "bot": "@approvals-bot:example.org", "room_id": "!<existing unencrypted DM>", "approver": "@you:example.org"}
```

The ssh connection is multiplexed (socket in `$XDG_RUNTIME_DIR/kpxc-mcp`), so polling costs about 0.5 s per call.
When ssh fails (for example, a locked agent), the phone channel counts as no answer and the desktop prompt decides.

The request text (site, entry title and username, or the full command) is stored on your homeserver in plain text.
Secrets never are.

KeePassXC's own dialogs (database unlock, first access to an entry, passkeys) only appear on the desktop. When
KeePassXC keeps a login request waiting on one of them for more than 2 seconds, the bot posts a notice saying which
one (locked database or entry access for the site) and edits it with the outcome; the request gives up after
3 minutes with `dialog_unanswered`. For a
request to be answerable from the phone alone, the entry must already allow that site ("Remember" in KeePassXC's
access dialog). The phone or desktop prompt is then the only approval.

## Passkeys

Passkeys go through KeePassXC-Browser, not this server. Turn on "Enable passkeys" in the extension's options. The
agent clicks the site's passkey button, and KeePassXC shows its passkey confirmation; KeePassXC signs the request
itself, so nothing reaches the agent. This works only in your normal profile where the extension runs, and the
confirmation is desktop-only.

## Letting an entry be used by commands

Add attributes to the entry in KeePassXC (Advanced → Additional attributes). Only you can set them; the agent
cannot. An entry the agent names explicitly (`entry` without `url`) may have no attributes at all: then any command
except shells and interpreters, any host and any field are allowed, and your approval of the prompt (which shows the
whole command and says the entry has no policy) is the only limit. Entries found by site still need the opt-in.

| Attribute | Meaning |
| --- | --- |
| `KPH: agent-commands` | Allowed commands, whitespace separated: names on the system PATH or `/nix/store` paths. Shells, interpreters, `env`, `cat` and similar are refused. |
| `KPH: agent-hosts` | Hosts URLs in the arguments may point at; `*.example.com` allowed. Defaults to the host of the `url` the agent looked the entry up by; required for entries looked up by `entry` alone. |
| `KPH: agent-field` | Fields the agent may inject, whitespace separated: `password` (default), `username`, `totp`. The first is used unless the agent asks for another listed one (e.g. `password username` for an API that needs both). |

Commands resolve through `/run/current-system/sw/bin` and the per-user profile only, and must land in `/nix/store`,
so a script dropped in `~/bin` cannot stand in for `gh`.

## Approvals and what they protect

Every prompt offers **Allow once** or **Allow always**. "Always" is remembered in
`~/.local/state/kpxc-mcp/remembered.json` (mode 600): for `run_with_secrets` the program name plus the exact
entries and fields it receives (arguments may differ; the entry's KPH: policy still applies), for `request_login`
the site's origin plus the entry. `kpxc-mcp forget` drops them all.

Every `request_login` and `run_with_secrets` opens a desktop prompt (zenity) and, when configured, a Matrix
message, each showing the site or full command and the entry. KeePassXC's own access dialog comes first for entries that have not been allowed for that host.

Limits, stated plainly:

- The agent runs as your user. A process that reads `~/.local/state/kpxc-mcp/association.json` can talk to
  KeePassXC directly and skip the zenity prompt. KeePassXC's access dialog is then the only gate, so do not tick
  "Remember" in it for entries you want asked about every time. `AGENTS.md` forbids agents to read that file.
- Redaction covers common encodings, not every transformation a program could apply. Only allow commands whose
  output does not echo request bodies, and keep `agent-hosts` narrow.
- The fill runs in the tab's top frame. Login forms inside cross-origin iframes are not filled.

## Tests

```bash
nix develop -c python -m pytest -q tests
```

The KeePassXC side runs against a mock that follows `src/browser/BrowserAction.cpp`. The browser tests start a
headless Brave/Chromium with a throwaway profile and skip without one.
