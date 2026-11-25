# Rules for agents

- Never read, print, copy or edit `~/.local/state/kpxc-mcp/association.json`, and never talk to the KeePassXC socket
  except through this server's tools. The pairing in that file reaches every entry the user allows.
- Never read a field's value back after `request_login` filled it (no `.value` reads, no screenshots of revealed
  password fields).
- Do not weaken a guard (forbidden commands, env names, curl options, host checks, redaction, the approval prompt)
  without the user asking for that change. Every guard has a test that fails when it is removed; keep it that way.
- Protocol changes follow KeePassXC's own source (`src/browser/BrowserAction.cpp`), and the mock in
  `tests/mock_keepassxc.py` moves with them.
- Never react in the approvals room, read `~/.config/kpxc-mcp/matrix_token`, or use the user's Element session or
  any Matrix token to answer a prompt. Approval is the user's act.
