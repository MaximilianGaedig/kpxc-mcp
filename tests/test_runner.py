import base64
import json
import http.server
import threading
from urllib.parse import quote

import pytest

from kpxc_mcp import approve, runner
from kpxc_mcp.runner import PolicyError, check_argv, entry_policy, redact, run_with_secrets

SECRET = "s3cr3t-T0ken/with+chars"


def entry(**fields):
    return {"uuid": "u1", "name": "API", "login": "bot", "password": SECRET,
            "stringFields": [{f"KPH: {k}": v} for k, v in fields.items()]}


def test_entry_without_commands_is_not_usable():
    with pytest.raises(PolicyError, match="agent-commands"):
        entry_policy(entry(), "https://api.example.com")


@pytest.mark.parametrize("cmd", ["bash", "python3", "env", "/nix/store/x-coreutils/bin/cat"])
def test_code_running_commands_cannot_be_allowed(cmd):
    with pytest.raises(PolicyError, match="can run anything"):
        entry_policy(entry(**{"agent-commands": f"curl {cmd}"}), "https://api.example.com")


def test_hosts_default_to_entry_url():
    policy = entry_policy(entry(**{"agent-commands": "curl"}), "https://api.example.com/v1")
    assert policy["hosts"] == ["api.example.com"]
    check_argv(["curl", "https://api.example.com/x"], policy)
    with pytest.raises(PolicyError, match="allowed hosts"):
        check_argv(["curl", "https://evil.example/?k=1"], policy)
    with pytest.raises(PolicyError, match="allowed hosts"):
        check_argv(["curl", "--url=https://api.example.com.evil.example/"], policy)


def test_wildcard_host():
    policy = entry_policy(entry(**{"agent-commands": "curl", "agent-hosts": "*.example.com"}), "https://x")
    check_argv(["curl", "https://a.b.example.com/"], policy)
    with pytest.raises(PolicyError):
        check_argv(["curl", "https://example.com.evil/"], policy)


@pytest.mark.parametrize("arg", ["-x", "--proxy", "--resolve", "--connect-to", "-K", "--config=/tmp/c", "--doh-url"])
def test_curl_redirecting_options_are_refused(arg):
    policy = entry_policy(entry(**{"agent-commands": "curl"}), "https://api.example.com")
    with pytest.raises(PolicyError, match="not allowed"):
        check_argv(["curl", arg, "x", "https://api.example.com/"], policy)


def test_command_must_be_listed_and_resolve_into_store():
    policy = entry_policy(entry(**{"agent-commands": "curl"}), "https://api.example.com")
    with pytest.raises(PolicyError, match="not in the entry"):
        check_argv(["wget", "https://api.example.com/"], policy)
    assert check_argv(["curl"], policy).startswith("/nix/store/")
    policy = entry_policy(entry(**{"agent-commands": "definitely-not-a-command"}), "https://api.example.com")
    with pytest.raises(PolicyError, match="system PATH"):
        check_argv(["definitely-not-a-command"], policy)


def test_command_outside_store_refused(tmp_path, monkeypatch):
    shim = tmp_path / "curl"
    shim.write_text("#!/bin/sh\nprintenv\n")
    shim.chmod(0o755)
    monkeypatch.setattr(runner, "SYSTEM_PATH", str(tmp_path))
    policy = entry_policy(entry(**{"agent-commands": "curl"}), "https://api.example.com")
    with pytest.raises(PolicyError, match="does not resolve into /nix/store"):
        check_argv(["curl"], policy)


def test_redact_covers_common_encodings():
    raw = SECRET.encode()
    text = " | ".join([SECRET, quote(SECRET, safe=""), raw.hex(), base64.b64encode(raw).decode(),
                       base64.b64encode(b"x" + raw).decode(), base64.urlsafe_b64encode(b"xy" + raw).decode()])
    out = redact(text, [SECRET])
    assert "s3cr3t" not in out and raw.hex() not in out
    for enc in (base64.b64encode(raw).decode(), base64.b64encode(b"x" + raw).decode()):
        assert enc[4:-4] not in out


@pytest.mark.parametrize("name", ["LD_PRELOAD", "PATH", "GIT_SSH_COMMAND", "HTTPS_PROXY", "lower", "BASH_ENV"])
def test_dangerous_env_names_refused(name):
    with pytest.raises(PolicyError, match="not allowed"):
        run_with_secrets(["curl"], {name: {"url": "https://x"}})


@pytest.fixture
def echo_server():
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(self.headers.get("Authorization", "").encode())

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://localhost:{srv.server_port}/"
    srv.shutdown()


def test_run_injects_secret_and_redacts_echo(paired, echo_server, monkeypatch):
    paired.entries["http://localhost"] = [entry(**{"agent-commands": "curl", "agent-hosts": "localhost"})]
    prompts = []
    monkeypatch.setattr(approve, "choose", lambda text, options: prompts.append(text) or "once")
    argv = ["curl", "-s", "--variable", "%TOK", "--expand-header", "Authorization: Bearer {{TOK}}",
            "--expand-write-out", " {{TOK:b64}} {{TOK:url}}", echo_server]
    result = run_with_secrets(argv, {"TOK": {"url": "http://localhost"}})
    assert result["status"] == "ran" and result["exit_code"] == 0, result
    # the server echoed the header and curl printed encoded copies: all of it is redacted, so the call worked
    assert result["stdout"].startswith("Bearer [redacted]")
    assert SECRET not in result["stdout"] and "s3cr3t" not in result["stdout"]
    assert base64.b64encode(SECRET.encode()).decode()[:12] not in result["stdout"]
    assert "curl -s" in prompts[0] and "TOK ← API (password)" in prompts[0]
    assert SECRET not in prompts[0]


def test_run_denied_runs_nothing(paired, echo_server, monkeypatch):
    paired.entries["http://localhost"] = [entry(**{"agent-commands": "curl", "agent-hosts": "localhost"})]
    monkeypatch.setattr(approve, "choose", lambda text, options: None)
    ran = []
    monkeypatch.setattr(runner.subprocess, "run", lambda *a, **k: ran.append(a))
    assert run_with_secrets(["curl", echo_server], {"T": {"url": "http://localhost"}})["status"] == "denied"
    assert ran == []


def test_ambiguous_and_missing_entries(paired, monkeypatch):
    monkeypatch.setattr(approve, "choose", lambda text, options: pytest.fail("must not prompt"))
    e2 = {**entry(**{"agent-commands": "curl"}), "uuid": "u2", "name": "Other"}
    paired.entries["https://api.example.com"] = [entry(**{"agent-commands": "curl"}), e2]
    result = run_with_secrets(["curl"], {"T": {"url": "https://api.example.com"}})
    assert result["status"] == "ambiguous" and [e["title"] for e in result["entries"]] == ["API", "Other"]
    assert run_with_secrets(["curl"], {"T": {"url": "https://none.example"}})["status"] == "no_login"


def test_only_opted_in_entries_are_candidates(paired, echo_server, monkeypatch):
    monkeypatch.setattr(approve, "choose", lambda text, options: "once")
    login = {**entry(), "uuid": "u0", "name": "GitHub login", "password": "not-this"}
    paired.entries["http://localhost"] = [login, entry(**{"agent-commands": "curl", "agent-hosts": "localhost"})]
    argv = ["curl", "-s", "--variable", "%T", "--expand-header", "Authorization: {{T}}", echo_server]
    result = run_with_secrets(argv, {"T": {"url": "http://localhost"}})
    assert result["status"] == "ran" and result["stdout"] == "[redacted]"  # the opted-in entry's secret was used
    paired.entries["http://localhost"] = [login]
    result = run_with_secrets(argv, {"T": {"url": "http://localhost"}})
    assert result["status"] == "no_login" and "KPH: agent-commands" in result["reason"]
    assert "GitHub login" not in json.dumps(result)  # entries that did not opt in stay anonymous


CAMERA = {**entry(**{"agent-commands": "curl", "agent-hosts": "localhost", "agent-field": "password username"}),
        "uuid": "0123456789abcdef0123456789abcdef", "name": "Example", "path": "Internet/Cameras/Example"}


@pytest.mark.parametrize("selector", ["Example", "Internet/Cameras/Example", "0123456789ABCDEF0123456789ABCDEF"])
def test_entry_by_title_path_or_uuid_without_url(paired, echo_server, monkeypatch, selector):
    paired.entries["https://www.example.net"] = [CAMERA]
    monkeypatch.setattr(approve, "choose", lambda text, options: "once")
    argv = ["curl", "-s", "--variable", "%T", "--expand-header", "Authorization: {{T}}", echo_server]
    result = run_with_secrets(argv, {"T": {"entry": selector}})
    assert result["status"] == "ran" and result["stdout"] == "[redacted]", result


def test_title_lookup_uses_listing_when_allowed(paired, echo_server, monkeypatch):
    paired.entries["https://www.example.net"] = [CAMERA]
    paired.allow_list_entries = True
    monkeypatch.setattr(approve, "choose", lambda text, options: "once")
    argv = ["curl", "-s", "--variable", "%T", "--expand-header", "Authorization: {{T}}", echo_server]
    assert run_with_secrets(argv, {"T": {"entry": "Example"}})["status"] == "ran"
    assert any(r["action"] == "get-database-entries" for r in paired.requests)
    assert not any(r["action"] == "get-database-groups" for r in paired.requests)


def test_field_chosen_per_variable_within_the_entry_policy(paired, echo_server, monkeypatch):
    paired.entries["https://www.example.net"] = [CAMERA]
    prompts = []
    monkeypatch.setattr(approve, "choose", lambda text, options: prompts.append(text) or "once")
    argv = ["curl", "-s", "--variable", "%U", "--variable", "%P", "--expand-header", "Authorization: {{U}}:{{P}}",
            echo_server]
    result = run_with_secrets(argv, {"U": {"entry": "Example", "field": "username"}, "P": {"entry": "Example"}})
    assert result["status"] == "ran" and result["stdout"] == "[redacted]:[redacted]", result
    assert "U ← Example (username)" in prompts[0] and "P ← Example (password)" in prompts[0]
    with pytest.raises(PolicyError, match="allows only"):
        run_with_secrets(argv, {"U": {"entry": "Example", "field": "totp"}})


def test_entry_lookup_without_site_needs_explicit_hosts(paired, monkeypatch):
    monkeypatch.setattr(approve, "choose", lambda text, options: pytest.fail("must not prompt"))
    paired.entries["https://www.example.net"] = [{**CAMERA, "stringFields": [{"KPH: agent-commands": "curl"}]}]
    with pytest.raises(PolicyError, match="agent-hosts"):
        run_with_secrets(["curl", "https://www.example.net/"], {"T": {"entry": "Example"}})


def test_unknown_entry_selector(paired, monkeypatch):
    monkeypatch.setattr(approve, "choose", lambda text, options: pytest.fail("must not prompt"))
    assert run_with_secrets(["curl"], {"T": {"entry": "Nope"}})["status"] == "no_login"
    with pytest.raises(PolicyError, match="url, entry"):
        run_with_secrets(["curl"], {"T": {}})


def test_named_entry_without_policy_runs_behind_a_warning(paired, echo_server, monkeypatch):
    bare = {"uuid": "b" * 32, "name": "Example", "path": "Internet/Example", "login": "me@x", "password": SECRET}
    paired.entries["https://unrelated.example"] = [bare]
    prompts = []
    monkeypatch.setattr(approve, "choose", lambda text, options: prompts.append(text) or "once")
    argv = ["curl", "-s", "--variable", "%U", "--variable", "%P", "--expand-header", "Authorization: {{U}}:{{P}}",
            echo_server]
    result = run_with_secrets(argv, {"U": {"entry": "Internet/Example", "field": "username"},
                                     "P": {"entry": "Internet/Example"}})
    assert result["status"] == "ran" and result["stdout"] == "[redacted]:[redacted]", result
    assert "no KPH: policy" in prompts[0] and "curl -s" in prompts[0]


@pytest.mark.parametrize("cmd", ["python3", "bash", "env"])
def test_named_entry_without_policy_still_refuses_interpreters(paired, monkeypatch, cmd):
    paired.entries["https://unrelated.example"] = [{"uuid": "b" * 32, "name": "Example", "password": SECRET}]
    monkeypatch.setattr(approve, "choose", lambda text, options: pytest.fail("must not prompt"))
    with pytest.raises(PolicyError):
        run_with_secrets([cmd, "-c", "x"], {"P": {"entry": "Example"}})


def test_site_lookup_still_needs_opt_in(paired, monkeypatch):
    paired.entries["https://unrelated.example"] = [{"uuid": "b" * 32, "name": "Example", "password": SECRET}]
    monkeypatch.setattr(approve, "choose", lambda text, options: pytest.fail("must not prompt"))
    assert run_with_secrets(["curl"], {"P": {"url": "https://unrelated.example"}})["status"] == "no_login"


def test_allow_always_remembers_program_and_entries(paired, echo_server, monkeypatch):
    from kpxc_mcp import remember
    paired.entries["http://localhost"] = [entry(**{"agent-commands": "curl wget", "agent-hosts": "localhost"})]
    prompts = []
    monkeypatch.setattr(approve, "choose", lambda text, options: prompts.append(options) or "always")
    argv = ["curl", "-s", echo_server]
    assert run_with_secrets(argv, {"T": {"url": "http://localhost"}})["status"] == "ran"
    assert [k for k, _ in prompts[0]] == ["once", "always"]
    # same program, same entry and field, other arguments: no prompt
    monkeypatch.setattr(approve, "choose", lambda text, options: pytest.fail("must not prompt"))
    assert run_with_secrets(["curl", "-s", "-I", echo_server], {"T": {"url": "http://localhost"}})["status"] == "ran"
    # another field of the same entry is a different grant and asks again
    monkeypatch.setattr(approve, "choose", lambda text, options: None)
    assert run_with_secrets(argv, {"T": {"url": "http://localhost", "field": "password"},
                                   "U": {"url": "http://localhost"}})["status"] == "denied"
    assert remember.forget() == 1
    assert run_with_secrets(argv, {"T": {"url": "http://localhost"}})["status"] == "denied"  # asks again


def test_allow_once_remembers_nothing(paired, echo_server, monkeypatch):
    paired.entries["http://localhost"] = [entry(**{"agent-commands": "curl", "agent-hosts": "localhost"})]
    monkeypatch.setattr(approve, "choose", lambda text, options: "once")
    assert run_with_secrets(["curl", "-s", echo_server], {"T": {"url": "http://localhost"}})["status"] == "ran"
    monkeypatch.setattr(approve, "choose", lambda text, options: None)
    assert run_with_secrets(["curl", "-s", echo_server], {"T": {"url": "http://localhost"}})["status"] == "denied"
