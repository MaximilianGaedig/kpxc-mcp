"""Run a command with KeePassXC secrets in its environment, under a policy stored in the entry itself.

The agent names the command and which entry goes into which environment variable; it never sees the value. Each
entry opts in through KPH: attributes, which only the user can set in KeePassXC:

  KPH: agent-commands   allowed commands, whitespace separated (names on the system PATH or /nix/store paths)
  KPH: agent-hosts      allowed hosts for URLs in the arguments (default: the entry URL's host)
  KPH: agent-field      fields the agent may inject, whitespace separated: password (default), username, totp;
                        the first is used unless the agent names another one with `field`

An entry is found by `url` (KeePassXC's site matching, `entry` then narrows by title) or by `entry` alone: a title,
a "Group/Title" path or a UUID (KeePassXC.find_entries).
"""

import base64
import os
import re
import shutil
import subprocess
from urllib.parse import quote, urlsplit

from . import approve, remember
from .keepassxc import connect_associated, string_fields

SYSTEM_PATH = f"/run/current-system/sw/bin:/etc/profiles/per-user/{os.environ.get('USER', '')}/bin"
OUTPUT_LIMIT = 256 * 1024

# Commands that can run arbitrary code or forward their environment anywhere; allowing one defeats the policy.
FORBIDDEN_COMMANDS = {
    "sh", "bash", "zsh", "fish", "dash", "env", "sudo", "doas", "su", "nix", "nix-shell", "xargs", "find",
    "python", "python3", "node", "deno", "bun", "perl", "ruby", "lua", "awk", "gawk", "sed", "busybox",
    "ssh", "socat", "nc", "ncat", "tee", "cat", "echo", "printf", "printenv", "strace", "gdb", "systemd-run",
}
ENV_NAME = re.compile(r"^[A-Z_][A-Z0-9_]*$")
FORBIDDEN_ENV = re.compile(r"^(LD_|DYLD_|PYTHON|NODE_|PERL|RUBY|GIT_|BASH_|ZDOTDIR$|ENV$|PATH$|HOME$|SHELL$|"
                           r"PROMPT_COMMAND$|SSL_|CURL_|HTTPS?_PROXY$|ALL_PROXY$|NO_PROXY$)", re.IGNORECASE)
# curl options that change where a request goes or read extra config
CURL_FORBIDDEN = re.compile(r"^(-x|--proxy.*|--preproxy|--socks.*|--resolve|--connect-to|-K|--config|--doh-url|"
                            r"--unix-socket|--abstract-unix-socket|-q|--disable)(=.*)?$")
URL_IN_ARG = re.compile(r"[a-zA-Z][a-zA-Z0-9+.-]*://[^\s\"'<>]+")


class PolicyError(Exception):
    pass


def resolve_command(name):
    path = name if name.startswith("/nix/store/") else shutil.which(name, path=SYSTEM_PATH)
    if not path:
        raise PolicyError(f"{name!r} is not on the system PATH")
    real = os.path.realpath(path)
    if not real.startswith("/nix/store/"):
        raise PolicyError(f"{name!r} does not resolve into /nix/store")
    return real


def entry_policy(entry, url, named=False):
    """The entry's KPH: policy. An entry the agent named explicitly (`entry` without `url`) may have none: then any
    command outside FORBIDDEN_COMMANDS, any host and any field are allowed, and the approval prompt, which shows
    the whole command and warns about the missing policy, is the only limit."""
    fields = string_fields(entry)
    commands = fields.get("KPH: agent-commands", "").split()
    if not commands and named:
        return {"commands": None, "hosts": None, "field": "password", "fields": ["password", "username", "totp"]}
    if not commands:
        raise PolicyError(f"entry {entry.get('name')!r} has no 'KPH: agent-commands' attribute, so it is not "
                          "allowed for commands")
    for c in commands:
        if os.path.basename(c) in FORBIDDEN_COMMANDS:
            raise PolicyError(f"entry {entry.get('name')!r} allows {c!r}, which can run anything; refusing")
    hosts = fields.get("KPH: agent-hosts", "").split()
    if not hosts:
        if not url or urlsplit(url).scheme == "keepassxc":
            raise PolicyError(f"entry {entry.get('name')!r} was not looked up by site, so it needs a "
                              "'KPH: agent-hosts' attribute")
        hosts = [urlsplit(url).hostname]
    allowed = fields.get("KPH: agent-field", "password").split() or ["password"]
    for field in allowed:
        if field not in ("password", "username", "totp"):
            raise PolicyError(f"unknown KPH: agent-field {field!r}")
    return {"commands": commands, "hosts": [h.lower() for h in hosts if h], "field": allowed[0],
            "fields": allowed}


def host_allowed(host, allowed):
    host = (host or "").lower().rstrip(".")
    return any(host == a or (a.startswith("*.") and host.endswith(a[1:])) for a in allowed)


def check_argv(argv, policy):
    """Raise unless argv[0] is allowed and every URL in the arguments points at an allowed host."""
    if policy["commands"] is None:  # named entry without a policy: refuse only what can run anything
        exe = resolve_command(argv[0])
        if os.path.basename(argv[0]) in FORBIDDEN_COMMANDS or os.path.basename(exe) in FORBIDDEN_COMMANDS:
            raise PolicyError(f"{argv[0]!r} can run anything; refusing")
        if os.path.basename(argv[0]) == "curl" and any(CURL_FORBIDDEN.match(a) for a in argv[1:]):
            raise PolicyError("this curl option is not allowed")
        return exe
    if argv[0] not in policy["commands"] and os.path.basename(argv[0]) not in {os.path.basename(c) for c in
                                                                                 policy["commands"]}:
        raise PolicyError(f"{argv[0]!r} is not in the entry's KPH: agent-commands")
    program = os.path.basename(argv[0])
    for arg in argv[1:]:
        if program == "curl" and CURL_FORBIDDEN.match(arg):
            raise PolicyError(f"curl option {arg!r} is not allowed")
        for url in URL_IN_ARG.findall(arg):
            if not host_allowed(urlsplit(url).hostname, policy["hosts"]):
                raise PolicyError(f"URL host in {url!r} is not in the entry's allowed hosts {policy['hosts']}")
    return resolve_command(next(c for c in policy["commands"]
                                if c == argv[0] or os.path.basename(c) == os.path.basename(argv[0])))


def secret_variants(value):
    """Encodings a command could echo a secret back in; all are removed from the output."""
    if len(value) < 4:
        return [value] if value else []
    raw = value.encode()
    variants = {value, quote(value, safe=""), raw.hex(), raw.hex().upper()}
    for shift in range(3):
        chunk = raw[shift:]
        for enc in (base64.b64encode(chunk).decode(), base64.urlsafe_b64encode(chunk).decode()):
            # the stable middle of the encoding, independent of padding and of what surrounds it
            usable = len(chunk) // 3 * 4
            if usable >= 8:
                variants.add(enc[:usable])
    return sorted(variants, key=len, reverse=True)


def redact(text, secrets):
    for secret in secrets:
        for variant in secret_variants(secret):
            text = text.replace(variant, "[redacted]")
    return text


def run_with_secrets(argv, env, cwd=None, timeout=120):
    """argv: command and arguments (no shell).
    env: {VAR: {"url": site, "entry": title | "Group/Title" | uuid, "field": password | username | totp}};
    at least one of url and entry."""
    if not argv or not isinstance(argv, list) or not all(isinstance(a, str) for a in argv):
        raise PolicyError("argv must be a non-empty list of strings")
    if not env:
        raise PolicyError("env must map at least one variable to a KeePassXC entry")
    for name in env:
        if not ENV_NAME.match(name) or FORBIDDEN_ENV.match(name):
            raise PolicyError(f"environment variable name {name!r} is not allowed")
    if cwd is not None and not os.path.isdir(cwd):
        raise PolicyError(f"cwd {cwd!r} is not a directory")

    conn, assoc = connect_associated()
    values, labels, grants, exe = {}, [], [], None
    with conn:
        for name, spec in env.items():
            url, selector = spec.get("url", ""), spec.get("entry", "")
            if not url and not selector:
                raise PolicyError(f"{name}: give url, entry, or both")
            if url:
                found = conn.get_logins(assoc, url)
                if selector:
                    found = [e for e in found if selector in (e.get("name"), e.get("uuid"))]
            else:
                found = conn.find_entries(assoc, selector)
            where = url or selector
            # by site, only entries the user opted in for commands are candidates (their titles may be shown to the
            # agent); an entry the agent named is a candidate as it is
            named = bool(selector) and not url
            entries = found if named else [e for e in found
                                           if string_fields(e).get("KPH: agent-commands", "").strip()]
            if not entries:
                return {"status": "no_login", "reason": (
                    f"{name}: none of the {len(found)} KeePassXC entries for {where} allows commands; the user "
                    "adds a 'KPH: agent-commands' attribute to the one to use" if found else
                    f"{name}: no KeePassXC entry matches {where}, or access was denied")}
            if len(entries) > 1:
                return {"status": "ambiguous",
                        "reason": f"{name}: several entries match; pass one's UUID (or Group/Title path) as `entry`",
                        "entries": sorted(({"title": e.get("name", ""), "group": e.get("group", ""),
                                            "uuid": e.get("uuid", "")} for e in entries),
                                          key=lambda e: (e["title"], e["group"]))}
            entry = entries[0]
            policy = entry_policy(entry, url, named)
            exe = check_argv(argv, policy)
            field = spec.get("field") or policy["field"]
            if field not in policy["fields"]:
                raise PolicyError(f"{name}: entry {entry.get('name')!r} allows only {policy['fields']} in "
                                  "'KPH: agent-field'")
            values[name] = conn.get_totp(entry["uuid"]) if field == "totp" else entry.get(
                "login" if field == "username" else "password", "")
            grants.append((entry["uuid"], field))
            labels.append(f"{name} ← {entry.get('name')} ({field})" + (
                "  — entry has no KPH: policy, so only this approval limits the command" if policy["commands"] is None
                else ""))

    prompt = ("An agent asks to run a command with KeePassXC secrets:\n\n" + " ".join(argv) +
              f"\n\nin {cwd or os.getcwd()}\n\n" + "\n".join(labels))
    key = remember.command_key(argv[0], grants)
    if not remember.is_remembered(key):
        program = os.path.basename(argv[0])
        answer = approve.choose(prompt, [("once", "Allow once"),
                                         ("always", f"Allow always: {program} with these entries, any arguments")])
        if answer is None:
            return {"status": "denied"}
        if answer == "always":
            remember.remember(key)

    child_env = {k: v for k, v in os.environ.items() if not FORBIDDEN_ENV.match(k) or k in ("PATH", "HOME", "SHELL")}
    child_env.update(values)
    try:
        proc = subprocess.run([exe, *argv[1:]], env=child_env, cwd=cwd, stdin=subprocess.DEVNULL,
                              capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"status": "timeout"}
    secrets = list(values.values())
    out = redact(proc.stdout[:OUTPUT_LIMIT].decode(errors="replace"), secrets)
    err = redact(proc.stderr[:OUTPUT_LIMIT].decode(errors="replace"), secrets)
    return {"status": "ran", "exit_code": proc.returncode, "stdout": out, "stderr": err,
            "truncated": len(proc.stdout) > OUTPUT_LIMIT or len(proc.stderr) > OUTPUT_LIMIT}
