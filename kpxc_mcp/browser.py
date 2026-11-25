"""Fill a login form in a Brave/Chromium tab through the DevTools protocol, so the values never pass the agent."""

import json
import os
import time
import urllib.request
from urllib.parse import urlsplit

from websockets.sync.client import connect

from . import approve, remember
from .keepassxc import Connection, KeePassXCError, connect_associated


def cdp_base():
    return os.environ.get("KPXC_MCP_CDP", "http://127.0.0.1:9222")


def page_targets():
    with urllib.request.urlopen(f"{cdp_base()}/json/list", timeout=5) as r:
        return [t for t in json.load(r) if t.get("type") == "page"]


def find_tab(tab):
    """The single page target whose id equals `tab` or whose URL contains it."""
    targets = page_targets()
    exact = [t for t in targets if t["id"] == tab]
    matches = exact or [t for t in targets if tab in t.get("url", "")]
    if len(matches) != 1:
        raise LookupError(f"{len(matches)} tabs match {tab!r}; pass a longer part of the URL")
    return matches[0]


def secure_origin(url):
    parts = urlsplit(url)
    return parts.scheme == "https" or (parts.scheme == "http" and parts.hostname in ("localhost", "127.0.0.1", "::1"))


# Runs in the page. Finds the visible login (or one-time-code) fields, sets them the way a user's typing would,
# and reports only which fields it filled.
FILL_JS = r"""
function (args) {
  if (location.origin !== args.origin) return {status: "origin_changed"};
  const all = [];
  const walk = (root) => {
    for (const el of root.querySelectorAll("*")) {
      if (el instanceof HTMLInputElement) all.push(el);
      if (el.shadowRoot) walk(el.shadowRoot);
    }
  };
  walk(document);
  const visible = (el) => !el.disabled && !el.readOnly && el.type !== "hidden" &&
    el.getClientRects().length > 0 && getComputedStyle(el).visibility !== "hidden";
  const inputs = all.filter(visible);
  const setValue = (el, value) => {
    el.focus();
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set.call(el, value);
    el.dispatchEvent(new InputEvent("input", {bubbles: true, composed: true, inputType: "insertText"}));
    el.dispatchEvent(new Event("change", {bubbles: true}));
  };
  const textual = (el) => ["text", "email", "tel", ""].includes(el.type);
  if (args.mode === "totp") {
    const hint = /otp|totp|2fa|mfa|one.?time|verification|security.?code|auth.?code|^code$/i;
    const field = inputs.find((el) => el.autocomplete === "one-time-code") ||
      inputs.find((el) => (textual(el) || el.type === "number") &&
        [el.name, el.id, el.placeholder, el.getAttribute("aria-label") || ""].some((s) => hint.test(s)));
    if (!field) return {status: "no_field"};
    if (args.probe) return {status: "ready", fields: ["totp"]};
    setValue(field, args.totp);
    return {status: "filled", fields: ["totp"]};
  }
  const passwords = inputs.filter((el) => el.type === "password");
  const pw = passwords.find((el) => el.autocomplete === "current-password") || passwords[0];
  const scope = pw ? (pw.form ? Array.from(pw.form.elements) : inputs) : inputs;
  const before = (el) => !pw || (el.compareDocumentPosition(pw) & Node.DOCUMENT_POSITION_FOLLOWING);
  const candidates = scope.filter((el) => el instanceof HTMLInputElement && visible(el) && textual(el) && before(el));
  const user = candidates.find((el) => el.autocomplete === "username") || candidates[candidates.length - 1];
  if (!user && !pw) return {status: "no_field"};
  if (args.probe) return {status: "ready", fields: [user && "username", pw && "password"].filter(Boolean)};
  const filled = [];
  if (user && args.login) { setValue(user, args.login); filled.push("username"); }
  if (pw) { setValue(pw, args.password); filled.push("password"); }
  if (!filled.length) return {status: "no_field"};
  return {status: "filled", fields: filled};
}
"""


class Page:
    def __init__(self, target):
        self.ws = connect(target["webSocketDebuggerUrl"], max_size=None, open_timeout=5)
        self.next_id = 0

    def close(self):
        self.ws.close()

    def call(self, method, **params):
        self.next_id += 1
        msg_id = self.next_id
        self.ws.send(json.dumps({"id": msg_id, "method": method, "params": params}))
        while True:
            reply = json.loads(self.ws.recv(timeout=15))
            if reply.get("id") == msg_id:
                if "error" in reply:
                    raise RuntimeError(f"{method}: {reply['error'].get('message')}")
                return reply["result"]

    def wait_loaded(self, timeout=15):
        """Wait for the document to finish loading; an agent often calls right after starting a navigation."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            state = self.call("Runtime.evaluate", expression="document.readyState", returnByValue=True)
            if state["result"].get("value") == "complete":
                return
            time.sleep(0.2)

    def run_fill(self, args):
        window = self.call("Runtime.evaluate", expression="globalThis")["result"]["objectId"]
        result = self.call("Runtime.callFunctionOn", objectId=window, functionDeclaration=FILL_JS,
                           arguments=[{"value": args}], returnByValue=True)
        if "exceptionDetails" in result:
            return {"status": "page_error"}
        return result["result"]["value"]


# An approved login also covers the one-time code that follows it: same tab, same origin, same entry, once, soon.
TOTP_FOLLOWUP_SECONDS = 180
_followups = {}  # (target id, origin) -> (entry uuid, deadline)


def request_login(tab, mode="login", entry_selector=None):
    """Ask KeePassXC for the login of the tab's site and fill it after the user approves. Returns a status dict
    with no credential values in it. `entry_selector` (title, "Group/Title" or UUID) picks the entry instead of the
    site match, for logins stored under another URL; the prompt then says the entry was not matched to the site."""
    target = find_tab(tab)
    url = target["url"]
    if not secure_origin(url):
        return {"status": "refused", "reason": "page is not https (or localhost)"}
    parts = urlsplit(url)
    origin = f"{parts.scheme}://{parts.netloc}"

    # look before asking: no prompt for a page without a form (e.g. already signed in and redirected)
    page = Page(target)
    try:
        page.wait_loaded()
        probe = page.run_fill({"mode": mode, "origin": origin, "probe": True})
    finally:
        page.close()
    if probe["status"] != "ready":
        return probe

    with Connection() as probe_conn:
        locked = probe_conn.is_locked()
    if locked:
        dialog = "KeePassXC is locked: unlock it on the desktop"
    else:
        dialog = (f"KeePassXC asks on the desktop whether to give {parts.netloc} access to an entry. "
                  "Tick Remember there so later requests can be approved from here")
    notice = f"{dialog} (an agent wants a login for {url}).\n\nThis dialog can only be answered on the desktop."
    try:
        with approve.desktop_dialog_notice(notice):
            conn, assoc = connect_associated()
            try:
                entries = conn.find_entries(assoc, entry_selector) if entry_selector else conn.get_logins(assoc, url)
            except BaseException:
                conn.close()
                raise
    except TimeoutError:
        return {"status": "dialog_unanswered",
                "reason": "KeePassXC's own unlock or access dialog was not answered on the desktop"}
    with conn:
        if mode == "totp":
            entries = [e for e in entries if e.get("totp")]
        if not entries:
            return {"status": "no_login", "reason": (
                f"no KeePassXC entry matches {entry_selector or parts.netloc}, or access was denied in KeePassXC; "
                "pass `entry` (title, Group/Title or UUID) when the login is stored under another URL")}
        followup = _followups.pop((target["id"], origin), None)
        remembered = [e["uuid"] for e in entries if remember.is_remembered(remember.login_key(origin, e["uuid"]))]
        if mode == "totp" and followup and followup[1] > time.monotonic() and \
                any(e["uuid"] == followup[0] for e in entries):
            picked = followup[0]
        elif len(remembered) == 1:
            picked = remembered[0]
        else:
            what = "a one-time code" if mode == "totp" else "a login"
            if mode == "login" and any(e.get("totp") for e in entries):
                what += " (and its one-time code, if the site asks next)"
            options = []
            for e in entries:
                label = f"{e.get('name', '')} — {e.get('login', '')} ({e.get('group', '')})"
                options += [(e["uuid"], label), (e["uuid"] + "|always", f"{label} — always for {parts.netloc}")]
            text = f"An agent asks to fill {what} into\n{url}\n(tab: {target.get('title', '')})"
            if entry_selector:
                text += (f"\n\nThe agent picked the entry ({entry_selector!r}); KeePassXC did not match it to "
                         f"{parts.netloc}. Check that this page belongs to the same service.")
            picked = approve.choose(text, options)
            if picked is None:
                return {"status": "denied"}
            if picked.endswith("|always"):
                picked = picked.removesuffix("|always")
                remember.remember(remember.login_key(origin, picked))
        entry = next(e for e in entries if e["uuid"] == picked)
        args = {"mode": mode, "origin": origin}
        if mode == "totp":
            args["totp"] = conn.get_totp(entry["uuid"])
        else:
            args["login"] = entry.get("login", "")
            args["password"] = entry.get("password", "")

    page = Page(target)
    try:
        result = page.run_fill(args)
    finally:
        page.close()
        args.clear()
    if mode == "login" and result.get("status") == "filled" and entry.get("totp"):
        _followups[(target["id"], origin)] = (entry["uuid"], time.monotonic() + TOTP_FOLLOWUP_SECONDS)
    return result


__all__ = ["request_login", "KeePassXCError"]
