"""request_login against a real headless Chromium/Brave with a throwaway profile and pages served on localhost."""

import http.server
import json
import os
import shutil
import signal
import socket
import subprocess
import threading
import time
import urllib.request

import pytest

from kpxc_mcp import approve, browser

PAGES = {
    "/login": """<form><input name=user type=email><input name=pass type=password autocomplete=current-password>
                 <button>Sign in</button></form>
                 <script>window.events=0;document.querySelector('[name=pass]').addEventListener('input',()=>events++)</script>""",
    "/first": """<form><input name=search type=text style=display:none><input id=identifier type=text>
                 <button>Next</button></form>""",
    "/otp": """<form><input name=user type=text value=me><input id=code inputmode=numeric autocomplete=one-time-code>
               </form>""",
    "/none": "<p>nothing to fill</p>",
}


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _chromium():
    for name in ("brave", "chromium", "chromium-browser", "google-chrome"):
        if exe := shutil.which(name):
            return exe
    return None


@pytest.fixture(scope="module")
def site():
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/slow":  # the form arrives 1.5 s after the page starts loading
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<p>loading</p>" + b" " * 4096)
                self.wfile.flush()
                time.sleep(1.5)
                self.wfile.write(PAGES["/login"].encode())
                return
            body = PAGES.get(self.path.split("?")[0])
            self.send_response(200 if body else 404)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write((body or "").encode())

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://localhost:{srv.server_port}"
    srv.shutdown()


@pytest.fixture(scope="module")
def chrome(tmp_path_factory):
    exe = _chromium()
    if not exe:
        pytest.skip("no Chromium-based browser on PATH")
    port = _free_port()
    profile = tmp_path_factory.mktemp("profile")
    proc = subprocess.Popen([exe, "--headless=new", f"--remote-debugging-port={port}", f"--user-data-dir={profile}",
                             "--no-first-run", "--disable-gpu", "about:blank"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    base = f"http://127.0.0.1:{port}"
    for _ in range(100):
        try:
            urllib.request.urlopen(f"{base}/json/version", timeout=1)
            break
        except OSError:
            time.sleep(0.2)
    else:
        os.killpg(proc.pid, signal.SIGKILL)
        pytest.fail("browser did not open its DevTools port")
    yield base
    # the brave launcher is a wrapper script; signal the whole group or the browser outlives the tests
    os.killpg(proc.pid, signal.SIGTERM)
    try:
        proc.wait(10)
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)
    shutil.rmtree(profile, ignore_errors=True)


@pytest.fixture
def tab(chrome, monkeypatch):
    monkeypatch.setenv("KPXC_MCP_CDP", chrome)
    opened = []

    def open_tab(url):
        req = urllib.request.Request(f"{chrome}/json/new?about:blank", method="PUT")
        target = json.load(urllib.request.urlopen(req, timeout=5))
        opened.append(target["id"])
        page = browser.Page(target)
        try:
            page.call("Page.navigate", url=url)
            for _ in range(50):
                state = page.call("Runtime.evaluate", expression="location.href + ' ' + document.readyState",
                                  returnByValue=True)["result"]["value"]
                if state == f"{url} complete":
                    break
                time.sleep(0.1)
            else:
                pytest.fail(f"{url} did not load: {state}")
        finally:
            page.close()
        return target

    yield open_tab
    for target_id in opened:
        urllib.request.urlopen(f"{chrome}/json/close/{target_id}", timeout=5)


def page_eval(target, expression):
    page = browser.Page(target)
    try:
        return page.call("Runtime.evaluate", expression=expression, returnByValue=True)["result"]["value"]
    finally:
        page.close()


ENTRY = {"uuid": "u1", "name": "Site", "login": "me@example.com", "password": "pa55-word", "group": "Web"}


@pytest.fixture
def allow(monkeypatch):
    prompts = []

    def choose(text, options):
        prompts.append((text, options))
        return options[0][0]

    monkeypatch.setattr(approve, "choose", choose)
    return prompts


def test_fills_username_and_password_without_returning_them(paired, site, tab, allow):
    paired.entries[site] = [ENTRY]
    target = tab(f"{site}/login")
    result = browser.request_login(target["id"])
    assert result == {"status": "filled", "fields": ["username", "password"]}
    assert "pa55-word" not in json.dumps(result) and "me@example.com" not in json.dumps(result)
    values = page_eval(target, "[document.querySelector('[name=user]').value, document.querySelector('[name=pass]')"
                               ".value, events]")
    assert values == ["me@example.com", "pa55-word", 1]
    assert f"{site}/login" in allow[0][0]
    assert "pa55-word" not in json.dumps(allow)


def test_tab_by_url_part_and_username_first_flow(paired, site, tab, allow):
    paired.entries[site] = [ENTRY]
    target = tab(f"{site}/first")
    assert browser.request_login("/first") == {"status": "filled", "fields": ["username"]}
    assert page_eval(target, "document.getElementById('identifier').value") == "me@example.com"


def test_totp(paired, site, tab, allow):
    paired.entries[site] = [{**ENTRY, "totp": "otpauth"}]
    paired.totp["u1"] = "654321"
    target = tab(f"{site}/otp")
    assert browser.request_login(target["id"], "totp") == {"status": "filled", "fields": ["totp"]}
    assert page_eval(target, "document.getElementById('code').value") == "654321"


def test_denied_fills_nothing(paired, site, tab, monkeypatch):
    paired.entries[site] = [ENTRY]
    monkeypatch.setattr(approve, "choose", lambda text, options: None)
    target = tab(f"{site}/login")
    assert browser.request_login(target["id"]) == {"status": "denied"}
    assert page_eval(target, "document.querySelector('[name=pass]').value") == ""


def test_no_entry_and_no_field(paired, site, tab, allow):
    target = tab(f"{site}/login")
    assert browser.request_login(target["id"])["status"] == "no_login"
    paired.entries[site] = [ENTRY]
    target = tab(f"{site}/none")
    lookups = len(paired.requests)
    assert browser.request_login(target["id"]) == {"status": "no_field"}
    # nothing was asked of KeePassXC or the user for a page without a form
    assert len(paired.requests) == lookups and allow == []


def test_origin_change_after_lookup_is_caught(paired, site, tab, monkeypatch):
    paired.entries[site] = [ENTRY]
    target = tab(f"{site}/login")

    def choose_then_navigate(text, options):
        page_eval(target, "location.href = 'about:blank'; 1")
        time.sleep(0.5)
        return options[0][0]

    monkeypatch.setattr(approve, "choose", choose_then_navigate)
    assert browser.request_login(target["id"]) == {"status": "origin_changed"}


def test_plain_http_sites_refused(paired, chrome, monkeypatch):
    monkeypatch.setenv("KPXC_MCP_CDP", chrome)
    monkeypatch.setattr(browser, "page_targets",
                        lambda: [{"id": "t", "type": "page", "url": "http://example.com/login"}])
    assert browser.request_login("t")["status"] == "refused"


def test_ambiguous_tab(chrome, site, tab):
    tab(f"{site}/login")
    tab(f"{site}/login?again")
    with pytest.raises(LookupError, match="2 tabs"):
        browser.request_login("/login")


def test_waits_for_a_page_that_is_still_loading(paired, site, chrome, monkeypatch, allow):
    monkeypatch.setenv("KPXC_MCP_CDP", chrome)
    paired.entries[site] = [ENTRY]
    req = urllib.request.Request(f"{chrome}/json/new?about:blank", method="PUT")
    target = json.load(urllib.request.urlopen(req, timeout=5))
    page = browser.Page(target)
    try:
        page.call("Page.navigate", url=f"{site}/slow")
        time.sleep(0.4)  # navigation committed, form not there yet
        assert browser.request_login(target["id"]) == {"status": "filled", "fields": ["username", "password"]}
    finally:
        page.close()
        urllib.request.urlopen(f"{chrome}/json/close/{target['id']}", timeout=5)


@pytest.fixture
def fresh_followups(monkeypatch):
    monkeypatch.setattr(browser, "_followups", {})


def test_login_approval_covers_the_following_code_once(paired, site, tab, allow, fresh_followups):
    paired.entries[site] = [{**ENTRY, "totp": "otpauth"}]
    paired.totp["u1"] = "111222"
    target = tab(f"{site}/login")
    assert browser.request_login(target["id"])["status"] == "filled"
    assert "one-time code" in allow[0][0]
    page_eval(target, f"location.href = '{site}/otp'; 1")
    time.sleep(0.5)
    assert browser.request_login(target["id"], "totp") == {"status": "filled", "fields": ["totp"]}
    assert len(allow) == 1  # no second prompt
    assert page_eval(target, "document.getElementById('code').value") == "111222"
    browser.request_login(target["id"], "totp")
    assert len(allow) == 2  # the follow-up is single use


def test_code_followup_is_bound_to_tab_and_expires(paired, site, tab, allow, fresh_followups, monkeypatch):
    paired.entries[site] = [{**ENTRY, "totp": "otpauth"}]
    first = tab(f"{site}/login")
    assert browser.request_login(first["id"])["status"] == "filled"
    other = tab(f"{site}/otp")
    browser.request_login(other["id"], "totp")
    assert len(allow) == 2  # another tab asks again
    monkeypatch.setattr(browser, "TOTP_FOLLOWUP_SECONDS", 0)
    assert browser.request_login(first["id"])["status"] == "filled"
    page_eval(first, f"location.href = '{site}/otp'; 1")
    time.sleep(0.5)
    browser.request_login(first["id"], "totp")
    assert len(allow) == 4  # expired, so it asks


def test_denied_login_grants_nothing(paired, site, tab, fresh_followups, monkeypatch):
    paired.entries[site] = [{**ENTRY, "totp": "otpauth"}]
    answers = iter([None, None])
    monkeypatch.setattr(approve, "choose", lambda text, options: next(answers))
    target = tab(f"{site}/login")
    assert browser.request_login(target["id"]) == {"status": "denied"}
    page_eval(target, f"location.href = '{site}/otp'; 1")
    time.sleep(0.5)
    assert browser.request_login(target["id"], "totp") == {"status": "denied"}


def test_unanswered_keepassxc_dialog_is_reported(paired, site, tab, allow, monkeypatch):
    from kpxc_mcp import keepassxc
    monkeypatch.setattr(keepassxc, "REPLY_TIMEOUT", 0.5)
    paired.entries[site] = [ENTRY]
    paired.dialog_seconds = 2
    target = tab(f"{site}/login")
    assert browser.request_login(target["id"])["status"] == "dialog_unanswered"
    assert allow == [] and page_eval(target, "document.querySelector('[name=pass]').value") == ""


def test_entry_picked_by_title_for_a_site_stored_elsewhere(paired, site, tab, allow):
    # the login is stored for another domain, so the site match finds nothing; the agent names the entry instead
    paired.entries["https://www.example.net"] = [{**ENTRY, "name": "Example", "path": "Internet/Example"}]
    target = tab(f"{site}/login")
    assert browser.request_login(target["id"])["status"] == "no_login"
    assert browser.request_login(target["id"], entry_selector="Example") == {"status": "filled",
                                                                          "fields": ["username", "password"]}
    assert page_eval(target, "document.querySelector('[name=pass]').value") == "pa55-word"
    # the prompt tells the user the agent chose the entry, not KeePassXC's site match
    assert "did not match it" in allow[-1][0] and "'Example'" in allow[-1][0]


def test_allow_always_for_site_skips_later_prompts(paired, site, tab, monkeypatch):
    paired.entries[site] = [ENTRY]
    monkeypatch.setattr(approve, "choose", lambda text, options: options[1][0])  # "<uuid>|always"
    target = tab(f"{site}/login")
    assert browser.request_login(target["id"])["status"] == "filled"
    monkeypatch.setattr(approve, "choose", lambda text, options: pytest.fail("must not prompt"))
    target = tab(f"{site}/login")
    assert browser.request_login(target["id"]) == {"status": "filled", "fields": ["username", "password"]}
