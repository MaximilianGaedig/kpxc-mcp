"""Approval prompts the user answers outside the agent's view.

Two channels race: a zenity dialog on the desktop and, when configured, a Matrix message the user reacts to from their
phone (kpxc_mcp.matrix). The first answer (Allow or Deny) wins and the other prompt is withdrawn. A channel that times out or
fails is no answer; when no channel answers, the request is denied.
"""

import contextlib
import os
import shutil
import subprocess
import threading

from . import context, matrix

TIMEOUT = 120
NOTICE_AFTER = 2.0  # KeePassXC answers at once unless one of its own dialogs is open


class NoAnswer(Exception):
    """A channel ended without the user deciding (timed out, could not show); the other channels still can."""


class Desktop:
    """A zenity dialog that can be withdrawn while open."""

    def __init__(self):
        self.proc = None

    @staticmethod
    def available():
        return shutil.which("zenity") is not None

    def ask(self, text, options):
        """Returns the chosen key, None when denied or timed out."""
        keys = [k for k, _ in options]
        caller = context.default_cwd()
        title = f"kpxc-mcp: {os.path.basename(caller.rstrip('/')) or caller}" if caller else "kpxc-mcp"
        if caller:
            text = f"Agent working in {caller}\n\n{text}"
        base = [shutil.which("zenity"), "--no-markup", f"--title={title}", f"--timeout={TIMEOUT}",
                "--cancel-label=Deny", "--icon=dialog-password"]
        if keys == ["once", "always"]:
            # the common case gets three buttons instead of a list to tick
            args = base + ["--question", "--width=560", "--ok-label=Allow once",
                           f"--extra-button={options[1][1]}", f"--text={text}"]
        elif len(options) == 1:
            args = base + ["--question", "--width=560", "--ok-label=Allow",
                           f"--text={text}\n\n{options[0][1]}".rstrip()]
        else:
            args = base + ["--list", "--radiolist", "--width=680", "--height=380", "--ok-label=Allow",
                           f"--text={text}", "--column=", "--column=key", "--column=Entry", "--hide-column=2",
                           "--print-column=2"]
            for i, (key, label) in enumerate(options):
                args += ["TRUE" if i == 0 else "FALSE", key, label]
        self.proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        try:
            out, _ = self.proc.communicate(timeout=TIMEOUT + 5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            raise NoAnswer("desktop prompt timed out")
        out = out.strip()
        if keys == ["once", "always"] and self.proc.returncode == 1 and out == options[1][1]:
            return "always"  # zenity reports an extra button as exit 1 with its label on stdout
        if self.proc.returncode == 1:  # Deny
            return None
        if self.proc.returncode != 0:  # 5 = zenity's own timeout; anything else is a dialog that never showed
            raise NoAnswer(f"zenity exited with {self.proc.returncode}")
        if len(options) == 1 or keys == ["once", "always"]:
            return options[0][0]
        return out if out in set(keys) else None

    def withdraw(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()


def _race(text, options):
    channels = []
    if Desktop.available():
        channels.append(("desktop", Desktop()))
    phone = matrix.Approver.from_config()
    if phone:
        channels.append(("phone", phone))
    if not channels:
        return None

    done = threading.Event()
    lock = threading.Lock()
    answer = {"failed": 0}

    def run(name, channel):
        try:
            key = channel.ask(text, options)
        except Exception:  # NoAnswer or a broken channel; the others still decide
            with lock:
                answer["failed"] += 1
                if answer["failed"] == len(channels):
                    done.set()
            return
        with lock:
            if "by" not in answer:
                answer.update(by=name, key=key)
                done.set()

    threads = [threading.Thread(target=run, args=c, daemon=True) for c in channels]
    for t in threads:
        t.start()
    done.wait(TIMEOUT + 15)
    for name, channel in channels:
        if name != answer.get("by"):
            channel.withdraw()
    return answer.get("key")


def confirm(text):
    """True only on an explicit Allow."""
    return _race(text, [("allow", "")]) == "allow"


def choose(text, options):
    """Pick one of `options` (list of (key, label)); returns the key, or None when denied."""
    return _race(text, options)


@contextlib.contextmanager
def desktop_dialog_notice(text):
    """Tell the phone when KeePassXC keeps a request waiting on one of its own desktop dialogs (unlock, entry
    access). Those cannot be answered from Matrix, so this is a notice, edited with the outcome, not a prompt."""
    phone = matrix.Approver.from_config()
    posted = threading.Event()

    def post():
        try:
            phone.notify(text)
            posted.set()
        except Exception:
            pass  # the notice is best effort; the desktop dialog still decides

    timer = threading.Timer(NOTICE_AFTER, post) if phone else None
    if timer:
        timer.daemon = True
        timer.start()
    outcome = "KeePassXC answered on the desktop."
    try:
        yield
    except TimeoutError:
        outcome = "Nobody answered KeePassXC's dialog; the request gave up."
        raise
    finally:
        if timer:
            timer.cancel()
            timer.join()
            if posted.is_set():
                phone.resolve(outcome)
