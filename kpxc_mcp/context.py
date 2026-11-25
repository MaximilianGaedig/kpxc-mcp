"""Per-request facts about the agent that called, for transports that serve several agents from one process."""

import threading

_local = threading.local()


def set_caller(cwd):
    _local.cwd = cwd


def default_cwd():
    """The calling agent's working directory, or None (the stdio server runs in the agent's own directory)."""
    return getattr(_local, "cwd", None)
