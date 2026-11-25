import pytest

from mock_keepassxc import MockKeePassXC


@pytest.fixture(autouse=True)
def no_real_matrix(tmp_path_factory, monkeypatch):
    """Never let a test read ~/.config/kpxc-mcp and post to the user's real approvals room."""
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path_factory.mktemp("config")))


@pytest.fixture
def kpxc(tmp_path, monkeypatch):
    mock = MockKeePassXC()
    monkeypatch.setenv("KPXC_MCP_SOCKET", mock.path)
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    yield mock
    mock.close()


@pytest.fixture
def paired(kpxc):
    from kpxc_mcp.keepassxc import Connection, save_association
    with Connection() as conn:
        save_association(conn.associate())
    return kpxc
