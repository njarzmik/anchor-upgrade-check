import io
import json
import urllib.error

import pytest

from anchor_upgrade_check.rpc import DEFAULT_URL, URL_ENV, Rpc, RpcError


class Script:
    """Stands in for urlopen: each call pops the next scripted reply or exception."""

    def __init__(self, *steps) -> None:
        self.steps = list(steps)
        self.calls = 0

    def __call__(self, req, timeout=None):
        self.calls += 1
        step = self.steps.pop(0)
        if isinstance(step, Exception):
            raise step
        return io.BytesIO(json.dumps(step).encode())


@pytest.fixture
def sleeps(monkeypatch) -> list[float]:
    log: list[float] = []
    monkeypatch.setattr("anchor_upgrade_check.rpc.time.sleep", log.append)
    return log


def http_error(code: int, headers: dict | None = None) -> urllib.error.HTTPError:
    return urllib.error.HTTPError("http://x", code, "err", headers or {}, None)


def test_retry_after_is_honoured(monkeypatch, sleeps) -> None:
    script = Script(http_error(429, {"Retry-After": "2"}), {"jsonrpc": "2.0", "id": 1, "result": 7})
    monkeypatch.setattr("urllib.request.urlopen", script)
    assert Rpc("http://127.0.0.1:8899").call("getSlot", []) == 7
    assert sleeps == [2.0] and script.calls == 2


def test_errors_never_carry_the_url(monkeypatch, sleeps) -> None:
    secret_url = "https://rpc.invalid/?api-key=SECRET123"
    script = Script(urllib.error.URLError(f"cannot reach {secret_url}"), urllib.error.URLError(secret_url))
    monkeypatch.setattr("urllib.request.urlopen", script)
    with pytest.raises(RpcError) as e:
        Rpc(secret_url, tries=2).call("getSlot", [])
    assert "SECRET123" not in str(e.value)


def test_non_retryable_errors_stop_at_once(monkeypatch, sleeps) -> None:
    script = Script({"jsonrpc": "2.0", "id": 1, "error": {"code": -32602, "message": "invalid params"}})
    monkeypatch.setattr("urllib.request.urlopen", script)
    with pytest.raises(RpcError, match="-32602"):
        Rpc("http://127.0.0.1:8899").call("getAccountInfo", [])
    script = Script(http_error(403))
    monkeypatch.setattr("urllib.request.urlopen", script)
    with pytest.raises(RpcError, match="HTTP 403"):
        Rpc("http://127.0.0.1:8899").call("getAccountInfo", [])
    assert script.calls == 1 and sleeps == []


def test_endpoint_choice(monkeypatch) -> None:
    monkeypatch.delenv(URL_ENV, raising=False)
    assert Rpc().url == DEFAULT_URL
    monkeypatch.setenv(URL_ENV, "http://127.0.0.1:8899")
    assert Rpc().url == "http://127.0.0.1:8899"
    assert Rpc("http://127.0.0.1:9000").url == "http://127.0.0.1:9000"
