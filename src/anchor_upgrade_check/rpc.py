"""A small JSON-RPC client over urllib.

The endpoint is the public mainnet RPC unless SOLANA_RPC_URL or --rpc names another. The URL is
never printed or put in an error message, because many providers carry the API key in it.
"""

import json
import os
import random
import time
import urllib.error
import urllib.request
from typing import Any, Protocol

DEFAULT_URL = "https://api.mainnet-beta.solana.com"
URL_ENV = "SOLANA_RPC_URL"
_RETRY_HTTP = {429, 500, 502, 503, 504}
_RETRY_RPC = {429, -32005, -32429}  # rate limited / node behind


class RpcError(RuntimeError):
    """The call did not return a result. Callers treat this as 'no verdict', never as 'no change'."""


class RpcClient(Protocol):
    def call(self, method: str, params: list[Any]) -> Any: ...


class Rpc:
    def __init__(self, url: str | None = None, *, timeout: float = 20.0, tries: int = 6) -> None:
        self.url = url or os.environ.get(URL_ENV) or DEFAULT_URL
        self.timeout = timeout
        self.tries = tries

    def _pause(self, attempt: int, retry_after: str | None) -> None:
        """Honour Retry-After when the server sends one; otherwise back off with jitter."""
        try:
            wait = min(60.0, float(retry_after)) if retry_after else None
        except ValueError:
            wait = None
        if wait is None:
            wait = min(20.0, 1.5 * (attempt + 1)) * random.uniform(0.5, 1.5)
        time.sleep(wait)

    def call(self, method: str, params: list[Any]) -> Any:
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
        headers = {"Content-Type": "application/json", "User-Agent": "anchor-upgrade-check"}
        last = "no attempt"
        for attempt in range(self.tries):
            retry_after = None
            try:
                req = urllib.request.Request(self.url, body, headers)
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    reply = json.load(resp)
            except urllib.error.HTTPError as e:
                last = f"HTTP {e.code}"
                if e.code not in _RETRY_HTTP:
                    raise RpcError(f"{method}: {last}") from None
                retry_after = e.headers.get("Retry-After") if e.headers else None
            except (urllib.error.URLError, OSError, ValueError) as e:
                last = type(e).__name__  # the message may contain the host; the type name does not
            else:
                err = reply.get("error") if isinstance(reply, dict) else {"message": "reply is not an object"}
                if not err:
                    return reply.get("result")
                code = err.get("code")
                last = f"RPC error {code}: {str(err.get('message'))[:120]}"
                if code not in _RETRY_RPC:
                    raise RpcError(f"{method}: {last}")
            if attempt + 1 < self.tries:
                self._pause(attempt, retry_after)
        raise RpcError(f"{method}: gave up after {self.tries} tries ({last})")
