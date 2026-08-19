from __future__ import annotations

import asyncio
import json
import urllib.error
import urllib.request
from dataclasses import dataclass


@dataclass(frozen=True)
class TrafficDelta:
    upload: int
    download: int


class HysteriaStatsClient:
    def __init__(self, base_url: str, secret: str, timeout: float = 5.0):
        self.base_url = base_url.rstrip("/")
        self.headers = {"Authorization": secret}
        self.timeout = timeout

    def _request_sync(self, path: str, method: str = "GET", body: bytes | None = None):
        headers = dict(self.headers)
        if body is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            f"{self.base_url}{path}",
            headers=headers,
            data=body,
            method=method,
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                payload = response.read().decode("utf-8")
                return json.loads(payload) if payload.strip() else {}
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Stats API HTTP {exc.code}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Stats API connection failed: {exc}") from exc

    async def _get_json(self, path: str):
        return await asyncio.to_thread(self._request_sync, path)

    async def get_traffic(self, clear: bool = False) -> dict[str, TrafficDelta]:
        suffix = "?clear=1" if clear else ""
        payload = await self._get_json(f"/traffic{suffix}")
        result: dict[str, TrafficDelta] = {}
        for key_id, item in payload.items():
            result[str(key_id)] = TrafficDelta(
                upload=max(0, int(item.get("tx", 0))),
                download=max(0, int(item.get("rx", 0))),
            )
        return result

    async def get_online(self) -> dict[str, int]:
        payload = await self._get_json("/online")
        return {str(key_id): max(0, int(count)) for key_id, count in payload.items()}

    async def kick(self, key_ids: list[str]) -> None:
        """Disconnect the given keys via the Traffic Stats API.

        Used when a traffic quota is reached: /auth blocks the next handshake,
        but an already established session has to be torn down explicitly.
        """
        if not key_ids:
            return
        body = json.dumps(list(key_ids)).encode("utf-8")
        await asyncio.to_thread(self._request_sync, "/kick", "POST", body)

    async def poll(self) -> tuple[dict[str, TrafficDelta], dict[str, int]]:
        traffic = await self.get_traffic(clear=True)
        online = await self.get_online()
        return traffic, online
