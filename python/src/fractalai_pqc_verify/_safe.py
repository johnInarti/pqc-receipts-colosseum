"""Hardening helpers shared by the verifier (red-team 2026-10-06).

* :func:`strict_json_loads` -- RFC 8259 JSON only: rejects ``NaN`` / ``Infinity`` / ``-Infinity`` (Python's
  ``json`` accepts them, ``JSON.parse`` does not) and turns ``RecursionError`` into ``ValueError`` so a
  deeply nested input is a rejection, never a crash.
* :func:`https_get_json` -- HTTPS GET that refuses any redirect leaving ``https://``, caps the body size and
  requires a JSON content type.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

__all__ = ["MAX_JSON_BYTES", "strict_json_loads", "https_get_json"]

MAX_JSON_BYTES = 2 * 1024 * 1024  # a key directory / receipt is a few KB; 2 MiB is generous


def _reject_constant(name: str) -> Any:
    raise ValueError(f"non-JSON constant {name} (RFC 8259 forbids NaN/Infinity)")


def strict_json_loads(text: str | bytes) -> Any:
    try:
        return json.loads(text, parse_constant=_reject_constant)
    except RecursionError as e:
        raise ValueError("JSON nesting too deep") from e


class _HttpsOnlyRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        if not newurl.lower().startswith("https://"):
            raise urllib.error.URLError(f"refusing redirect from {req.full_url} to non-HTTPS {newurl}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def https_get_json(url: str, *, user_agent: str, timeout: float, max_bytes: int = MAX_JSON_BYTES) -> tuple[Any, str]:
    """Return ``(parsed_json, final_url)``. Raises ``ValueError`` / ``OSError`` on any policy violation."""
    if not url.lower().startswith("https://"):
        raise ValueError("refusing non-HTTPS URL")
    opener = urllib.request.build_opener(_HttpsOnlyRedirect)
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": user_agent})
    with opener.open(req, timeout=timeout) as resp:  # noqa: S310 (https enforced, redirects too)
        final = resp.geturl()
        if not final.lower().startswith("https://"):
            raise ValueError(f"final URL is not HTTPS: {final}")
        ctype = (resp.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if ctype and ctype != "application/json" and not ctype.endswith("+json"):
            raise ValueError(f"unexpected Content-Type {ctype!r} (want application/json)")
        body = resp.read(max_bytes + 1)
        if len(body) > max_bytes:
            raise ValueError(f"response larger than {max_bytes} bytes")
    return strict_json_loads(body.decode("utf-8")), final
