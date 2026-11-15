"""Capture Python requests HTTP exchanges as a sanitized HAR 1.2 file."""

from __future__ import annotations

import argparse
import base64
import json
import re
import weakref
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import requests

_SECRET = re.compile(r"pass(?:word)?|token|secret|api[_-]?key|auth|session|cookie|credential|csrf|client[_-]?secret", re.I)


def _redact_fields(data):
    if isinstance(data, dict):
        return {key: "[REDACTED]" if _SECRET.search(str(key)) else _redact_fields(value)
                for key, value in data.items()}
    if isinstance(data, list):
        return [_redact_fields(value) for value in data]
    return data


def _sanitize_url(url: str, sensitive: bool):
    parts = urlsplit(url)
    query = parse_qsl(parts.query, keep_blank_values=True)
    if not sensitive:
        query = [(key, "[REDACTED]" if _SECRET.search(key) else value)
                 for key, value in query]
    # Remove userinfo even when the URL was written as https://user:pass@host/.
    host = parts.netloc if sensitive else parts.netloc.rsplit("@", 1)[-1]
    clean = urlunsplit((parts.scheme, host, parts.path, urlencode(query), ""))
    return clean, [{"name": key, "value": value} for key, value in query]


def _headers(headers, sensitive: bool):
    return [{"name": key, "value": value if sensitive or not _SECRET.search(key)
             else "[REDACTED]"} for key, value in headers.items()]


def _bytes(value):
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    return None  # Streaming bodies are not consumed or modified.


def _body(data: bytes | None, mime: str, *, include_bodies: bool,
          include_sensitive: bool, max_body_bytes: int):
    body = {"size": len(data) if data is not None else -1, "mimeType": mime}
    if not include_bodies or data is None:
        return body
    if len(data) > max_body_bytes:
        body["comment"] = "Body omitted: exceeds configured maximum"
        return body
    lowered = mime.lower()
    if include_sensitive:
        if any(t in lowered for t in ("text/", "json", "xml", "html", "javascript", "x-www-form-urlencoded")):
            body["text"] = data.decode("utf-8", errors="replace")
        else:
            body["text"] = base64.b64encode(data).decode("ascii")
            body["encoding"] = "base64"
        return body
    if "json" in lowered:
        try:
            body["text"] = json.dumps(_redact_fields(json.loads(data)), ensure_ascii=False)
            return body
        except (ValueError, UnicodeError):
            pass
    if "application/x-www-form-urlencoded" in lowered:
        try:
            values = parse_qsl(data.decode("utf-8"), keep_blank_values=True)
            body["text"] = urlencode([(k, "[REDACTED]" if _SECRET.search(k) else v)
                                       for k, v in values])
            return body
        except UnicodeError:
            pass
    body["comment"] = "Body omitted: content cannot be safely redacted"
    return body


def _version(response):
    raw = getattr(response, "raw", None)
    version = getattr(raw, "version", None)
    return {10: "HTTP/1.0", 11: "HTTP/1.1", 20: "HTTP/2", 30: "HTTP/3"}.get(version, "")


def _entry(response, started, *, include_bodies, include_sensitive, max_body_bytes):
    req = response.request
    url, query = _sanitize_url(req.url, include_sensitive)
    req_mime = req.headers.get("Content-Type", "application/octet-stream")
    res_mime = response.headers.get("Content-Type", "application/octet-stream")
    req_bytes = _bytes(req.body)
    content_bytes = response.__dict__.get("_content")
    if not isinstance(content_bytes, bytes):
        content_bytes = None  # Do not consume streamed responses.
    request_data = {
        "method": req.method, "url": url, "httpVersion": _version(response),
        "cookies": [], "headers": _headers(req.headers, include_sensitive),
        "queryString": query, "headersSize": -1,
        "bodySize": len(req_bytes) if req_bytes is not None else -1,
    }
    if req_bytes is not None:
        post = _body(req_bytes, req_mime, include_bodies=include_bodies,
                     include_sensitive=include_sensitive, max_body_bytes=max_body_bytes)
        request_data["postData"] = {"mimeType": post.pop("mimeType"), **post}
    response_data = {
        "status": response.status_code, "statusText": str(response.reason or ""),
        "httpVersion": _version(response), "cookies": [],
        "headers": _headers(response.headers, include_sensitive),
        "content": _body(content_bytes, res_mime, include_bodies=include_bodies,
                         include_sensitive=include_sensitive, max_body_bytes=max_body_bytes),
        "redirectURL": response.headers.get("Location", ""), "headersSize": -1,
        "bodySize": len(content_bytes) if content_bytes is not None else -1,
    }
    elapsed = max(0.0, round(response.elapsed.total_seconds() * 1000, 3))
    return {
        "startedDateTime": started.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "time": elapsed, "request": request_data, "response": response_data,
        "cache": {},
        "timings": {"blocked": -1, "dns": -1, "connect": -1, "ssl": -1,
                    "send": -1, "wait": elapsed, "receive": -1},
    }


class HARSession(requests.Session):
    """Drop-in requests.Session recording normal requests and direct send() calls."""

    def __init__(self, *, include_bodies=False, include_sensitive=False, max_body_bytes=1048576):
        super().__init__()
        if max_body_bytes < 0:
            raise ValueError("max_body_bytes must be nonnegative")
        self.include_bodies = include_bodies
        self.include_sensitive = include_sensitive
        self.max_body_bytes = max_body_bytes
        self._entries = []
        self._seen = weakref.WeakSet()

    def send(self, request, **kwargs):
        started = datetime.now(timezone.utc)
        response = super().send(request, **kwargs)
        # Parent calls may contain redirects already captured by nested send().
        for index, hop in enumerate([*response.history, response]):
            if hop in self._seen:
                continue
            self._seen.add(hop)
            at = started if index == 0 else datetime.now(timezone.utc) - hop.elapsed
            self._entries.append((at, _entry(
                hop, at, include_bodies=self.include_bodies,
                include_sensitive=self.include_sensitive, max_body_bytes=self.max_body_bytes,
            )))
        return response

    def export(self):
        return {"log": {"version": "1.2", "creator": {"name": "http-to-har", "version": "1.0.0"},
                        "entries": [item for _, item in sorted(self._entries, key=lambda x: x[0])],
                        "comment": "Python requests capture; timings approximate. Browser-only traffic is not recorded."}}

    def save(self, path):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.export(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        return path


def main(argv=None):
    p = argparse.ArgumentParser(description="Capture HTTP requests to HAR 1.2 using Python requests")
    p.add_argument("url", help="HTTP(S) URL")
    p.add_argument("-o", "--output", default="capture.har")
    p.add_argument("-X", "--method", help="HTTP method (default: GET or POST when body provided)")
    p.add_argument("-H", "--header", action="append", default=[], help="Header in 'Name: value' form")
    payload = p.add_mutually_exclusive_group()
    payload.add_argument("--data", help="Raw request body")
    payload.add_argument("--json", dest="json_data", help="JSON request body")
    p.add_argument("--follow", action="store_true", help="Follow redirects and record each hop")
    p.add_argument("--timeout", type=float, default=30)
    p.add_argument("--include-bodies", action="store_true", help="Capture safely redacted JSON/form bodies")
    p.add_argument("--include-sensitive", action="store_true", help="Keep credentials and raw bodies (DO NOT share HAR)")
    args = p.parse_args(argv)
    if urlsplit(args.url).scheme not in ("http", "https"):
        p.error("URL must start with http:// or https://")
    if args.timeout <= 0:
        p.error("--timeout must be positive")
    headers = {}
    for header in args.header:
        if ":" not in header:
            p.error(f"Invalid -H header: {header!r}")
        key, value = header.split(":", 1)
        if not key.strip():
            p.error("Header name cannot be empty")
        headers[key.strip()] = value.strip()
    data = args.data
    if args.json_data is not None:
        try:
            data = json.loads(args.json_data)
        except json.JSONDecodeError as exc:
            p.error(f"Invalid JSON: {exc}")
    method = args.method or ("POST" if data is not None else "GET")
    with HARSession(include_bodies=args.include_bodies, include_sensitive=args.include_sensitive) as session:
        try:
            response = session.request(
                method, args.url, headers=headers, timeout=args.timeout,
                allow_redirects=args.follow,
                **({"json": data} if args.json_data is not None else {"data": data}),
            )
        except requests.RequestException as exc:
            session.save(args.output)
            p.exit(1, f"Request failed: {exc}. Partial HAR saved to {args.output}\n")
        session.save(args.output)
        print(f"Saved {len(session.export()['log']['entries'])} HTTP exchange(s) to {args.output} (status {response.status_code})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
