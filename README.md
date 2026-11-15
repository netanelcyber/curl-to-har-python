# HTTP requests → HAR (Python)

Capture HTTP requests sent by Python's `requests` library as **HAR 1.2**. No browser, Selenium, proxy, or `curl` is needed.

## Install

```bash
python -m pip install -r requirements.txt
```

## CLI

```bash
python http_to_har.py https://example.org/ -o capture.har
python http_to_har.py https://example.org/api -X POST -H 'Content-Type: application/json' --json '{"hello":"world"}' --include-bodies -o api.har
python http_to_har.py https://example.org/redirect --follow -o redirects.har
```

## Python `requests` API

```python
from http_to_har import HARSession

with HARSession(include_bodies=True) as session:
    session.get("https://example.org/")
    session.post("https://example.org/api", json={"hello": "world"})
    session.save("traffic.har")
```

`HARSession` also captures requests made through `session.send(prepared_request)` and redirect hops. It records methods, URLs, headers, query strings, status codes, optionally bodies, and approximate response-header latency. It **does not** capture browser JavaScript or full DNS/TLS connection timings.

**Privacy:** By default, body contents are omitted, and common credential-bearing headers and query parameters are redacted. `--include-bodies` includes JSON/form data with best-effort secret-field masking; other body types are omitted unless `--include-sensitive` is set. HAR files may still contain confidential data in URLs, headers, or payloads. Do not commit `.har` files or share sensitive captures. Use only with systems you are authorized to test.
