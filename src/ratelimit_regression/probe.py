from __future__ import annotations

import argparse
import ipaddress
import json
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener


MAX_ATTEMPTS = 8


def require_loopback(url: str) -> str:
    parsed = urlsplit(url)
    host = (parsed.hostname or "").lower()
    try:
        address = ipaddress.ip_address(host)
    except ValueError as error:
        raise ValueError("a literal loopback IP address is required") from error
    if parsed.scheme != "http" or not address.is_loopback:
        raise ValueError("only HTTP loopback IP addresses are accepted")
    if parsed.username or parsed.password:
        raise ValueError("credentials in URLs are not accepted")
    return url


class NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


def check_rate_limit(url: str, attempts: int = MAX_ATTEMPTS) -> tuple[bool, list[int]]:
    """Send a capped series of synthetic requests; report first 429 position."""
    require_loopback(url)
    if not 1 <= attempts <= MAX_ATTEMPTS:
        raise ValueError(f"attempts must be between 1 and {MAX_ATTEMPTS}")
    statuses: list[int] = []
    blocked_at: int | None = None
    opener = build_opener(ProxyHandler({}), NoRedirectHandler)
    for index in range(1, attempts + 1):
        request = Request(
            url,
            data=json.dumps({"token": "fixture-invalid", "password": "fixture-invalid"}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with opener.open(request, timeout=2) as response:
                status = response.status
                retry_after = response.headers.get("Retry-After")
        except HTTPError as error:
            status = error.code
            retry_after = error.headers.get("Retry-After")
            error.close()
        statuses.append(status)
        if status == 429:
            blocked_at = index
            if not retry_after or not retry_after.isdigit():
                return False, statuses
            break
        if status not in {400, 401, 403, 422}:
            return False, statuses
        time.sleep(0.01)
    return blocked_at is not None, statuses


def main() -> int:
    parser = argparse.ArgumentParser(description="Capped local rate-limit regression check")
    parser.add_argument("url", help="local fixture endpoint, e.g. http://127.0.0.1:8765/activate")
    parser.add_argument("--attempts", type=int, default=MAX_ATTEMPTS, choices=range(1, MAX_ATTEMPTS + 1))
    args = parser.parse_args()
    try:
        passed, statuses = check_rate_limit(args.url, args.attempts)
    except (ValueError, URLError, TimeoutError, OSError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    blocked = statuses.index(429) + 1 if 429 in statuses else None
    print(json.dumps({"result": "PASS" if passed else "FAIL", "attempts_sent": len(statuses), "blocked_at": blocked, "http_statuses": statuses}, sort_keys=True))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
