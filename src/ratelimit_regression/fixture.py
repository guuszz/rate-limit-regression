from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from .policy import SlidingWindowLimiter


class Handler(BaseHTTPRequestHandler):
    limiter = SlidingWindowLimiter(limit=3, window_seconds=5)
    vulnerable = False

    def do_POST(self) -> None:
        if urlsplit(self.path).path != "/activate":
            self.send_error(404)
            return
        length = min(int(self.headers.get("Content-Length", "0")), 2048)
        self.rfile.read(length)
        decision = self.limiter.check(self.client_address[0]) if not self.vulnerable else None
        if decision is not None and not decision.allowed:
            self.send_response(429)
            self.send_header("Retry-After", str(decision.retry_after))
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = b'{"detail":"invalid fixture credentials"}'
        self.send_response(401)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


def main() -> None:
    parser = argparse.ArgumentParser(description="Synthetic loopback activation fixture")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--vulnerable", action="store_true", help="disable the limiter to show a failing fixture")
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("port must be between 1024 and 65535")
    Handler.vulnerable = args.vulnerable
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"fixture={'vulnerable' if args.vulnerable else 'fixed'} url=http://127.0.0.1:{args.port}/activate")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
