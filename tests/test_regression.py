from __future__ import annotations

import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from ratelimit_regression.fixture import Handler
from ratelimit_regression.probe import check_rate_limit, require_loopback
from ratelimit_regression.policy import SlidingWindowLimiter


class LimiterTests(unittest.TestCase):
    def test_blocks_at_limit_and_recovers_after_window(self) -> None:
        limiter = SlidingWindowLimiter(limit=2, window_seconds=5)
        self.assertTrue(limiter.check("fixture-user", now=10).allowed)
        self.assertTrue(limiter.check("fixture-user", now=11).allowed)
        blocked = limiter.check("fixture-user", now=12)
        self.assertFalse(blocked.allowed)
        self.assertGreaterEqual(blocked.retry_after, 1)
        self.assertTrue(limiter.check("fixture-user", now=16).allowed)

    def test_identity_buckets_are_independent(self) -> None:
        limiter = SlidingWindowLimiter(limit=1, window_seconds=5)
        self.assertTrue(limiter.check("one", now=1).allowed)
        self.assertFalse(limiter.check("one", now=1).allowed)
        self.assertTrue(limiter.check("two", now=1).allowed)

    def test_rejects_non_loopback_targets(self) -> None:
        for url in (
            "https://127.0.0.1/x",
            "http://example.com/x",
            "http://localhost/x",
            "http://192.168.1.2/x",
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                require_loopback(url)

    def test_rejects_credentials_and_attempts_above_cap(self) -> None:
        for url in ("http://user:pass@127.0.0.1/x", "http://localhost.attacker.test/x"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                require_loopback(url)
        with self.assertRaises(ValueError):
            check_rate_limit("http://127.0.0.1/x", attempts=9)

    def test_fixed_fixture_passes_and_vulnerable_fixture_fails(self) -> None:
        Handler.limiter = SlidingWindowLimiter(limit=3, window_seconds=5)
        Handler.vulnerable = False
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        url = f"http://127.0.0.1:{server.server_port}/activate"
        try:
            passed, statuses = check_rate_limit(url)
            self.assertTrue(passed)
            self.assertEqual(statuses, [401, 401, 401, 429])
            Handler.limiter = SlidingWindowLimiter(limit=3, window_seconds=5)
            Handler.vulnerable = True
            failed, vulnerable_statuses = check_rate_limit(url)
            self.assertFalse(failed)
            self.assertEqual(vulnerable_statuses, [401] * 8)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_redirect_is_not_followed(self) -> None:
        destination_hits: list[bool] = []

        class DestinationHandler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                destination_hits.append(True)
                self.send_response(401)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, format: str, *args: object) -> None:
                return

        destination = ThreadingHTTPServer(("127.0.0.1", 0), DestinationHandler)
        destination_thread = threading.Thread(target=destination.serve_forever, daemon=True)
        destination_thread.start()

        class RedirectHandler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                self.send_response(302)
                self.send_header("Location", f"http://127.0.0.1:{destination.server_port}/activate")
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, format: str, *args: object) -> None:
                return

        redirect = ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
        redirect_thread = threading.Thread(target=redirect.serve_forever, daemon=True)
        redirect_thread.start()
        try:
            passed, statuses = check_rate_limit(f"http://127.0.0.1:{redirect.server_port}/activate", attempts=1)
            self.assertFalse(passed)
            self.assertEqual(statuses, [302])
            self.assertEqual(destination_hits, [])
        finally:
            redirect.shutdown()
            redirect.server_close()
            redirect_thread.join(timeout=2)
            destination.shutdown()
            destination.server_close()
            destination_thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
