# SPDX-License-Identifier: Apache-2.0
"""Tests for TRACE-level request body logging redaction (jundot/omlx#931)."""

import asyncio
import json
import logging

from omlx.server import DebugRequestLoggingMiddleware, _redact_sensitive_json


class TestRedactSensitiveJson:
    def test_redacts_known_keys(self):
        data = {"api_key": "sk-secret", "name": "my key"}
        assert _redact_sensitive_json(data) == {
            "api_key": "***REDACTED***",
            "name": "my key",
        }

    def test_redacts_nested_and_case_insensitive(self):
        data = {"outer": {"Password": "hunter2", "keep": "me"}}
        assert _redact_sensitive_json(data) == {
            "outer": {"Password": "***REDACTED***", "keep": "me"}
        }

    def test_redacts_within_lists(self):
        data = [{"token": "abc"}, {"messages": "hi"}]
        assert _redact_sensitive_json(data) == [
            {"token": "***REDACTED***"},
            {"messages": "hi"},
        ]

    def test_non_sensitive_body_untouched(self):
        data = {"messages": [{"role": "user", "content": "hello"}]}
        assert _redact_sensitive_json(data) == data


class TestDebugRequestLoggingMiddleware:
    def _run(self, body: bytes, *, method="POST", enabled=True):
        async def inner_app(scope, receive, send):
            await receive()

        middleware = DebugRequestLoggingMiddleware(inner_app)
        scope = {"type": "http", "method": method, "path": "/admin/api/login"}

        sent = {"more": True}

        async def receive():
            if sent["more"]:
                sent["more"] = False
                return {"type": "http.request", "body": body, "more_body": False}
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message):
            pass

        logger = logging.getLogger("omlx.server")
        original_level = logger.level
        logger.setLevel(5 if enabled else logging.INFO)
        try:
            records = []
            handler = logging.Handler()
            handler.emit = lambda record: records.append(record)
            logger.addHandler(handler)
            try:
                asyncio.run(middleware(scope, receive, send))
            finally:
                logger.removeHandler(handler)
        finally:
            logger.setLevel(original_level)
        return records

    def test_redacts_api_key_in_login_body(self):
        body = json.dumps({"api_key": "sk-super-secret"}).encode()
        records = self._run(body)
        assert len(records) == 1
        message = records[0].getMessage()
        assert "sk-super-secret" not in message
        assert "***REDACTED***" in message

    def test_non_json_body_still_logged_without_crashing(self):
        records = self._run(b"not json at all")
        assert len(records) == 1
        assert "not json at all" in records[0].getMessage()

    def test_non_post_requests_are_skipped(self):
        records = self._run(json.dumps({"api_key": "secret"}).encode(), method="GET")
        assert records == []

    def test_disabled_log_level_skips_logging(self):
        records = self._run(
            json.dumps({"api_key": "secret"}).encode(), enabled=False
        )
        assert records == []
