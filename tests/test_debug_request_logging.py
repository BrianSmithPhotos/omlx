# SPDX-License-Identifier: Apache-2.0
"""Tests for the trace-level request body logging middleware."""

import pytest

import asyncio
import json
import logging

from omlx.server import (
    DebugRequestLoggingMiddleware,
    _is_textual_body,
    _redact_sensitive_json,
)

TRACE = 5


class TestIsTextualBody:
    def test_textual_types(self):
        assert _is_textual_body("application/json")
        assert _is_textual_body("application/json; charset=utf-8")
        assert _is_textual_body("application/problem+json")
        assert _is_textual_body("application/x-www-form-urlencoded")
        assert _is_textual_body("text/plain")

    def test_binary_types(self):
        assert not _is_textual_body("multipart/form-data; boundary=xyz")
        assert not _is_textual_body("audio/wav")
        assert not _is_textual_body("video/mp4")
        assert not _is_textual_body("application/octet-stream")
        assert not _is_textual_body("")


def _make_scope(content_type: str) -> dict:
    return {
        "type": "http",
        "method": "POST",
        "path": "/v1/audio/transcriptions",
        "headers": [
            (b"content-type", content_type.encode("latin-1")),
            (b"content-length", b"12345"),
        ],
    }


def _make_receive(body: bytes):
    messages = [{"type": "http.request", "body": body, "more_body": False}]

    async def receive():
        return messages.pop(0)

    return receive


async def _noop_send(message):
    pass


class TestDebugRequestLoggingMiddleware:
    @pytest.mark.asyncio
    async def test_binary_body_not_dumped(self, caplog):
        received = []

        async def inner_app(scope, receive, send):
            message = await receive()
            received.append(message["body"])

        binary = b"\x00\x01RIFFBINARYJUNK\xff\xfe" * 4
        middleware = DebugRequestLoggingMiddleware(inner_app)
        caplog.set_level(TRACE, logger="omlx.server")

        await middleware(
            _make_scope("multipart/form-data; boundary=xyz"),
            _make_receive(binary),
            _noop_send,
        )

        # Body reaches the app untouched (streamed, not re-buffered)
        assert received == [binary]
        logged = "\n".join(r.getMessage() for r in caplog.records)
        assert "bytes omitted" in logged
        assert "multipart/form-data" in logged
        assert "RIFFBINARYJUNK" not in logged

    @pytest.mark.asyncio
    async def test_json_body_still_logged(self, caplog):
        received = []

        async def inner_app(scope, receive, send):
            message = await receive()
            received.append(message["body"])

        body = b'{"model": "whisper", "stream": true}'
        middleware = DebugRequestLoggingMiddleware(inner_app)
        caplog.set_level(TRACE, logger="omlx.server")

        await middleware(
            _make_scope("application/json"),
            _make_receive(body),
            _noop_send,
        )

        assert received == [body]
        logged = "\n".join(r.getMessage() for r in caplog.records)
        assert '"model": "whisper"' in logged


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

    def test_redacts_hf_and_ms_tokens(self):
        data = {"hf_token": "hf_abc123", "ms_token": "ms_xyz789", "repo_id": "org/model"}
        assert _redact_sensitive_json(data) == {
            "hf_token": "***REDACTED***",
            "ms_token": "***REDACTED***",
            "repo_id": "org/model",
        }

    def test_max_tokens_not_redacted(self):
        # max_tokens/budget_tokens etc. are token *counts*, not credentials —
        # the exact-match redaction list must not treat "token" as a substring.
        data = {"max_tokens": 512, "budget_tokens": 128}
        assert _redact_sensitive_json(data) == data


class TestRedactionMiddleware:
    def _run(
        self,
        body: bytes,
        *,
        method="POST",
        enabled=True,
        content_type="application/json",
    ):
        async def inner_app(scope, receive, send):
            await receive()

        middleware = DebugRequestLoggingMiddleware(inner_app)
        scope = {
            "type": "http",
            "method": method,
            "path": "/admin/api/login",
            "headers": [(b"content-type", content_type.encode("latin-1"))],
        }

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
        records = self._run(b"not json at all", content_type="text/plain")
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
