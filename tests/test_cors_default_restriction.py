# SPDX-License-Identifier: Apache-2.0
"""Tests for restricting default CORS to private-network origins (jundot/omlx#928)."""

from omlx.server import _cors_allow_origin_kwargs, _PRIVATE_NETWORK_ORIGIN_REGEX


class TestCorsAllowOriginKwargs:
    def test_default_wildcard_uses_private_network_regex(self):
        kwargs = _cors_allow_origin_kwargs(["*"])
        assert kwargs == {"allow_origin_regex": _PRIVATE_NETWORK_ORIGIN_REGEX.pattern}

    def test_explicit_origins_are_honored_as_is(self):
        origins = ["https://example.com"]
        kwargs = _cors_allow_origin_kwargs(origins)
        assert kwargs == {"allow_origins": origins}

    def test_explicit_empty_list_is_honored_as_is(self):
        kwargs = _cors_allow_origin_kwargs([])
        assert kwargs == {"allow_origins": []}


class TestPrivateNetworkOriginRegex:
    def _match(self, origin: str) -> bool:
        return _PRIVATE_NETWORK_ORIGIN_REGEX.match(origin) is not None

    def test_matches_localhost(self):
        assert self._match("http://localhost")
        assert self._match("http://localhost:8000")
        assert self._match("https://localhost:3000")

    def test_matches_loopback_ipv4(self):
        assert self._match("http://127.0.0.1")
        assert self._match("http://127.0.0.1:8000")

    def test_matches_loopback_ipv6(self):
        assert self._match("http://[::1]:8000")

    def test_matches_rfc1918_ranges(self):
        assert self._match("http://10.0.0.5:8000")
        assert self._match("http://172.16.0.5:8000")
        assert self._match("http://172.31.255.255:8000")
        assert self._match("http://192.168.1.100:8000")

    def test_matches_link_local(self):
        assert self._match("http://169.254.1.1:8000")

    def test_rejects_public_origins(self):
        assert not self._match("https://example.com")
        assert not self._match("https://evil.example.com")
        assert not self._match("http://8.8.8.8")

    def test_rejects_out_of_range_private_lookalikes(self):
        # 172.15.x.x and 172.32.x.x are outside the 172.16.0.0/12 block.
        assert not self._match("http://172.15.0.1:8000")
        assert not self._match("http://172.32.0.1:8000")

    def test_rejects_subdomain_of_localhost(self):
        assert not self._match("http://localhost.evil.com")
