"""URL validation and path/method guard tests (no network)."""
from __future__ import annotations

import pytest

from ragsec.config import Settings
from ragsec.netguard import (
    UrlPolicyError, assert_in_allowlist, assert_safe_path, validate_loopback_url,
)
from ragsec.llm.ollama import RUNTIME_ALLOWLIST

ACCEPTED = [
    ("http://127.0.0.1:11434", "127.0.0.1", 11434),
    ("http://127.0.0.1", "127.0.0.1", 11434),
    ("http://localhost:11434", "127.0.0.1", 11434),   # normalized to 127.0.0.1
    ("http://localhost", "127.0.0.1", 11434),
    ("http://127.0.0.1:1", "127.0.0.1", 1),
    ("http://127.0.0.1:65535/", "127.0.0.1", 65535),
]

REJECTED = [
    "http://0.0.0.0:11434",                 # wildcard
    "http://192.168.1.10:11434",            # LAN
    "http://8.8.8.8:11434",                 # public
    "http://example.com:11434",             # external domain
    "http://[::1]:11434",                   # IPv6 loopback
    "http://127.0.0.2:11434",               # other loopback
    "http://localhost.example.com:11434",   # lookalike host
    "http://user:pass@127.0.0.1:11434",     # userinfo
    "http://127.0.0.1:11434/?x=1",          # query string
    "http://127.0.0.1:11434/#frag",         # fragment
    "http://127.0.0.1:11434/api",           # non-root path
    "https://127.0.0.1:11434",              # scheme not allowed
    "ftp://127.0.0.1:11434",                # scheme not allowed
    "http://2130706433:11434",              # integer IP for 127.0.0.1
    "http://0x7f000001:11434",              # hex IP
    "http://127.1:11434",                   # abbreviated IP
    "http://127.0.0.1:0",                   # port out of range
    "http://127.0.0.1:99999",               # port out of range
    "http://127.0.0.1:11434\n",             # control character
    "  http://127.0.0.1:11434",             # leading whitespace
    "127.0.0.1:11434",                      # no scheme
    "http://localhost:11434@evil.com",      # ambiguous / userinfo-like
]


@pytest.mark.parametrize("url,host,port", ACCEPTED)
def test_accepted_urls(url, host, port):
    conn = validate_loopback_url(url)
    assert conn.host == host and conn.port == port
    assert conn.base_url == f"http://{host}:{port}"


@pytest.mark.parametrize("url", REJECTED)
def test_rejected_urls(url):
    with pytest.raises(UrlPolicyError):
        validate_loopback_url(url)


@pytest.mark.parametrize("url", REJECTED)
def test_settings_rejects_bad_url_preventing_startup(url):
    # Settings construction must FAIL (not warn) on an invalid Ollama URL.
    with pytest.raises(Exception):
        Settings(ollama_url=url, api_key="x" * 8)


def test_settings_normalizes_localhost():
    s = Settings(ollama_url="http://localhost:11434", api_key="x" * 8)
    assert s.ollama_url == "http://127.0.0.1:11434"


def test_safe_path_accepts_allowed():
    for p in ("/api/chat", "/api/embed", "/api/generate", "/api/ps"):
        assert_safe_path(p)


@pytest.mark.parametrize("path", [
    "/api/chat?x=1",            # query
    "/api/../api/pull",         # dot segment
    "/api/chat/../pull",        # dot segment
    "http://127.0.0.1/api/chat",  # absolute URL
    "//evil/api/chat",          # network-path reference
    "/api/chat%2f..%2fpull",    # encoded
    "/api/chat\n",              # control char
    "/api/pull/blobs",          # two segments (not /api/<name>)
])
def test_safe_path_rejects_bypasses(path):
    with pytest.raises(UrlPolicyError):
        assert_safe_path(path)


def test_allowlist_rejects_admin_and_wrong_method():
    assert_in_allowlist("POST", "/api/chat", RUNTIME_ALLOWLIST)  # ok
    for method, path in [("POST", "/api/pull"), ("POST", "/api/create"), ("POST", "/api/push"),
                         ("POST", "/api/delete"), ("POST", "/api/copy"), ("GET", "/api/chat"),
                         ("GET", "/api/tags"), ("POST", "/api/show")]:
        with pytest.raises(UrlPolicyError):
            assert_in_allowlist(method, path, RUNTIME_ALLOWLIST)
