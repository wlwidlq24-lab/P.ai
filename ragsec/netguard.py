"""Loopback-only URL validation and request-path/method guards for all Ollama communication.

This is application-level attack-surface reduction, NOT a patch for any Ollama CVE. It constrains what
*this application* may send; it cannot change what the Ollama server binds to or accepts (see README §Security).

Policy (deliberately narrow):
  * scheme: exactly "http"
  * host:   exactly "127.0.0.1" or "localhost" (localhost is normalized to 127.0.0.1)
  * port:   1..65535 (default 11434); only from trusted server-side settings, never user input
  * path:   empty or "/"
  * rejected: userinfo, query, fragment, control chars, IPv6 (incl. ::1), other loopbacks (127.0.0.2),
             lookalike hosts (localhost.example.com), integer/hex/abbreviated IPs, 0.0.0.0, LAN/public.
Comparisons are exact on the parsed host; never substring/prefix matching.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

ALLOWED_SCHEMES = ("http",)
ALLOWED_HOSTS = ("127.0.0.1", "localhost")
NORMALIZED_HOST = "127.0.0.1"
DEFAULT_PORT = 11434
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
# A conservative shape for the whole URL: scheme://host[:port][/]. No query/fragment/userinfo/path-beyond-slash.
_URL_SHAPE = re.compile(r"^http://(?:127\.0\.0\.1|localhost)(?::\d{1,5})?/?$")


class UrlPolicyError(ValueError):
    """Raised when a URL violates the loopback-only policy. Must prevent startup, not warn."""


@dataclass(frozen=True)
class OllamaConnection:
    """Immutable, validated connection target. Request-time code re-checks against this."""
    scheme: str
    host: str   # normalized (127.0.0.1)
    port: int

    @property
    def base_url(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}"

    @property
    def expected_netloc(self) -> str:
        return f"{self.host}:{self.port}"


def validate_loopback_url(url: str) -> OllamaConnection:
    if not isinstance(url, str) or not url:
        raise UrlPolicyError("ollama url must be a non-empty string")
    if url != url.strip():
        raise UrlPolicyError("ollama url has leading/trailing whitespace")
    if _CONTROL.search(url):
        raise UrlPolicyError("ollama url contains control characters")
    try:
        parts = urlsplit(url)
    except ValueError as e:
        raise UrlPolicyError(f"ollama url is unparseable: {e}") from e

    if parts.scheme not in ALLOWED_SCHEMES:
        raise UrlPolicyError(f"scheme must be one of {ALLOWED_SCHEMES}, got {parts.scheme!r}")
    if parts.username is not None or parts.password is not None:
        raise UrlPolicyError("ollama url must not contain user information")
    if parts.query:
        raise UrlPolicyError("ollama url must not contain a query string")
    if parts.fragment:
        raise UrlPolicyError("ollama url must not contain a fragment")
    if parts.path not in ("", "/"):
        raise UrlPolicyError(f"ollama url path must be empty or '/', got {parts.path!r}")

    # hostname (urlsplit lowercases and strips brackets for IPv6); require an exact allowed host.
    host = parts.hostname
    if host is None:
        raise UrlPolicyError("ollama url has no host")
    # Reject IPv6 explicitly (incl. ::1): bracketed form sets hostname to the inner address.
    if ":" in host or url.count("[") or url.count("]"):
        raise UrlPolicyError("IPv6 addresses (including ::1) are rejected under the loopback-only policy")
    if host not in ALLOWED_HOSTS:
        # Catch integer/hex/abbreviated IPs and other loopbacks with a clear message.
        try:
            ip = ipaddress.ip_address(host)
            reason = f"IP {ip} is not the exact string 127.0.0.1"
        except ValueError:
            reason = "host is not exactly '127.0.0.1' or 'localhost'"
        raise UrlPolicyError(f"host {host!r} rejected: {reason}")

    # Port: urlsplit raises on non-numeric/out-of-range via the .port property.
    try:
        port = parts.port
    except ValueError as e:
        raise UrlPolicyError(f"invalid port: {e}") from e
    port = DEFAULT_PORT if port is None else port
    if not (1 <= port <= 65535):
        raise UrlPolicyError(f"port {port} out of range 1..65535")

    # Final defense-in-depth: the whole string must match the strict shape (no parser-ambiguous residue).
    if not _URL_SHAPE.match(url):
        raise UrlPolicyError(f"ollama url {url!r} does not match the strict loopback shape")

    return OllamaConnection(scheme=parts.scheme, host=NORMALIZED_HOST, port=port)


# -------------------------- request path / method guards --------------------------
_SAFE_PATH = re.compile(r"^/api/[a-z]+$")


def assert_safe_path(path: str) -> None:
    """Reject absolute URLs, network-path refs, query strings, dot segments, encoded bypasses."""
    if not isinstance(path, str) or not path:
        raise UrlPolicyError("request path must be a non-empty string")
    if _CONTROL.search(path):
        raise UrlPolicyError("request path contains control characters")
    if "://" in path or path.startswith("//"):
        raise UrlPolicyError(f"absolute URL / network-path reference not allowed: {path!r}")
    if "?" in path or "#" in path:
        raise UrlPolicyError(f"query string / fragment not allowed in path: {path!r}")
    if "%" in path:
        raise UrlPolicyError(f"percent-encoding not allowed in path: {path!r}")
    if "." in path or "\\" in path:  # blocks dot-segments (/../) and backslash tricks; our paths have no dots
        raise UrlPolicyError(f"dot segments / backslashes not allowed in path: {path!r}")
    if not _SAFE_PATH.match(path):
        raise UrlPolicyError(f"path {path!r} is not a simple /api/<name> path")


def assert_in_allowlist(method: str, path: str, allowlist: frozenset[tuple[str, str]]) -> None:
    assert_safe_path(path)
    if (method, path) not in allowlist:
        raise UrlPolicyError(f"method/path {method} {path} is not in the endpoint allowlist")
