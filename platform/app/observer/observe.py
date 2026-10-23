"""The observer: views a client site's public homepage like any visitor (DESIGN.md §4.9).

Rule R10. One `GET /`, following at most 3 redirects. Response headers only (the body is never
read), plus the TLS certificate's expiry. No logins, form posts, other paths or crawling.

Because a compromised site could redirect us anywhere, every hop must be http(s), and in prod
must resolve to a public IP address (no loopback, private, link-local or metadata addresses).
"""

import ipaddress
import socket
import ssl
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import urljoin, urlsplit

import httpx

USER_AGENT = "TransFunnel-Protect-Observer/1.0 (+security monitoring by the site's agency)"
MAX_REDIRECTS = 3
TIMEOUT = 10.0


@dataclass(frozen=True)
class ObservationResult:
    final_url: str | None
    http_status: int | None
    server_header: str | None
    powered_by: str | None
    behind_cloudflare: bool | None
    tls_expires_at: datetime | None
    error: str | None = None


class BlockedTarget(Exception):
    pass


Resolver = Callable[[str], list[str]]
# Maps a public URL to (URL to connect to, Host header). Identity outside the Docker demo.
Rewrite = Callable[[str], tuple[str, str | None]]


def _no_rewrite(url: str) -> tuple[str, str | None]:
    return url, None


def _resolve(host: str) -> list[str]:
    return sorted({info[4][0] for info in socket.getaddrinfo(host, None)})


def check_target(url: str, allow_private: bool, resolve: Resolver = _resolve) -> None:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise BlockedTarget(f"not an http(s) URL: {url}")
    if allow_private:
        return
    try:
        addresses = resolve(parts.hostname)
    except OSError as e:
        raise BlockedTarget(f"can't resolve {parts.hostname}") from e
    for addr in addresses:
        if not ipaddress.ip_address(addr).is_global:
            raise BlockedTarget(f"{parts.hostname} resolves to a non-public address")


def tls_expiry(host: str, port: int = 443, timeout: float = TIMEOUT) -> datetime | None:
    context = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls:
            cert = tls.getpeercert()
    not_after = cert.get("notAfter") if cert else None
    if not isinstance(not_after, str):
        return None
    return datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), tz=UTC)


def observe(
    url: str,
    *,
    allow_private: bool = False,
    client: httpx.Client | None = None,
    resolve: Resolver = _resolve,
    get_tls_expiry: Callable[[str, int], datetime | None] = tls_expiry,
    rewrite: Rewrite = _no_rewrite,
) -> ObservationResult:
    own_client = client is None
    client = client or httpx.Client(timeout=TIMEOUT, follow_redirects=False)
    target = url.rstrip("/") + "/"
    try:
        for _ in range(MAX_REDIRECTS + 1):
            connect_url, host = rewrite(target)
            check_target(connect_url, allow_private, resolve)
            headers_out = {"User-Agent": USER_AGENT}
            if host:
                headers_out["Host"] = host
            with client.stream("GET", connect_url, headers=headers_out) as resp:
                headers = resp.headers  # the body is never read
                status = resp.status_code
            location = headers.get("location")
            if status in (301, 302, 303, 307, 308) and location:
                target = urljoin(target, location)
                continue
            break
        else:
            return ObservationResult(target, None, None, None, None, None, "too many redirects")

        server = headers.get("server")
        cloudflare = "cf-ray" in headers or (server or "").lower() == "cloudflare"
        expires, error = None, None
        parts = urlsplit(target)
        if parts.scheme == "https" and parts.hostname:
            try:
                expires = get_tls_expiry(parts.hostname, parts.port or 443)
            except (OSError, ssl.SSLError, ValueError) as e:
                error = f"TLS check failed: {type(e).__name__}"
        return ObservationResult(
            final_url=target,
            http_status=status,
            server_header=(server or None) and server[:200],
            powered_by=(headers.get("x-powered-by") or None) and headers["x-powered-by"][:200],
            behind_cloudflare=cloudflare,
            tls_expires_at=expires,
            error=error,
        )
    except BlockedTarget as e:
        return ObservationResult(target, None, None, None, None, None, f"blocked: {e}")
    except httpx.HTTPError as e:
        return ObservationResult(
            target, None, None, None, None, None, f"request failed: {type(e).__name__}"
        )
    finally:
        if own_client:
            client.close()
