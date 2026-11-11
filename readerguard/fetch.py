"""Careful URL fetching: http(s) only, size and time limits, manual redirects, and an SSRF guard that refuses
private, loopback, link-local and reserved addresses on every hop (so a public URL cannot bounce the scanner
into your internal network)."""
from __future__ import annotations

import ipaddress
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

from .findings import Finding

UA = "readerguard/0.2 (+document safety scanner)"


@dataclass
class FetchOptions:
    timeout: float = 15.0
    max_bytes: int = 25_000_000
    max_redirects: int = 5
    allow_private: bool = False
    fetch_resources: bool = True       # linked CSS and scripts of HTML pages
    max_resource_bytes: int = 2_000_000
    user_agent: str = UA


@dataclass
class Fetched:
    url: str
    final_url: str
    status: int
    content_type: str
    headers: dict
    body: bytes
    findings: list = field(default_factory=list)


class FetchError(Exception):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def _check_host(url: str, allow_private: bool) -> None:
    u = urlparse(url)
    if u.scheme not in ("http", "https"):
        raise FetchError(f"unsupported URL scheme '{u.scheme}'")
    if not u.hostname:
        raise FetchError("URL has no host")
    if allow_private:
        return
    try:
        infos = socket.getaddrinfo(u.hostname, u.port or (443 if u.scheme == "https" else 80))
    except socket.gaierror as e:
        raise FetchError(f"cannot resolve host {u.hostname}: {e}") from None
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
            raise FetchError(f"refusing to fetch {u.hostname}: resolves to non-public address {ip}")


def _get(url: str, opt: FetchOptions, limit: int, accept: str = "*/*"):
    req = urllib.request.Request(url, headers={"User-Agent": opt.user_agent, "Accept": accept})
    try:
        resp = _OPENER.open(req, timeout=opt.timeout)
    except urllib.error.HTTPError as e:
        resp = e                      # 3xx (redirect not followed) and 4xx/5xx land here
    body = resp.read(limit + 1) if resp.status < 300 else b""
    if len(body) > limit:
        raise FetchError(f"response exceeds the {limit // 1_000_000} MB limit")
    return resp.status, dict(resp.headers), body


def fetch(url: str, opt: FetchOptions | None = None) -> Fetched:
    opt = opt or FetchOptions()
    findings, cur, hops = [], url, 0
    while True:
        _check_host(cur, opt.allow_private)
        status, headers, body = _get(cur, opt, opt.max_bytes)
        if status in (301, 302, 303, 307, 308):
            loc = headers.get("Location") or headers.get("location")
            if not loc:
                raise FetchError(f"redirect without Location from {cur}")
            nxt = urljoin(cur, loc)
            if urlparse(nxt).hostname != urlparse(cur).hostname:
                findings.append(Finding(check="redirect", severity="info", text=nxt,
                                        message=f"redirected from {urlparse(cur).hostname} to {urlparse(nxt).hostname}"))
            if urlparse(cur).scheme == "https" and urlparse(nxt).scheme == "http":
                findings.append(Finding(check="insecure_transport", severity="low", text=nxt,
                                        message="redirect downgrades HTTPS to HTTP"))
            cur, hops = nxt, hops + 1
            if hops > opt.max_redirects:
                raise FetchError("too many redirects")
            continue
        if status >= 400:
            raise FetchError(f"HTTP {status} from {cur}")
        break
    if urlparse(cur).scheme == "http":
        findings.append(Finding(check="insecure_transport", severity="low", message="content served over plain HTTP"))
    ctype = (headers.get("Content-Type") or headers.get("content-type") or "").split(";")[0].strip().lower()
    return Fetched(url=url, final_url=cur, status=status, content_type=ctype, headers=headers, body=body,
                   findings=findings)


def resource_fetcher(opt: FetchOptions):
    """fn(url, kind) -> bytes | None, used by the HTML analyzer for linked CSS and scripts. Never raises."""
    def get(url: str, kind: str):
        try:
            _check_host(url, opt.allow_private)
            status, _, body = _get(url, opt, opt.max_resource_bytes)
            return body if status < 300 else None
        except Exception:
            return None
    return get
