"""HTTPS-only fetching with explicit host approval.

  * Every URL, including each redirect hop, must be https:// on an approved
    host (exact match), port 443, without credentials.
  * Redirects are followed manually so each hop is validated before any
    connection is made to it; an HTTPS -> HTTP hop is always rejected.
  * Certificates are validated with the system trust store.
  * Timeouts, bounded retries for transient failures, streaming downloads
    with a hard size limit.
  * Query strings are redacted from anything logged or shown (signed CDN
    URLs carry credentials there).
"""

import hashlib
import http.client
import json
import os
import socket
import ssl
import time
import urllib.parse
from dataclasses import dataclass

from wardctl import __version__
from wardctl.errors import FetchError, HostRejected

USER_AGENT = f"wardctl/{__version__} (+Debian)"
MAX_REDIRECTS = 5
CHUNK = 64 * 1024


def redact(url):
    try:
        p = urllib.parse.urlsplit(url)
    except ValueError:
        return "<invalid url>"
    host = p.hostname or ""
    query = "?…" if p.query else ""
    return f"{p.scheme}://{host}{p.path}{query}"


def host_of(url):
    try:
        return (urllib.parse.urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def check_url(url, approved_hosts):
    try:
        p = urllib.parse.urlsplit(url)
        port = p.port
    except ValueError:
        raise HostRejected(f"invalid URL {redact(url)}")
    if p.scheme != "https":
        raise HostRejected(f"refusing non-HTTPS URL {redact(url)}")
    if p.username is not None or p.password is not None:
        raise HostRejected("refusing URL that embeds credentials")
    if port not in (None, 443):
        raise HostRejected(f"refusing non-standard port in {redact(url)}")
    host = (p.hostname or "").lower()
    if host not in {h.lower() for h in approved_hosts}:
        raise HostRejected(
            f"host {host!r} is not an approved download host ({', '.join(sorted(approved_hosts))})",
            hint="If you have verified this host is the vendor's official download/CDN host, pass "
                 "--allow-host HOST to `wardctl add`/`install`, or add it to the app's approved_hosts "
                 "in ~/.wardctl/config.json.")
    return p


@dataclass
class RawResponse:
    status: int
    headers: dict   # lower-case keys
    body: object    # has .read(n) and .close()


class HttpsTransport:
    """The real network transport (http.client + system CA validation)."""

    def __init__(self, timeout=30):
        self.timeout = timeout
        self.context = ssl.create_default_context()

    def open(self, method, url, headers):
        p = urllib.parse.urlsplit(url)
        conn = http.client.HTTPSConnection(p.hostname, 443, timeout=self.timeout, context=self.context)
        path = p.path or "/"
        if p.query:
            path += "?" + p.query
        conn.request(method, path, headers=headers)
        resp = conn.getresponse()
        hdrs = {k.lower(): v for k, v in resp.getheaders()}

        class Body:
            def read(self, n=-1):
                return resp.read(n)

            def close(self):
                resp.close()
                conn.close()
        return RawResponse(resp.status, hdrs, Body())


TRANSIENT = (socket.timeout, TimeoutError, ConnectionError, http.client.HTTPException, ssl.SSLError, OSError)


@dataclass
class DownloadResult:
    final_url: str
    size: int
    sha256: str
    sha512: str
    complete: bool = True


class HttpClient:
    def __init__(self, transport=None, retries=3, backoff=1.0, sleep=time.sleep):
        self.transport = transport or HttpsTransport()
        self.retries = retries
        self.backoff = backoff
        self.sleep = sleep
        self.log = []   # redacted request log, useful for dry-run reports

    def _open(self, url, approved_hosts, headers=None, accept_partial=False):
        hdrs = {"User-Agent": USER_AGENT, "Accept-Encoding": "identity"}
        hdrs.update(headers or {})
        current = url
        for _ in range(MAX_REDIRECTS + 1):
            check_url(current, approved_hosts)
            resp = self._open_once(current, hdrs)
            if resp.status in (301, 302, 303, 307, 308):
                location = resp.headers.get("location")
                resp.body.close()
                if not location:
                    raise FetchError(f"redirect without Location from {redact(current)}")
                nxt = urllib.parse.urljoin(current, location)
                if urllib.parse.urlsplit(nxt).scheme != "https":
                    raise HostRejected(f"refusing redirect from HTTPS to {redact(nxt)}")
                self.log.append(f"redirect {redact(current)} -> {redact(nxt)}")
                current = nxt
                continue
            if resp.status == 200 or (accept_partial and resp.status == 206):
                return current, resp
            resp.body.close()
            hint = None
            if resp.status in (403, 429) and host_of(current) == "api.github.com":
                hint = "GitHub's unauthenticated API limit (60 requests/hour) may be exhausted; retry later."
            raise FetchError(f"HTTP {resp.status} from {redact(current)}", hint=hint)
        raise FetchError(f"too many redirects starting at {redact(url)}")

    def _open_once(self, url, headers):
        last = None
        for attempt in range(self.retries):
            try:
                self.log.append(f"GET {redact(url)}")
                resp = self.transport.open("GET", url, headers)
            except HostRejected:
                raise
            except ssl.SSLCertVerificationError as exc:
                raise FetchError(f"TLS certificate verification failed for {host_of(url)}: {exc.verify_message}")
            except TRANSIENT as exc:
                last = exc
            else:
                if resp.status in (429, 500, 502, 503, 504) and attempt + 1 < self.retries:
                    resp.body.close()
                    last = FetchError(f"HTTP {resp.status}")
                else:
                    return resp
            if attempt + 1 < self.retries:
                self.sleep(self.backoff * (2 ** attempt))
        raise FetchError(f"network error fetching {redact(url)}: {last}",
                         hint="Check connectivity and retry; nothing was installed.")

    def _read_all(self, resp, max_bytes, url):
        length = resp.headers.get("content-length")
        if length and length.isdigit() and int(length) > max_bytes:
            resp.body.close()
            raise FetchError(f"{redact(url)} is {length} bytes, over the {max_bytes}-byte limit")
        chunks, total = [], 0
        try:
            while True:
                chunk = resp.body.read(CHUNK)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise FetchError(f"{redact(url)} exceeded the {max_bytes}-byte limit")
                chunks.append(chunk)
        finally:
            resp.body.close()
        return b"".join(chunks)

    def get_bytes(self, url, approved_hosts, max_bytes=8 * 1024 * 1024, headers=None):
        final, resp = self._open(url, approved_hosts, headers)
        return final, self._read_all(resp, max_bytes, final)

    def get_json(self, url, approved_hosts, max_bytes=8 * 1024 * 1024, headers=None):
        final, data = self.get_bytes(url, approved_hosts, max_bytes, headers)
        try:
            return json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise FetchError(f"{redact(final)} did not return valid JSON: {exc}")

    def peek(self, url, approved_hosts, nbytes):
        """Fetch only the first `nbytes` (Range request; if the server ignores
        Range the transfer is cut off after `nbytes`)."""
        final, resp = self._open(url, approved_hosts, {"Range": f"bytes=0-{nbytes - 1}"}, accept_partial=True)
        out, total = [], 0
        try:
            while total < nbytes:
                chunk = resp.body.read(min(CHUNK, nbytes - total))
                if not chunk:
                    break
                out.append(chunk)
                total += len(chunk)
        finally:
            resp.body.close()
        return final, b"".join(out)

    def download(self, url, approved_hosts, dest, max_bytes):
        """Stream to `dest` (created exclusively, mode 0600)."""
        final, resp = self._open(url, approved_hosts)
        length = resp.headers.get("content-length")
        if length and length.isdigit() and int(length) > max_bytes:
            resp.body.close()
            raise FetchError(f"{redact(final)} is {length} bytes, over the {max_bytes}-byte limit",
                             hint="Raise settings.max_download_mb if this size is expected.")
        h256, h512, total = hashlib.sha256(), hashlib.sha512(), 0
        fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            with os.fdopen(fd, "wb") as fh:
                while True:
                    chunk = resp.body.read(CHUNK)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > max_bytes:
                        raise FetchError(f"{redact(final)} exceeded the {max_bytes}-byte limit")
                    h256.update(chunk)
                    h512.update(chunk)
                    fh.write(chunk)
        except BaseException:
            try:
                os.unlink(dest)
            except FileNotFoundError:
                pass
            raise
        finally:
            resp.body.close()
        if length and length.isdigit() and int(length) != total:
            os.unlink(dest)
            raise FetchError(f"truncated download from {redact(final)} ({total} of {length} bytes)")
        return DownloadResult(final, total, h256.hexdigest(), h512.hexdigest())
