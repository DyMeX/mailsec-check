"""The only module that opens sockets: target policy, host resolution with address pinning, a size-limited HTTP
client (used for the MTA-STS policy file), the SMTP STARTTLS probe and the run budget.

Rules: a target must resolve only to public addresses (every redirect hop goes through the same check), connections
go to the pinned address with SNI and a Host header equal to the name, HTTP ports are 80/443 only (port 25 is used
only for MX hosts), bodies are read with byte and time limits, gzip is decompressed with a limit, there are no
cookies and no authentication."""
import http.client
import ipaddress
import smtplib
import socket
import ssl
import threading
import time
import zlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import quote, urljoin, urlsplit


class ForbiddenTarget(Exception):
    """Private, local, shared-range or literal IP address, or a disallowed port: no connection is made."""


class BudgetExceeded(Exception):
    """Run time or the number of requests/queries exceeded."""


class NetworkError(Exception):
    pass


FORBIDDEN = [ipaddress.ip_network(x) for x in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
    "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/3",
    "::/128", "::1/128", "64:ff9b::/96", "64:ff9b:1::/48", "2001::/32", "2001:db8::/32", "2002::/16", "fc00::/7",
    "fe80::/10", "ff00::/8")]


class TargetPolicy:
    """allowed(ip): public address (is_global) outside the explicit list; an IPv4 address mapped into IPv6 is
    checked as IPv4. allow_private=True is for tests only (local fake servers)."""

    def __init__(self, forbidden=FORBIDDEN, ports=(80, 443), allow_private=False):
        self.forbidden = list(forbidden)
        self.ports = set(ports)
        self.allow_private = allow_private

    def allowed(self, ip):
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if a.version == 6 and a.ipv4_mapped is not None:
            a = a.ipv4_mapped
        if self.allow_private:
            return True
        if not a.is_global:
            return False
        return not any(a in n for n in self.forbidden)

    def port_ok(self, port):
        return port in self.ports


def is_literal_ip(host):
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def resolve_host(host, resolver, policy):
    """Addresses of a host (IPv4 before IPv6). Raises ForbiddenTarget when the host is a literal IP or any address
    is non-public (deliberately strict: a name with a mix of public and private addresses is a typical rebinding
    vector)."""
    if is_literal_ip(host):
        raise ForbiddenTarget(f"literal IP: {host}")
    addresses = []
    for rtype in ("A", "AAAA"):
        ans = resolver.query(host, rtype)
        if ans.state == "ok":
            addresses.extend(ans.records)
    if not addresses:
        raise NetworkError(f"{host}: no address (A/AAAA)")
    for ip in addresses:
        if not policy.allowed(ip):
            raise ForbiddenTarget(f"{host} -> {ip}")
    return addresses


class Budget:
    """Run deadline, counters of HTTP requests and DNS queries, and a pause between requests to the same host."""

    def __init__(self, deadline_s=90, max_http=25, max_dns=320, pause_s=0.3):
        self.end = time.monotonic() + deadline_s
        self.max_http, self.max_dns, self.pause = max_http, max_dns, pause_s
        self.http_n = self.dns_n = 0
        self.last = {}
        self.lock = threading.Lock()

    def remaining(self):
        return max(0.0, self.end - time.monotonic())

    def check_time(self):
        if self.remaining() <= 0:
            raise BudgetExceeded("time")

    def http(self, host=""):
        with self.lock:
            self.check_time()
            if self.http_n >= self.max_http:
                raise BudgetExceeded("HTTP requests")
            self.http_n += 1
            t = self.last.get(host, 0)
            wait = max(0.0, t + self.pause - time.monotonic())
            self.last[host] = time.monotonic() + wait
        if wait:
            time.sleep(min(wait, self.remaining()))

    def dns(self):
        with self.lock:
            self.check_time()
            if self.dns_n >= self.max_dns:
                raise BudgetExceeded("DNS queries")
            self.dns_n += 1

    def timeout(self, wanted):
        """Operation timeout no longer than the remaining run time (at least 0.5 s so a socket never gets 0)."""
        return max(0.5, min(wanted, self.remaining()))


@dataclass
class Response:
    status: int
    headers: list
    body: bytes
    url: str
    ip: str
    tls: dict | None
    ttfb_ms: int
    redirects: list = field(default_factory=list)
    truncated: bool = False

    def header(self, name):
        n = name.lower()
        for k, v in self.headers:
            if k.lower() == n:
                return v
        return None


def _cert_date(s):
    try:
        return datetime.strptime(s, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


def tls_info(sock, error=None):
    """TLS session information from an ssl socket: version, cipher, certificate (when verified) or just the error."""
    w = {"version": None, "cipher": None, "verification": "ok" if not error else f"error: {error}"}
    try:
        w["version"] = sock.version()
        c = sock.cipher()
        w["cipher"] = c[0] if c else None
        cert = sock.getpeercert() or {}
    except (ssl.SSLError, OSError, AttributeError):
        cert = {}
    if cert:
        not_after = _cert_date(cert.get("notAfter"))
        not_before = _cert_date(cert.get("notBefore"))
        w["valid_until"] = not_after.isoformat() if not_after else None
        w["valid_from"] = not_before.isoformat() if not_before else None
        w["days_to_expiry"] = (not_after - datetime.now(timezone.utc)).days if not_after else None
        w["issuer"] = " / ".join(v for rdn in cert.get("issuer", ()) for k, v in rdn if k in ("organizationName", "commonName"))
        w["subject"] = " / ".join(v for rdn in cert.get("subject", ()) for k, v in rdn if k == "commonName")
        w["san"] = [v for t, v in cert.get("subjectAltName", ()) if t == "DNS"][:50]
    return w


def _socket(ip, port, timeout):
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    s = socket.socket(family, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
    except OSError:
        s.close()
        raise
    return s


def _check_peer(sock, ip):
    """After connecting, verify that the socket really talks to the pinned address."""
    try:
        peer = sock.getpeername()[0].split("%")[0]
    except OSError:
        return
    a, b = ipaddress.ip_address(peer), ipaddress.ip_address(ip)
    if a.version == 6 and a.ipv4_mapped is not None:
        a = a.ipv4_mapped
    if a != b:
        sock.close()
        raise ForbiddenTarget(f"peer {peer} != {ip}")


class HttpClient:
    """fetch(url): GET/HEAD to a pinned address, with a size limit, gzip decompression and a redirect policy:
    'same-host' (same host or the www. variant, same default port), 'any-https' or 'none'."""

    def __init__(self, resolver, policy, budget, ua, connect_s=3, read_s=6, max_b=256 * 1024, max_redirects=3,
                 allow_invalid_cert=True):
        self.resolver, self.policy, self.budget, self.ua = resolver, policy, budget, ua
        self.connect_s, self.read_s, self.max_b, self.max_redirects = connect_s, read_s, max_b, max_redirects
        self.allow_invalid_cert = allow_invalid_cert

    def _connect(self, host, port, https):
        addresses = resolve_host(host, self.resolver, self.policy)
        last = None
        for ip in addresses:
            try:
                s = _socket(ip, port, self.budget.timeout(self.connect_s))
            except OSError as e:
                last = e
                continue
            _check_peer(s, ip)
            if not https:
                return s, ip, None
            ctx = ssl.create_default_context()
            try:
                ss = ctx.wrap_socket(s, server_hostname=host)
                return ss, ip, tls_info(ss)
            except ssl.SSLCertVerificationError as e:
                s.close()
                if not self.allow_invalid_cert:
                    raise NetworkError(f"certificate: {e.verify_message}") from None
                ctx2 = ssl.create_default_context()
                ctx2.check_hostname = False
                ctx2.verify_mode = ssl.CERT_NONE
                s = _socket(ip, port, self.budget.timeout(self.connect_s))
                _check_peer(s, ip)
                try:
                    ss = ctx2.wrap_socket(s, server_hostname=host)
                except (ssl.SSLError, OSError) as e2:
                    s.close()
                    last = e2
                    continue
                return ss, ip, tls_info(ss, error=e.verify_message)
            except (ssl.SSLError, OSError) as e:
                s.close()
                last = e
                continue
        raise NetworkError(f"{host}:{port}: {type(last).__name__ if last else 'no connection'}")

    def _read(self, resp, max_b):
        """Body with a byte limit and decompression (zlib with max_length - a gzip bomb cannot inflate memory)."""
        encoding = (resp.getheader("Content-Encoding") or "").lower().strip()
        dec = zlib.decompressobj(47) if encoding in ("gzip", "deflate", "x-gzip") else None
        result, truncated, read = bytearray(), False, 0
        while True:
            self.budget.check_time()
            chunk = resp.read(16384)
            if not chunk:
                break
            read += len(chunk)
            if dec is not None:
                try:
                    data = dec.decompress(chunk, max_length=max_b - len(result) + 1)
                except zlib.error:
                    truncated = True
                    break
            else:
                data = chunk
            result.extend(data)
            if len(result) > max_b or read > max_b * 4:
                truncated = True
                break
        return bytes(result[:max_b]), truncated

    def fetch(self, url, method="GET", headers=None, max_b=None, redirects="same-host", redirect_limit=None):
        max_b = max_b or self.max_b
        redirect_limit = self.max_redirects if redirect_limit is None else redirect_limit
        path_taken = []
        while True:
            u = urlsplit(url)
            host = (u.hostname or "").lower().rstrip(".")
            if u.scheme not in ("http", "https") or not host or "@" in u.netloc:
                raise ForbiddenTarget(f"address: {url[:120]}")
            https = u.scheme == "https"
            port = u.port or (443 if https else 80)
            if not self.policy.port_ok(port):
                raise ForbiddenTarget(f"port {port}")
            self.budget.http(host)
            sock, ip, tls = self._connect(host, port, https)
            sock.settimeout(self.budget.timeout(self.read_s))
            conn = (http.client.HTTPSConnection if https else http.client.HTTPConnection)(host, port, timeout=self.read_s)
            conn.sock = sock   # already connected to the pinned address; http.client will not call connect()
            path = quote(u.path or "/", safe="/%:@!$&'()*+,;=~-._") + (f"?{u.query}" if u.query else "")
            h = {"User-Agent": self.ua, "Accept": "text/plain,text/html;q=0.9,*/*;q=0.5",
                 "Accept-Language": "en", "Accept-Encoding": "gzip", "Connection": "close"}
            h.update(headers or {})
            t0 = time.monotonic()
            try:
                conn.request(method, path, headers=h)
                resp = conn.getresponse()
                ttfb = int((time.monotonic() - t0) * 1000)
                body, truncated = (b"", False) if method == "HEAD" else self._read(resp, max_b)
                resp_headers = list(resp.getheaders())
                status = resp.status
            except (http.client.HTTPException, OSError, ssl.SSLError) as e:
                raise NetworkError(f"{host}: {type(e).__name__}") from None
            finally:
                conn.close()
            out = Response(status, resp_headers, body, url, ip, tls, ttfb, list(path_taken), truncated)
            target = out.header("Location")
            if status in (301, 302, 303, 307, 308) and target and redirects != "none" and len(path_taken) < redirect_limit:
                new = urljoin(url, target.strip())
                nu = urlsplit(new)
                nh = (nu.hostname or "").lower().rstrip(".")
                if redirects == "same-host" and nh not in (host, "www." + host, host.removeprefix("www.")):
                    return out   # a foreign host is reported, not followed
                if nu.scheme == "http" and redirects == "any-https":
                    return out
                if nu.scheme not in ("http", "https"):
                    return out
                path_taken.append(url)
                url = new
                continue
            return out


class PinnedSMTP(smtplib.SMTP):
    """SMTP to an MX host at a pinned address: the MX name stays in self._host (STARTTLS verifies the certificate
    against it) while the socket connects to a specific IP. Overrides the private _get_socket; a unit test checks
    that it exists."""

    def __init__(self, ip, host, port=25, timeout=12, local_hostname=None):
        self.ip = ip
        super().__init__(host, port, local_hostname=local_hostname, timeout=timeout)

    def _get_socket(self, host, port, timeout):
        s = _socket(self.ip, port, timeout)
        _check_peer(s, self.ip)
        return s


assert hasattr(smtplib.SMTP, "_get_socket")


def probe_starttls(mx, ip, ehlo, timeout=12):
    """One connection to an MX on port 25: banner, EHLO, STARTTLS (certificate verified against the MX name), QUIT.
    No MAIL FROM - this is not a delivery attempt."""
    w = {"mx": mx, "ip": ip, "connected": False, "starttls_offered": False, "starttls_ok": False, "tls": None, "error": None}
    s = None
    try:
        s = PinnedSMTP(ip, mx, 25, timeout=timeout, local_hostname=ehlo)
        w["connected"] = True
        code, _ = s.ehlo(ehlo)
        if code != 250:
            w["error"] = f"EHLO {code}"
            return w
        if not s.has_extn("starttls"):
            return w
        w["starttls_offered"] = True
        try:
            s.starttls(context=ssl.create_default_context())
            w["starttls_ok"] = True
            w["tls"] = tls_info(s.sock)
        except ssl.SSLCertVerificationError as e:
            w["error"] = f"MX certificate: {e.verify_message}"
        except (ssl.SSLError, smtplib.SMTPException, OSError) as e:
            w["error"] = f"STARTTLS: {type(e).__name__}"
    except (smtplib.SMTPException, OSError, ForbiddenTarget) as e:
        w["error"] = f"{type(e).__name__}"
    finally:
        if s is not None:
            try:
                s.quit()
            except (smtplib.SMTPException, OSError):
                try:
                    s.close()
                except OSError:
                    pass
    return w
