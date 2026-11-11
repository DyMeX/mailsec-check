"""Test fakes: a resolver backed by a dict of zones, an HTTP client backed by a dict of URLs, and a run context
without network access."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mailsec_check import net  # noqa: E402
from mailsec_check import result as R  # noqa: E402
from mailsec_check.domain import normalize_input  # noqa: E402
from mailsec_check.psl import SuffixList  # noqa: E402
from mailsec_check.resolver import DnsAnswer, ptr_name  # noqa: E402

PSL = SuffixList(None)   # built-in list (no file)


class FakeResolver:
    """zone: {("name", "TYPE"): [records] | "NXDOMAIN" | "TIMEOUT" | "ERROR"}; a missing key means NOERROR without records."""

    def __init__(self, zone=None, budget=None):
        self.zone = {(k[0].lower().rstrip("."), k[1].upper()): v for k, v in (zone or {}).items()}
        self.budget = budget
        self.queries = []

    def query(self, name, rtype):
        if self.budget is not None:
            self.budget.dns()
        key = (name.lower().rstrip("."), rtype.upper())
        self.queries.append(key)
        v = self.zone.get(key)
        if v == "NXDOMAIN":
            return DnsAnswer([], "nxdomain")
        if v == "TIMEOUT":
            return DnsAnswer([], "timeout")
        if v == "ERROR":
            return DnsAnswer([], "error")
        if not v:
            # NXDOMAIN when no type exists for this name (like a real DNS)
            if not any(k[0] == key[0] for k in self.zone):
                return DnsAnswer([], "nxdomain")
            return DnsAnswer([], "empty")
        return DnsAnswer(list(v), "ok")

    def ptr(self, ip):
        return self.query(ptr_name(ip), "PTR")


class FakeHttp:
    """responses: {url: (status, headers_dict, body_bytes)} or {url: Exception}; a missing URL raises NetworkError."""

    def __init__(self, responses=None, budget=None):
        self.responses = dict(responses or {})
        self.budget = budget
        self.requests = []

    def fetch(self, url, method="GET", headers=None, max_b=None, redirects="same-host", redirect_limit=None):
        if self.budget is not None:
            self.budget.http(url.split("/")[2])
        self.requests.append(url)
        if url not in self.responses:
            raise net.NetworkError(f"fake: no {url}")
        v = self.responses[url]
        if isinstance(v, Exception):
            raise v
        status, headers_, body = v[0], v[1], v[2]
        return net.Response(status, list(headers_.items()), body if isinstance(body, bytes) else body.encode("utf-8"),
                            url, "93.184.216.34", None, 120)


def context(domain, zone=None, http=None, options=None, config=None):
    d = normalize_input(domain, PSL)
    budget = net.Budget(60, 50, 300, 0)
    k = {"SPF_MAX_QUERIES": 30, "STARTTLS_MAX_MX": 2, "STARTTLS_TIMEOUT_S": 2, "EHLO": "test"}
    k.update(config or {})
    resolver = zone if hasattr(zone, "query") else FakeResolver(zone, budget=budget)
    http = http if hasattr(http, "fetch") else FakeHttp(http, budget=budget)
    op = {"starttls": False}
    op.update(options or {})
    return R.Context(d, resolver, http, budget, k, op)


def company_zone(domain="example.com", ip="93.184.216.34", mx="mail.example.com", spf="v=spf1 mx -all",
                 dmarc="v=DMARC1; p=reject; rua=mailto:dmarc@example.com", dkim=("default", "v=DKIM1; k=rsa; p=" + "A" * 400)):
    s = {
        (domain, "A"): [ip], (domain, "AAAA"): ["2606:2800:220:1:248:1893:25c8:1946"],
        (domain, "MX"): [f"10 {mx}"], (mx, "A"): [ip], (domain, "TXT"): [spf],
        ("_dmarc." + domain, "TXT"): [dmarc] if dmarc else "NXDOMAIN",
        (ptr_name(ip), "PTR"): [mx],
    }
    if dkim:
        s[(f"{dkim[0]}._domainkey.{domain}", "TXT")] = [dkim[1]]
    return s
