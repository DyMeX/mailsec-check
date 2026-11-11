"""DNS queries: explicit public resolvers (DNSSEC-validating by default), per-query timeout, query budget and an
in-run cache. Uses dnspython. Test fakes implement the same interface: query(name, rtype) -> DnsAnswer."""
import ipaddress
from dataclasses import dataclass, field

DEFAULT_RESOLVERS = ("1.1.1.1", "9.9.9.9")


@dataclass
class DnsAnswer:
    records: list = field(default_factory=list)
    state: str = "empty"    # ok | empty (NOERROR without records) | nxdomain | timeout | error

    @property
    def ok(self):
        return self.state == "ok"


def record_text(r, rtype):
    """dnspython record -> plain text (names without the trailing dot)."""
    if rtype == "TXT":
        return b"".join(r.strings).decode("utf-8", "replace")
    if rtype == "MX":
        return f"{r.preference} {r.exchange.to_text().rstrip('.')}"
    if rtype in ("A", "AAAA"):
        return r.address
    if rtype in ("CNAME", "NS", "PTR"):
        return r.target.to_text().rstrip(".")
    return r.to_text()


class Resolver:
    def __init__(self, resolvers=DEFAULT_RESOLVERS, timeout=2.0, lifetime=4.0, budget=None):
        import dns.flags
        import dns.resolver
        self._dns = dns
        r = dns.resolver.Resolver(configure=False)
        r.nameservers = list(resolvers)
        r.timeout, r.lifetime = timeout, lifetime
        r.search = []
        r.flags = dns.flags.RD | dns.flags.AD
        r.use_edns(0, 0, 1232)
        self.r = r
        self.budget = budget
        self.cache = {}
        self.queries = 0

    def query(self, name, rtype):
        import dns.exception
        import dns.name
        import dns.resolver
        rtype = rtype.upper()
        key = (name.lower().rstrip("."), rtype)
        if key in self.cache:
            return self.cache[key]
        if self.budget is not None:
            self.budget.dns()
        self.queries += 1
        try:
            n = dns.name.from_text(key[0])
            ans = self.r.resolve(n, rtype, raise_on_no_answer=False, search=False)
            records = [record_text(x, rtype) for x in ans.rrset] if ans.rrset is not None else []
            w = DnsAnswer(records, "ok" if records else "empty")
        except dns.resolver.NXDOMAIN:
            w = DnsAnswer([], "nxdomain")
        except (dns.resolver.LifetimeTimeout, dns.exception.Timeout):
            w = DnsAnswer([], "timeout")
        except (dns.exception.DNSException, ValueError, UnicodeError):
            w = DnsAnswer([], "error")
        self.cache[key] = w
        return w

    def ptr(self, ip):
        import dns.reversename
        try:
            name = dns.reversename.from_address(ip).to_text()
        except Exception:   # dnspython raises several exception types for bad addresses
            return DnsAnswer([], "error")
        return self.query(name, "PTR")


def ptr_name(ip):
    """Reverse name without dnspython (used by the test fakes)."""
    return ipaddress.ip_address(ip).reverse_pointer
