"""Builds the run context, runs all mail checks and computes the exit code."""
import re
import time

from . import __version__, checks, net
from . import result as R
from .domain import InputError, normalize_input
from .resolver import DEFAULT_RESOLVERS

EXIT_OK, EXIT_WARN, EXIT_FAIL, EXIT_ERROR = 0, 1, 2, 3

DEFAULT_CONFIG = {
    "DNS_TIMEOUT_S": 2, "DNS_LIFETIME_S": 4, "DNS_MAX_QUERIES": 320, "SPF_MAX_QUERIES": 30,
    "HTTP_CONNECT_S": 3, "HTTP_READ_S": 6, "HTTP_MAX_REQUESTS": 25, "HTTP_MAX_REDIRECTS": 3,
    "HTTP_PAUSE_S": 0.3, "RESPONSE_MAX_B": 256 * 1024,
    "STARTTLS_TIMEOUT_S": 12, "STARTTLS_MAX_MX": 2, "DEADLINE_S": 90,
    "EHLO": "localhost", "UA": f"mailsec-check/{__version__}",
}

_SELECTOR = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,61}[a-z0-9])?$")
MAX_SELECTORS = 3


def parse_selectors(values):
    """DKIM selectors from command-line values (at most 3, separated by comma or space). Also accepts a pasted
    "s=name" and "name._domainkey". ValueError for a name that cannot be a DNS label."""
    out = []
    for text in values or []:
        for part in re.split(r"[,;\s]+", (text or "").strip().lower()):
            part = part.removeprefix("s=").split("._domainkey")[0].strip(".")
            if not part:
                continue
            if not _SELECTOR.match(part) or ".." in part:
                raise ValueError(f"invalid DKIM selector: {part}")
            if part not in out:
                out.append(part)
    if len(out) > MAX_SELECTORS:
        raise ValueError(f"at most {MAX_SELECTORS} extra selectors are accepted")
    return out


def build_context(domain, config=None, resolver=None, http=None, options=None, budget=None, resolvers=DEFAULT_RESOLVERS):
    k = dict(DEFAULT_CONFIG)
    k.update(config or {})
    if not hasattr(domain, "organizational"):
        domain = normalize_input(domain)
    budget = budget or net.Budget(float(k["DEADLINE_S"]), int(k["HTTP_MAX_REQUESTS"]), int(k["DNS_MAX_QUERIES"]), float(k["HTTP_PAUSE_S"]))
    if resolver is None:
        from .resolver import Resolver
        resolver = Resolver(list(resolvers), float(k["DNS_TIMEOUT_S"]), float(k["DNS_LIFETIME_S"]), budget)
    if http is None:
        http = net.HttpClient(resolver, net.TargetPolicy(), budget, k["UA"], float(k["HTTP_CONNECT_S"]), float(k["HTTP_READ_S"]),
                              int(k["RESPONSE_MAX_B"]), int(k["HTTP_MAX_REDIRECTS"]))
    return R.Context(domain, resolver, http, budget, k, dict(options or {}))


def exit_code(results):
    """0 all PASS, 1 at least one WARN, 2 at least one FAIL, 3 nothing could be assessed (no PASS, WARN or FAIL)."""
    statuses = {r.status for r in results}
    if not statuses & {"PASS", "WARN", "FAIL"}:
        return EXIT_ERROR
    if "FAIL" in statuses:
        return EXIT_FAIL
    if "WARN" in statuses:
        return EXIT_WARN
    return EXIT_OK


def run(domain, **kw):
    """Runs all mail checks. Returns a dict ready for JSON. Raises InputError for an unusable domain name."""
    t0 = time.monotonic()
    ctx = build_context(domain, **kw)
    results = checks.run_all(ctx)
    counts = {s: sum(1 for r in results if r.status == s) for s in ("PASS", "WARN", "FAIL", "INFO", "SKIP")}
    return {
        "tool": "mailsec-check", "version": __version__,
        "domain": ctx.domain.name, "domain_unicode": ctx.domain.unicode, "organizational_domain": ctx.domain.organizational,
        "duration_s": round(time.monotonic() - t0, 1),
        "exit_code": exit_code(results),
        "summary": {k.lower(): v for k, v in counts.items()},
        "checks": [r.as_dict() for r in results],
        "context": {k: ctx.shared.get(k) for k in ("mail_provider", "null_mx")},
        "budget": {"http": ctx.budget.http_n, "dns": ctx.budget.dns_n},
        "log": ctx.log,
    }


__all__ = ["run", "build_context", "exit_code", "parse_selectors", "InputError"]
