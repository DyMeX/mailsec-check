"""Result of a single check and the run context."""
from dataclasses import dataclass, field

from . import net

# internal levels, in the order used by the checks:
#   ok        -> PASS
#   warning   -> WARN
#   error     -> FAIL (severity "error")
#   critical  -> FAIL (severity "critical")
#   info      -> INFO (not applicable or informational, never affects the exit code)
#   skipped   -> SKIP (could not be checked, never affects the exit code)
LEVELS = ("ok", "warning", "error", "critical", "info", "skipped")
STATUS_OF = {"ok": "PASS", "warning": "WARN", "error": "FAIL", "critical": "FAIL", "info": "INFO", "skipped": "SKIP"}


@dataclass
class Result:
    check: str
    level: str
    message: str = ""
    data: dict = field(default_factory=dict)

    @property
    def status(self):
        return STATUS_OF[self.level]

    @property
    def severity(self):
        return self.level if self.level in ("error", "critical") else None

    def as_dict(self):
        return {"check": self.check, "status": self.status, "severity": self.severity,
                "message": self.message, "data": self.data}


def _r(check, level, message, data):
    assert level in LEVELS, level
    return Result(check, level, message, dict(data))


def ok(check, message="", **data):
    return _r(check, "ok", message, data)


def warn(check, message="", **data):
    return _r(check, "warning", message, data)


def error(check, message="", **data):
    return _r(check, "error", message, data)


def critical(check, message="", **data):
    return _r(check, "critical", message, data)


def info(check, message="", **data):
    return _r(check, "info", message, data)


def not_applicable(check, reason, **data):
    """The check does not apply (e.g. a domain without mail): reported as information, not as a skip."""
    return _r(check, "info", f"Not applicable: {reason}.", data)


def skipped(check, reason="", **data):
    return _r(check, "skipped", reason, data)


def plural(n, noun, many=None):
    return f"{n} {noun if n == 1 else (many or noun + 's')}"


@dataclass
class Context:
    domain: object          # domain.Domain
    resolver: object        # resolver.Resolver or a fake (query(name, rtype) -> DnsAnswer, ptr(ip))
    http: object            # net.HttpClient or a fake (fetch(url, ...) -> net.Response)
    budget: object          # net.Budget
    config: dict
    options: dict = field(default_factory=dict)    # extra_selectors, starttls
    shared: dict = field(default_factory=dict)     # values shared between checks (MX list, provider, ...)
    log: list = field(default_factory=list)

    def note(self, text):
        self.log.append(text[:300])

    def option(self, name, default=None):
        return self.options.get(name, default)

    def fetch(self, url, **kw):
        return self.http.fetch(url, **kw)


def guarded(ctx, func, checks):
    """Runs one check function; any exception becomes a skipped result for the given ids, so one failure does not
    spoil the rest. checks: {check id: None} or an iterable of ids."""
    try:
        return list(func(ctx))
    except net.BudgetExceeded:
        reason = "run limit reached"
    except net.ForbiddenTarget as e:
        reason = "address not allowed"
        ctx.note(f"{func.__name__}: {e}")
    except net.NetworkError as e:
        reason = "connection error during the check"
        ctx.note(f"{func.__name__}: {e}")
    except Exception as e:   # noqa: BLE001 - the run must finish the remaining checks
        reason = "internal error"
        ctx.note(f"{func.__name__}: {type(e).__name__}: {e}")
    return [skipped(i, reason) for i in checks]
