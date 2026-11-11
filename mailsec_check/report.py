"""Text report: one line per check."""
import os
import sys

COLORS = {"PASS": "32", "WARN": "33", "FAIL": "31", "INFO": "36", "SKIP": "90"}


def use_color(stream):
    return stream.isatty() and "NO_COLOR" not in os.environ and os.environ.get("TERM") != "dumb"


def render(report, color=False):
    lines = [f"mailsec-check {report['version']}  {report['domain_unicode']}  ({report['duration_s']} s, "
             f"{report['budget']['dns']} DNS queries, {report['budget']['http']} network connections)", ""]
    width = max(len(c["check"]) for c in report["checks"]) if report["checks"] else 10
    for c in report["checks"]:
        tag = f"[{c['status']}]"
        if color:
            tag = f"\033[{COLORS[c['status']]}m{tag}\033[0m"
        sev = " (critical)" if c["severity"] == "critical" else ""
        lines.append(f"{tag}{' ' * (6 - len(c['status']))} {c['check']:<{width}}  {c['message']}{sev}")
    s = report["summary"]
    lines += ["", f"{s['pass']} pass, {s['warn']} warn, {s['fail']} fail, {s['skip']} skipped, {s['info']} not applicable. "
                  f"Exit code {report['exit_code']}."]
    return "\n".join(lines)


def print_log(report, stream=None):
    stream = stream or sys.stderr
    for line in report["log"]:
        print(f"log: {line}", file=stream)
