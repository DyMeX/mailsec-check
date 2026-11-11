"""Command line: mailsec-check <domain> [--json] [--selector NAME] ..."""
import argparse
import json
import sys

from . import __version__, report, runner
from .domain import InputError
from .resolver import DEFAULT_RESOLVERS


def build_parser():
    p = argparse.ArgumentParser(
        prog="mailsec-check",
        description="Passive e-mail security checks for a domain: MX, SPF, DKIM, DMARC, MTA-STS, TLS-RPT, STARTTLS "
                    "and PTR of the mail servers. No mail is sent and nothing is authenticated.",
        epilog="Exit codes: 0 all pass, 1 warnings, 2 failures, 3 could not run (invalid input or nothing could be assessed).")
    p.add_argument("domain", help="domain name to check (a URL or an address is reduced to its domain)")
    p.add_argument("--json", action="store_true", help="print the full result as JSON instead of the text report")
    p.add_argument("--selector", action="append", default=[], metavar="NAME",
                   help="extra DKIM selector to try first (the s= value of a DKIM-Signature header); up to 3, repeatable")
    p.add_argument("--no-starttls", action="store_true", help="do not connect to the MX hosts on port 25 (skips the STARTTLS check)")
    p.add_argument("--resolver", default=",".join(DEFAULT_RESOLVERS), metavar="IP[,IP]",
                   help="DNS resolvers to query (default: %(default)s)")
    p.add_argument("--ehlo", default=runner.DEFAULT_CONFIG["EHLO"], metavar="NAME",
                   help="name sent in EHLO during the STARTTLS probe (default: %(default)s)")
    p.add_argument("--deadline", type=int, default=runner.DEFAULT_CONFIG["DEADLINE_S"], metavar="SECONDS",
                   help="overall time limit of the run (default: %(default)s)")
    p.add_argument("--psl-file", metavar="PATH", help="Public Suffix List file (default: system file if present, else a small built-in set)")
    p.add_argument("--verbose", action="store_true", help="print internal notes (errors that made a check skip) to stderr")
    p.add_argument("--version", action="version", version=f"mailsec-check {__version__}")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        selectors = runner.parse_selectors(args.selector)
        if args.psl_file:
            from . import psl
            psl.get_list(args.psl_file)
        resolvers = tuple(x.strip() for x in args.resolver.split(",") if x.strip())
        if not resolvers:
            raise ValueError("no resolver given")
        out = runner.run(args.domain, options={"extra_selectors": selectors, "starttls": not args.no_starttls},
                         config={"EHLO": args.ehlo, "DEADLINE_S": args.deadline}, resolvers=resolvers)
    except (InputError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return runner.EXIT_ERROR
    except ImportError as e:
        print(f"error: missing dependency: {e}", file=sys.stderr)
        return runner.EXIT_ERROR
    if args.json:
        json.dump(out, sys.stdout, ensure_ascii=False, indent=2)
        print()
    else:
        print(report.render(out, color=report.use_color(sys.stdout)))
    if args.verbose:
        report.print_log(out)
    return out["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
