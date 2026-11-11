"""Command line: output formats and exit codes without network access."""
import contextlib
import io
import json
import unittest
from unittest import mock

from . import fakes
from mailsec_check import cli, runner


def run_cli(argv, zone=None, http=None):
    def fake_build(domain, config=None, resolver=None, http_=None, options=None, budget=None, resolvers=None):
        return fakes.context(domain, zone if zone is not None else fakes.company_zone(), http, options, config)
    out, err = io.StringIO(), io.StringIO()
    with mock.patch.object(runner, "build_context", fake_build), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(argv)
    return code, out.getvalue(), err.getvalue()


class TestCli(unittest.TestCase):
    def test_text_report_one_line_per_check(self):
        code, out, _ = run_cli(["example.com"])
        self.assertEqual(code, 1)   # DMARC is fine, but MTA-STS / TLS-RPT are missing -> warnings
        lines = [l for l in out.splitlines() if l.startswith("[")]
        self.assertEqual(len(lines), 12)
        self.assertTrue(lines[0].startswith("[PASS]"))
        self.assertIn("Exit code 1", out)

    def test_json(self):
        code, out, _ = run_cli(["example.com", "--json"])
        d = json.loads(out)
        self.assertEqual(d["exit_code"], code)
        self.assertEqual(d["domain"], "example.com")
        self.assertEqual(len(d["checks"]), 12)
        self.assertEqual({c["status"] for c in d["checks"]} - {"PASS", "WARN", "FAIL", "INFO", "SKIP"}, set())
        self.assertEqual(sum(d["summary"].values()), 12)

    def test_failure_exit_code(self):
        zone = fakes.company_zone(spf=None, dmarc=None)
        zone[("example.com", "TXT")] = ["unrelated"]
        code, _, _ = run_cli(["example.com"], zone)
        self.assertEqual(code, 2)

    def test_invalid_input_is_exit_3(self):
        self.assertEqual(cli.main(["localhost"]), 3)

    def test_bad_selector_is_exit_3(self):
        self.assertEqual(cli.main(["example.com", "--selector", "a/b"]), 3)

    def test_too_many_selectors_is_exit_3(self):
        self.assertEqual(cli.main(["example.com", "--selector", "a b c d"]), 3)


if __name__ == "__main__":
    unittest.main()
