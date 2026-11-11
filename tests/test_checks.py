"""Check logic on fakes: MX, SPF, DKIM, DMARC, MTA-STS, TLS-RPT, STARTTLS, PTR, the full run and the exit code."""
import unittest

from . import fakes
from mailsec_check import checks, net, runner
from mailsec_check import result as R
from mailsec_check.resolver import DnsAnswer


def pick(results, ident):
    return next(x for x in results if x.check == ident)


class TestSPF(unittest.TestCase):
    def spf(self, records, extra=None):
        s = fakes.company_zone(spf="v=spf1 mx -all")
        s[("example.com", "TXT")] = records
        s.update(extra or {})
        ctx = fakes.context("example.com", s)
        return checks._mx(ctx), checks._spf(ctx)

    def test_missing(self):
        _, w = self.spf(["something else"])
        self.assertEqual(pick(w, "spf.record").level, "error")

    def test_multiple(self):
        _, w = self.spf(["v=spf1 -all", "v=spf1 mx -all"])
        self.assertEqual(pick(w, "spf.record").level, "error")

    def test_all(self):
        cases = (("v=spf1 mx -all", "ok"), ("v=spf1 mx ~all", "warning"), ("v=spf1 mx ?all", "warning"),
                 ("v=spf1 mx +all", "critical"), ("v=spf1 mx", "warning"))
        for rec, level in cases:
            _, w = self.spf([rec])
            self.assertEqual(pick(w, "spf.all").level, level, rec)

    def test_lookups_and_loop(self):
        extra = {("a.example.net", "TXT"): ["v=spf1 include:b.example.net -all"], ("b.example.net", "TXT"): ["v=spf1 include:a.example.net -all"]}
        _, w = self.spf(["v=spf1 include:a.example.net -all"], extra)
        self.assertIn(pick(w, "spf.lookups").level, ("ok", "warning", "error"))   # a loop does not hang
        extra = {(f"i{i}.example.net", "TXT"): ["v=spf1 a mx -all"] for i in range(6)}
        _, w = self.spf(["v=spf1 " + " ".join(f"include:i{i}.example.net" for i in range(6)) + " -all"], extra)
        self.assertEqual(pick(w, "spf.lookups").level, "error")   # 6 includes + 12 inside > 10
        _, w = self.spf(["v=spf1 include:gone1.example.net include:gone2.example.net include:gone3.example.net -all"])
        self.assertEqual(pick(w, "spf.lookups").level, "warning")   # 3 void
        _, w = self.spf(["v=spf1 redirect=_spf.example.net"], {("_spf.example.net", "TXT"): ["v=spf1 ip4:203.0.113.0/24 ~all"]})
        self.assertEqual(pick(w, "spf.all").level, "ok")

    def test_unknown_mechanism_and_ptr(self):
        _, w = self.spf(["v=spf1 mx somethingodd -all"])
        self.assertEqual(pick(w, "spf.record").level, "error")
        _, w = self.spf(["v=spf1 ptr -all"])
        self.assertEqual(pick(w, "spf.lookups").level, "warning")

    def test_dns_timeout_skips_all_three(self):
        _, w = self.spf("TIMEOUT")
        self.assertEqual([x.level for x in w], ["skipped"] * 3)


class TestDKIM(unittest.TestCase):
    def dkim(self, dkim, extra=None, options=None):
        s = fakes.company_zone(dkim=dkim)
        s.update(extra or {})
        ctx = fakes.context("example.com", s, options=options)
        checks._mx(ctx)
        return checks._dkim(ctx)[0]

    def test_ok(self):
        w = self.dkim(("default", "v=DKIM1; k=rsa; p=" + "A" * 400))
        self.assertEqual(w.level, "ok")
        self.assertEqual(w.data["found"][0]["selector"], "default")

    def test_missing_and_extra_selector(self):
        w = self.dkim(None)
        self.assertEqual(w.level, "skipped")   # own server: the selector cannot be guessed, no hit is not proof
        self.assertGreaterEqual(w.data["selectors_checked"], 30)
        w = self.dkim(("v1-rsa-20261013", "v=DKIM1; p=" + "A" * 400), options={"extra_selectors": ["v1-rsa-20261013"]})
        self.assertEqual(w.level, "ok")

    def test_weak(self):
        self.assertEqual(self.dkim(("default", "v=DKIM1; p=")).level, "warning")
        self.assertEqual(self.dkim(("default", "v=DKIM1; t=y; p=" + "A" * 400)).level, "warning")
        self.assertEqual(self.dkim(("default", "v=DKIM1; k=rsa; p=" + "A" * 150)).level, "warning")   # about 1024 bits
        self.assertEqual(self.dkim(("default", "v=DKIM1; k=ed25519; p=" + "A" * 44)).level, "ok")

    def test_wildcard(self):
        class Wild(fakes.FakeResolver):
            def query(self, name, rtype):
                if "_domainkey." in name:
                    return DnsAnswer(["v=DKIM1; p=" + "A" * 400], "ok")
                return super().query(name, rtype)
        ctx = fakes.context("example.com", Wild(fakes.company_zone(dkim=None)))
        checks._mx(ctx)
        w = checks._dkim(ctx)[0]
        self.assertTrue(w.data.get("wildcard"))
        self.assertEqual(w.level, "warning")

    def test_selector_with_date_found_only_when_given(self):
        s = fakes.company_zone(dkim=("v1-rsa-20261013", "v=DKIM1; k=rsa; p=" + "A" * 400))
        without = fakes.context("example.com", s)
        checks._mx(without)
        w = checks._dkim(without)[0]
        self.assertEqual(w.level, "skipped")
        self.assertIn("--selector", w.message)
        given = fakes.context("example.com", s, options={"extra_selectors": ["v1-rsa-20261013"]})
        checks._mx(given)
        self.assertEqual(checks._dkim(given)[0].level, "ok")

    def test_parse_selectors(self):
        f = runner.parse_selectors
        self.assertEqual(f([]), [])
        self.assertEqual(f([""]), [])
        self.assertEqual(f([" V1-RSA-20261013 "]), ["v1-rsa-20261013"])
        self.assertEqual(f(["s1, s2;s1 google"]), ["s1", "s2", "google"])
        self.assertEqual(f(["s=selector1"]), ["selector1"])
        self.assertEqual(f(["k1._domainkey.example.com"]), ["k1"])
        for bad in ("a b c d", "<script>", "a/b", "-abc", "x" * 70, "a..b", "\u0105", "a'b"):
            with self.assertRaises(ValueError, msg=bad):
                f([bad])


class TestDMARC(unittest.TestCase):
    def dmarc(self, rec, domain="example.com", extra=None):
        s = fakes.company_zone(dmarc=rec)
        s.update(extra or {})
        ctx = fakes.context(domain, s)
        checks._mx(ctx)
        return checks._dmarc(ctx)

    def test_policies(self):
        cases = (("v=DMARC1; p=reject; rua=mailto:a@b.example.org", "ok"), ("v=DMARC1; p=quarantine", "warning"),
                 ("v=DMARC1; p=none", "warning"), ("v=DMARC1; p=reject; pct=50", "warning"), ("v=DMARC1; sp=none", "error"),
                 ("v=DMARC1; p=reject; t=y", "warning"))
        for rec, level in cases:
            self.assertEqual(pick(self.dmarc(rec), "dmarc.policy").level, level, rec)
        self.assertEqual(pick(self.dmarc(None), "dmarc.record").level, "critical")
        self.assertEqual(pick(self.dmarc("v=DMARC1; p=reject"), "dmarc.rua").level, "warning")

    def test_missing_record_without_mail_is_error_not_critical(self):
        s = fakes.company_zone(dmarc=None)
        s[("example.com", "MX")] = ["0 ."]
        ctx = fakes.context("example.com", s)
        checks._mx(ctx)
        self.assertEqual(pick(checks._dmarc(ctx), "dmarc.record").level, "error")

    def test_subdomain_inherits(self):
        s = fakes.company_zone(dmarc="v=DMARC1; p=reject; sp=quarantine")
        s[("_dmarc.shop.example.com", "TXT")] = "NXDOMAIN"
        s[("shop.example.com", "MX")] = ["10 mail.example.com"]
        s[("shop.example.com", "A")] = ["93.184.216.34"]
        ctx = fakes.context("shop.example.com", s)
        checks._mx(ctx)
        w = checks._dmarc(ctx)
        self.assertEqual(pick(w, "dmarc.record").level, "ok")
        self.assertEqual(pick(w, "dmarc.policy").level, "warning")   # sp=quarantine


class TestDmarcRua(unittest.TestCase):
    def rua(self, record, extra=None, domain="example.com"):
        s = fakes.company_zone(dmarc=record)
        s.update(extra or {})
        ctx = fakes.context(domain, s)
        checks._mx(ctx)
        return pick(checks._dmarc(ctx), "dmarc.rua"), ctx

    def test_own_domain_needs_no_queries(self):
        w, ctx = self.rua("v=DMARC1; p=reject; rua=mailto:dmarc@example.com,mailto:x@mail.example.com")
        self.assertEqual(w.level, "ok")
        self.assertFalse([z for z in ctx.resolver.queries if "_report._dmarc" in z[0]])

    def test_foreign_domain_without_authorization(self):
        w, _ = self.rua("v=DMARC1; p=reject; rua=mailto:reports@other.example.org", {("other.example.org", "A"): ["203.0.113.4"]})
        self.assertEqual(w.level, "warning")
        self.assertEqual(w.data["rua_unauthorized"], ["other.example.org"])
        self.assertIn("example.com._report._dmarc.other.example.org", w.message)

    def test_foreign_domain_with_authorization(self):
        w, _ = self.rua("v=DMARC1; p=reject; rua=mailto:reports@other.example.org!10m, mailto:a@example.com",
                        {("example.com._report._dmarc.other.example.org", "TXT"): ["v=DMARC1"]})
        self.assertEqual(w.level, "ok")

    def test_one_of_two_without_authorization(self):
        w, _ = self.rua("v=DMARC1; p=reject; rua=mailto:a@good.example.org,mailto:b@bad.example.org",
                        {("example.com._report._dmarc.good.example.org", "TXT"): ["v=DMARC1; "], ("bad.example.org", "A"): ["203.0.113.4"]})
        self.assertEqual((w.level, w.data["rua_unauthorized"]), ("warning", ["bad.example.org"]))

    def test_dns_error_does_not_count(self):
        w, _ = self.rua("v=DMARC1; p=reject; rua=mailto:a@other.example.org", {("example.com._report._dmarc.other.example.org", "TXT"): "TIMEOUT"})
        self.assertEqual(w.level, "ok")


class TestMX(unittest.TestCase):
    def test_null_mx(self):
        s = fakes.company_zone()
        s[("example.com", "MX")] = ["0 "]
        ctx = fakes.context("example.com", s)
        w = checks.run_all(ctx)
        self.assertEqual(pick(w, "mx").level, "info")
        self.assertEqual(pick(w, "dkim").level, "info")   # not applicable, but not "skipped"
        self.assertTrue(pick(w, "dkim").message.startswith("Not applicable"))

    def test_no_mx_with_a_record(self):
        s = fakes.company_zone()
        s[("example.com", "MX")] = []
        ctx = fakes.context("example.com", s)
        self.assertEqual(checks._mx(ctx)[0].level, "warning")
        w = checks.run_all(fakes.context("example.com", s))
        for ident in ("mx.starttls", "mx.ptr", "mta_sts", "tls_rpt"):   # implicit MX: an omission, not "not applicable"
            self.assertEqual(pick(w, ident).level, "skipped", ident)

    def test_no_mx_and_no_a(self):
        s = {("example.com", "TXT"): ["v=spf1 -all"], ("example.com", "MX"): []}
        ctx = fakes.context("example.com", s)
        self.assertEqual(checks._mx(ctx)[0].level, "error")

    def test_nxdomain(self):
        ctx = fakes.context("example.com", {("example.com", "MX"): "NXDOMAIN"})
        self.assertEqual(checks._mx(ctx)[0].level, "critical")

    def test_mx_without_address(self):
        s = {("example.com", "MX"): ["10 mail.example.com"], ("mail.example.com", "TXT"): ["x"]}
        ctx = fakes.context("example.com", s)
        self.assertEqual(checks._mx(ctx)[0].level, "critical")

    def test_partly_resolving(self):
        s = fakes.company_zone()
        s[("example.com", "MX")] = ["10 mail.example.com", "20 gone.example.com"]
        s[("gone.example.com", "TXT")] = ["x"]
        ctx = fakes.context("example.com", s)
        self.assertEqual(checks._mx(ctx)[0].level, "warning")

    def test_trusted_provider_skips_probe(self):
        s = fakes.company_zone(mx="aspmx.l.google.com")
        s[("aspmx.l.google.com", "A")] = ["93.184.216.35"]
        ctx = fakes.context("example.com", s, options={"starttls": True})
        w = checks.run_all(ctx)
        self.assertEqual(ctx.shared["mail_provider"], "Google Workspace")
        self.assertEqual(pick(w, "mx.starttls").level, "ok")
        self.assertIn("not probed", pick(w, "mx.starttls").message)

    def test_starttls_probe_disabled(self):
        ctx = fakes.context("example.com", fakes.company_zone())
        w = checks.run_all(ctx)
        self.assertEqual(pick(w, "mx.starttls").level, "skipped")


class TestStarttlsAggregation(unittest.TestCase):
    """Verdicts of the STARTTLS check for different probe outcomes (the probe itself is replaced)."""

    def verdict(self, *probes):
        from unittest import mock
        s = fakes.company_zone()
        ctx = fakes.context("example.com", s, options={"starttls": True})
        checks._mx(ctx)
        with mock.patch.object(net, "probe_starttls", side_effect=list(probes)):
            return checks._starttls(ctx)[0]

    @staticmethod
    def probe(connected=True, offered=True, ok=True, days=60, error=None):
        return {"mx": "mail.example.com", "ip": "93.184.216.34", "connected": connected, "starttls_offered": offered,
                "starttls_ok": ok, "tls": {"days_to_expiry": days} if ok else None, "error": error}

    def test_ok(self):
        self.assertEqual(self.verdict(self.probe()).level, "ok")

    def test_certificate_expiring_soon(self):
        w = self.verdict(self.probe(days=5))
        self.assertEqual(w.level, "warning")
        self.assertIn("5 days", w.message)

    def test_offered_but_certificate_invalid(self):
        w = self.verdict(self.probe(ok=False, error="MX certificate: expired"))
        self.assertEqual(w.level, "warning")
        self.assertIn("expired", w.message)

    def test_not_offered(self):
        self.assertEqual(self.verdict(self.probe(offered=False, ok=False)).level, "critical")

    def test_cannot_connect(self):
        w = self.verdict(self.probe(connected=False, offered=False, ok=False))
        self.assertEqual(w.level, "skipped")


class TestPTR(unittest.TestCase):
    def ptr(self, ptr_records, extra=None):
        s = fakes.company_zone()
        s[(next(k for k in s if k[1] == "PTR")[0], "PTR")] = ptr_records
        s.update(extra or {})
        ctx = fakes.context("example.com", s)
        checks._mx(ctx)
        return checks._ptr(ctx)[0]

    def test_match(self):
        self.assertEqual(self.ptr(["mail.example.com"]).level, "ok")

    def test_forward_confirmed(self):
        w = self.ptr(["host.example.net"], {("host.example.net", "A"): ["93.184.216.34"]})
        self.assertEqual(w.level, "ok")

    def test_mismatch(self):
        w = self.ptr(["host.example.net"], {("host.example.net", "A"): ["203.0.113.9"]})
        self.assertEqual(w.level, "warning")

    def test_missing(self):
        self.assertEqual(self.ptr([]).level, "warning")


class TestMtaSts(unittest.TestCase):
    URL = "https://mta-sts.example.com/.well-known/mta-sts.txt"

    def sts(self, policy, mx=("10 mail.example.com",), status=200, txt=True):
        s = fakes.company_zone()
        s[("example.com", "MX")] = list(mx)
        for r in mx:
            s[(r.split()[1], "A")] = ["93.184.216.34"]
        if txt:
            s[("_mta-sts.example.com", "TXT")] = ["v=STSv1; id=1"]
        ctx = fakes.context("example.com", s, {self.URL: (status, {"Content-Type": "text/plain"}, policy)})
        checks._mx(ctx)
        return pick(checks._mta_sts(ctx), "mta_sts")

    def test_matching(self):
        self.assertEqual(self.sts("version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 604800\n").level, "ok")
        self.assertEqual(self.sts("version: STSv1\r\nmode: testing\r\nmx: mail.example.com\r\nmax_age: 86400\r\n").level, "warning")

    def test_several_mx_lines_and_pattern(self):
        pol = "version: STSv1\nmode: enforce\nmx: mx1.provider.example\nmx: *.example.com\nmax_age: 604800\n"
        self.assertEqual(self.sts(pol, ("10 mail.example.com", "20 mx1.provider.example")).level, "ok")
        self.assertEqual(self.sts("version: STSv1\nmode: enforce\nmx: MAIL.Example.COM.\n").level, "ok")

    def test_pattern_covers_one_label(self):
        w = self.sts("version: STSv1\nmode: enforce\nmx: *.example.com\n", ("10 a.b.example.com",))
        self.assertEqual(w.level, "error")

    def test_mx_outside_policy(self):
        w = self.sts("version: STSv1\nmode: enforce\nmx: old.example.com\nmax_age: 604800\n")
        self.assertEqual((w.level, w.data["mx_outside"]), ("error", ["mail.example.com"]))
        w = self.sts("version: STSv1\nmode: testing\nmx: old.example.com\n", ("10 mail.example.com", "20 old.example.com"))
        self.assertEqual((w.level, w.data["mx_outside"]), ("warning", ["mail.example.com"]))

    def test_policy_without_mx(self):
        self.assertEqual(self.sts("version: STSv1\nmode: enforce\nmax_age: 1\n").level, "error")

    def test_no_mode(self):
        self.assertEqual(self.sts("version: STSv1\nmax_age: 1\n").level, "warning")

    def test_no_record(self):
        self.assertEqual(self.sts("", txt=False).level, "warning")

    def test_http_error(self):
        self.assertEqual(self.sts("", status=404).level, "warning")

    def test_unreachable_policy(self):
        s = fakes.company_zone()
        s[("_mta-sts.example.com", "TXT")] = ["v=STSv1; id=1"]
        ctx = fakes.context("example.com", s, {})
        checks._mx(ctx)
        self.assertEqual(checks._mta_sts(ctx)[0].level, "warning")


class TestTlsRpt(unittest.TestCase):
    def test_present_and_absent(self):
        s = fakes.company_zone()
        ctx = fakes.context("example.com", s)
        checks._mx(ctx)
        self.assertEqual(checks._tls_rpt(ctx)[0].level, "warning")
        s[("_smtp._tls.example.com", "TXT")] = ["v=TLSRPTv1; rua=mailto:t@example.com"]
        ctx = fakes.context("example.com", s)
        checks._mx(ctx)
        self.assertEqual(checks._tls_rpt(ctx)[0].level, "ok")


class TestFullRun(unittest.TestCase):
    def test_all_pass_gives_exit_0(self):
        s = fakes.company_zone()
        s[("_mta-sts.example.com", "TXT")] = ["v=STSv1; id=1"]
        s[("_smtp._tls.example.com", "TXT")] = ["v=TLSRPTv1; rua=mailto:t@example.com"]
        http = {"https://mta-sts.example.com/.well-known/mta-sts.txt": (200, {}, "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 604800\n")}
        ctx = fakes.context("example.com", s, http)
        w = checks.run_all(ctx)
        self.assertEqual([x.check for x in w], list(checks.CHECK_IDS))
        levels = {x.check: x.level for x in w}
        self.assertEqual(levels["mx.starttls"], "skipped")
        self.assertEqual(runner.exit_code(w), runner.EXIT_OK)

    def test_exit_codes(self):
        mk = lambda *levels: [R.Result(f"c{i}", lv) for i, lv in enumerate(levels)]
        self.assertEqual(runner.exit_code(mk("ok", "ok", "info", "skipped")), 0)
        self.assertEqual(runner.exit_code(mk("ok", "warning")), 1)
        self.assertEqual(runner.exit_code(mk("ok", "warning", "error")), 2)
        self.assertEqual(runner.exit_code(mk("critical")), 2)
        self.assertEqual(runner.exit_code(mk("skipped", "info")), 3)
        self.assertEqual(runner.exit_code([]), 3)

    def test_run_report_shape(self):
        s = fakes.company_zone()
        ctx = fakes.context("example.com", s)
        w = checks.run_all(ctx)
        d = w[0].as_dict()
        self.assertEqual(set(d), {"check", "status", "severity", "message", "data"})
        self.assertEqual(pick(checks.run_all(fakes.context("example.com", {("example.com", "MX"): "NXDOMAIN"})), "mx").severity, "critical")

    def test_dns_failure_everywhere_gives_exit_3(self):
        class Dead(fakes.FakeResolver):
            def query(self, name, rtype):
                return DnsAnswer([], "timeout")
        ctx = fakes.context("example.com", Dead({}))
        self.assertEqual(runner.exit_code(checks.run_all(ctx)), 3)

    def test_exception_in_a_check_becomes_skip(self):
        class Broken(fakes.FakeResolver):
            def query(self, name, rtype):
                if rtype == "MX":
                    raise RuntimeError("boom")
                return super().query(name, rtype)
        ctx = fakes.context("example.com", Broken(fakes.company_zone()))
        w = checks.run_all(ctx)
        self.assertEqual(pick(w, "mx").level, "skipped")
        self.assertEqual(pick(w, "mx").message, "internal error")

    def test_budget_exhaustion_becomes_skip(self):
        ctx = fakes.context("example.com", fakes.company_zone())
        ctx.budget.max_dns = 1
        w = checks.run_all(ctx)
        self.assertTrue(any(x.level == "skipped" for x in w))


if __name__ == "__main__":
    unittest.main()
