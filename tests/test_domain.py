"""Domain input normalization and the Public Suffix List."""
import unittest

from . import fakes
from mailsec_check import domain, psl


class TestNormalize(unittest.TestCase):
    def test_inputs(self):
        n = lambda t: domain.normalize_input(t, fakes.PSL)
        self.assertEqual(n("https://www.Example.COM/shop?x=1").name, "example.com")
        self.assertEqual(n("shop.example.com.au").organizational, "example.com.au")
        self.assertEqual(n("münchen.de").name, "xn--mnchen-3ya.de")
        self.assertEqual(n("example.com:8080").name, "example.com")
        self.assertEqual(n("user@example.com").name, "example.com")
        self.assertTrue(n("a.b.example.com").is_subdomain)
        self.assertFalse(n("example.com").is_subdomain)
        for bad in ("localhost", "127.0.0.1", "[::1]", "com.au", "com", "a", "", "host.local", "host.onion",
                    "ex ample.com", "-example.com", "a" * 64 + ".com", "example.123", "x.test"):
            with self.assertRaises(domain.InputError, msg=bad):
                n(bad)
        with self.assertRaises(domain.InputError):
            n(None)


class TestPSL(unittest.TestCase):
    def test_rules(self):
        l = psl.SuffixList(None)
        self.assertEqual(l.registrable("a.b.example.com.au"), "example.com.au")
        self.assertEqual(l.registrable("example.com"), "example.com")
        self.assertEqual(l.registrable("www.example.co.uk"), "example.co.uk")
        self.assertIsNone(l.registrable("co.uk"))
        self.assertEqual(l.registrable("x.unknowntld"), "x.unknowntld")
        self.assertEqual(l.source, "built-in")

    def test_file_with_wildcard_and_exception(self):
        import os
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".dat", delete=False, encoding="utf-8") as f:
            f.write("// comment\ntld\n*.wild.tld\n!ok.wild.tld\n")
            path = f.name
        try:
            l = psl.SuffixList(path)
            self.assertEqual(l.source, "file")
            self.assertEqual(l.registrable("a.b.wild.tld"), "a.b.wild.tld")
            self.assertEqual(l.registrable("x.ok.wild.tld"), "ok.wild.tld")
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
