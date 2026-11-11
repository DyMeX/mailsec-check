"""Target policy, budget, size-limited HTTP client, redirects and the SMTP probe class."""
import gzip
import http.server
import threading
import unittest

from . import fakes
from mailsec_check import net


class TestPolicy(unittest.TestCase):
    def test_forbidden(self):
        p = net.TargetPolicy()
        for ip in ("127.0.0.1", "10.1.2.3", "192.168.1.1", "172.16.0.1", "100.64.0.1", "100.127.255.254", "169.254.169.254",
                   "0.0.0.0", "224.0.0.1", "255.255.255.255", "::1", "fc00::1", "fe80::1", "::ffff:127.0.0.1", "::ffff:192.168.1.1",
                   "64:ff9b::7f00:1", "2002:7f00:1::", "2001:0:1::1", "198.18.0.1", "192.0.2.1", "203.0.113.5"):
            self.assertFalse(p.allowed(ip), ip)

    def test_allowed(self):
        p = net.TargetPolicy()
        for ip in ("8.8.8.8", "188.114.97.11", "1.1.1.1", "2606:4700::1111", "2a01:4f8::1"):
            self.assertTrue(p.allowed(ip), ip)
        self.assertFalse(p.allowed("not-an-ip"))
        self.assertTrue(p.port_ok(443) and p.port_ok(80) and not p.port_ok(8080) and not p.port_ok(25))

    def test_literal_ip_forms(self):
        r = fakes.FakeResolver({})
        p = net.TargetPolicy()
        for host in ("127.0.0.1", "2130706433", "0x7f000001", "0177.0.0.1", "[::1]", "::1", "100.64.0.1"):
            with self.assertRaises((net.ForbiddenTarget, net.NetworkError), msg=host):
                net.resolve_host(host, r, p)

    def test_rebinding_and_mixed_addresses(self):
        r = fakes.FakeResolver({("bad.example.com", "A"): ["93.184.216.34", "10.0.0.5"]})
        with self.assertRaises(net.ForbiddenTarget):
            net.resolve_host("bad.example.com", r, net.TargetPolicy())
        r = fakes.FakeResolver({("ok.example.com", "A"): ["93.184.216.34"], ("ok.example.com", "AAAA"): ["fc00::1"]})
        with self.assertRaises(net.ForbiddenTarget):
            net.resolve_host("ok.example.com", r, net.TargetPolicy())
        r = fakes.FakeResolver({("ok.example.com", "A"): ["93.184.216.34"]})
        self.assertEqual(net.resolve_host("ok.example.com", r, net.TargetPolicy()), ["93.184.216.34"])

    def test_redirect_to_private_and_foreign_targets_rejected(self):
        """Ports other than 80/443, private targets and non-HTTP schemes are rejected before connecting."""
        r = fakes.FakeResolver({("ok.example.com", "A"): ["93.184.216.34"], ("internal.example.com", "A"): ["10.0.0.1"]})
        c = net.HttpClient(r, net.TargetPolicy(), net.Budget(5, 10, 10, 0), "t", connect_s=0.2)
        for url in ("https://ok.example.com:8443/", "http://internal.example.com/", "ftp://ok.example.com/", "http://user@ok.example.com/"):
            with self.assertRaises(net.ForbiddenTarget, msg=url):
                c.fetch(url)


class TestBudget(unittest.TestCase):
    def test_limits(self):
        b = net.Budget(deadline_s=5, max_http=2, max_dns=1, pause_s=0)
        b.http("a")
        b.http("a")
        with self.assertRaises(net.BudgetExceeded):
            b.http("a")
        b.dns()
        with self.assertRaises(net.BudgetExceeded):
            b.dns()
        b2 = net.Budget(deadline_s=0, max_http=5, max_dns=5)
        with self.assertRaises(net.BudgetExceeded):
            b2.http("x")
        self.assertEqual(b2.timeout(10), 0.5)


class _Server(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == "/bomb":
            data = gzip.compress(b"A" * 5_000_000)
            self.send_response(200)
            self.send_header("Content-Encoding", "gzip")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        elif self.path == "/big":
            self.send_response(200)
            self.send_header("Content-Length", str(3_000_000))
            self.end_headers()
            try:
                self.wfile.write(b"B" * 3_000_000)
            except OSError:
                pass
        elif self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "http://other.example/")
            self.end_headers()
        elif self.path == "/loop":
            self.send_response(302)
            self.send_header("Location", "/loop")
            self.end_headers()
        else:
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", "5")
            self.end_headers()
            self.wfile.write(b"hello")


class TestLocalClient(unittest.TestCase):
    """Real sockets on localhost: a policy that allows private addresses (tests only) and a resolver pointing the name at 127.0.0.1."""

    @classmethod
    def setUpClass(cls):
        cls.srv = http.server.HTTPServer(("127.0.0.1", 0), _Server)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def client(self, max_b=256 * 1024):
        r = fakes.FakeResolver({("test.example", "A"): ["127.0.0.1"]})
        p = net.TargetPolicy(ports=(80, 443, self.port), allow_private=True)
        return net.HttpClient(r, p, net.Budget(10, 20, 20, 0), "t", connect_s=1, read_s=2, max_b=max_b)

    def test_plain(self):
        o = self.client().fetch(f"http://test.example:{self.port}/")
        self.assertEqual((o.status, o.body, o.ip), (200, b"hello", "127.0.0.1"))

    def test_gzip_bomb(self):
        o = self.client(max_b=100_000).fetch(f"http://test.example:{self.port}/bomb")
        self.assertTrue(o.truncated)
        self.assertLessEqual(len(o.body), 100_000)

    def test_large_response(self):
        o = self.client(max_b=50_000).fetch(f"http://test.example:{self.port}/big")
        self.assertTrue(o.truncated)
        self.assertEqual(len(o.body), 50_000)

    def test_foreign_host_not_followed(self):
        o = self.client().fetch(f"http://test.example:{self.port}/redirect")
        self.assertEqual(o.status, 302)
        self.assertEqual(o.header("Location"), "http://other.example/")

    def test_redirect_loop_is_bounded(self):
        o = self.client().fetch(f"http://test.example:{self.port}/loop")
        self.assertEqual(o.status, 302)
        self.assertEqual(len(o.redirects), 3)

    def test_redirects_none(self):
        o = self.client().fetch(f"http://test.example:{self.port}/loop", redirects="none")
        self.assertEqual(o.status, 302)
        self.assertEqual(len(o.redirects), 0)


class _FakeSmtp:
    """Minimal SMTP server on localhost: greets, answers EHLO, optionally advertises STARTTLS and then refuses it."""

    def __init__(self, advertise_starttls):
        import socket
        self.advertise = advertise_starttls
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]
        self.commands = []
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self):
        conn, _ = self.sock.accept()
        f = conn.makefile("rwb")
        f.write(b"220 fake ESMTP\r\n")
        f.flush()
        for raw in f:
            cmd = raw.decode().strip()
            self.commands.append(cmd.split()[0].upper() if cmd else "")
            verb = self.commands[-1]
            if verb == "EHLO":
                f.write(b"250-fake\r\n250-STARTTLS\r\n250 SIZE 1000\r\n" if self.advertise else b"250-fake\r\n250 SIZE 1000\r\n")
            elif verb == "STARTTLS":
                f.write(b"454 TLS not available\r\n")
            elif verb == "QUIT":
                f.write(b"221 bye\r\n")
                f.flush()
                break
            else:
                f.write(b"502 no\r\n")
            f.flush()
        conn.close()
        self.sock.close()


class TestSMTP(unittest.TestCase):
    def probe(self, advertise):
        srv = _FakeSmtp(advertise)
        # the probe always uses port 25; point PinnedSMTP at the fake port for this test
        orig = net.PinnedSMTP.__init__

        def init(self_, ip, host, port=25, timeout=12, local_hostname=None):
            orig(self_, ip, host, srv.port, timeout, local_hostname)
        net.PinnedSMTP.__init__ = init
        try:
            return net.probe_starttls("mail.example.com", "127.0.0.1", "test", timeout=3), srv
        finally:
            net.PinnedSMTP.__init__ = orig

    def test_no_starttls_offered(self):
        w, srv = self.probe(False)
        self.assertTrue(w["connected"])
        self.assertFalse(w["starttls_offered"])
        self.assertEqual(srv.commands, ["EHLO", "QUIT"])   # no MAIL FROM, nothing beyond EHLO and QUIT

    def test_starttls_offered_but_refused(self):
        w, srv = self.probe(True)
        self.assertTrue(w["starttls_offered"])
        self.assertFalse(w["starttls_ok"])
        self.assertIn("STARTTLS", w["error"])
        self.assertNotIn("MAIL", srv.commands)

    def test_get_socket_exists(self):
        import smtplib
        self.assertTrue(hasattr(smtplib.SMTP, "_get_socket"))
        self.assertIn("_get_socket", net.PinnedSMTP.__dict__)

    def test_probe_reports_unreachable_without_raising(self):
        w = net.probe_starttls("mail.example.com", "127.0.0.1", "test", timeout=1)
        self.assertFalse(w["connected"])
        self.assertIsNotNone(w["error"])


if __name__ == "__main__":
    unittest.main()
