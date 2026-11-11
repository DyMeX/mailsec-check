# mailsec-check

Passive e-mail security checks for a domain, from the command line.

```
mailsec-check example.org
```

It looks at the DNS records and mail servers of a domain and prints one line per check: PASS, WARN or FAIL, what
was found, and what to change. It can also print JSON and sets an exit code, so it can run in a script or a CI job.

The checks are passive. The tool does DNS lookups, fetches one MTA-STS policy file over HTTPS, and opens at most
two SMTP connections that stop after EHLO and STARTTLS. It never sends mail and never authenticates.

## What it checks

| Check id | PASS means | Typical fix |
|---|---|---|
| `mx` | The domain has MX records and every MX host (first 5) resolves to an address. A Null MX is reported as INFO. | Add or repair MX records; use a Null MX (`0 .`) and `v=spf1 -all` for a domain that sends and receives no mail. |
| `spf.record` | Exactly one `v=spf1` record exists and every term is known. | Publish one SPF record; merge duplicates; remove unknown terms. |
| `spf.all` | The record ends in `-all`, or has a `redirect=`. | Replace `~all` / `?all` with `-all` once the sender list is complete; never use `+all`. |
| `spf.lookups` | At most 10 DNS-querying terms (include, a, mx, ptr, exists, redirect), at most 2 empty (void) lookups, no `ptr`. | Flatten or drop includes; remove `ptr`. |
| `dkim` | At least one DKIM key is found under a known selector, with no weak key. | Enable DKIM signing in the mail system; use RSA 2048 or Ed25519; remove `t=y` when done testing. |
| `dmarc.record` | Exactly one `v=DMARC1` record exists at `_dmarc.<domain>` (or at the organizational domain for a subdomain). | Publish a DMARC record. |
| `dmarc.policy` | `p=reject` with `pct` 100 (or absent) and without `t=y`. | Move from `none` to `quarantine` to `reject` after reading the reports. |
| `dmarc.rua` | A `rua=` address exists; addresses in other domains have the authorization record. | Add `rua=mailto:...`; for an address in another domain publish `<domain>._report._dmarc.<that domain>` = `v=DMARC1`. |
| `mta_sts` | `_mta-sts` TXT record exists, the policy file returns 200, `mode: enforce`, and every MX host matches an `mx:` line. | Publish `https://mta-sts.<domain>/.well-known/mta-sts.txt`; fix `mx:` lines; switch `testing` to `enforce`. |
| `tls_rpt` | A `v=TLSRPTv1` record exists at `_smtp._tls.<domain>`. | Publish a TLS-RPT record with a `rua=` address. |
| `mx.starttls` | The MX hosts offer STARTTLS with a certificate that verifies against the MX name and is valid for at least 14 more days. | Enable STARTTLS; install a certificate that matches the MX host name; renew it. |
| `mx.ptr` | The first MX host's first IPv4 address has a PTR record that equals the MX name or resolves back to the address. | Set reverse DNS for the mail server address. |

Messages for WARN and FAIL results include the suggested fix where the check has one.

## Install

Requires Python 3.10 or newer and `dnspython` (installed automatically).

```
pip install .
# optional: exact RSA key size for DKIM keys
pip install ".[keys]"
```

Without the optional `cryptography` package, the DKIM key size is estimated from the length of the decoded public
key (under 100 bytes: 256 bits, under 200: 1024, under 420: 2048, otherwise 4096).

You can also run it from a checkout without installing: `python -m mailsec_check <domain>`.

## Usage

```
mailsec-check <domain> [--json] [--selector NAME] [--no-starttls] [--resolver IP[,IP]]
                       [--ehlo NAME] [--deadline SECONDS] [--psl-file PATH] [--verbose]
```

| Option | Meaning |
|---|---|
| `--json` | Print the full result as JSON instead of the text report. |
| `--selector NAME` | Extra DKIM selector to try first (the `s=` value in a `DKIM-Signature` header). Up to 3, repeatable. Also accepts `s=name` and `name._domainkey`. |
| `--no-starttls` | Do not connect to MX hosts on port 25. The `mx.starttls` check is then SKIP. |
| `--resolver` | DNS resolvers to query. Default `1.1.1.1,9.9.9.9`. The system resolver is not used. |
| `--ehlo` | Host name sent in EHLO during the STARTTLS probe. Default `localhost`. |
| `--deadline` | Overall time limit in seconds. Default 90. |
| `--psl-file` | Public Suffix List file. See limitations. |
| `--verbose` | Print internal notes to stderr (errors that made a check SKIP). |

Input may also be a URL or an address; it is reduced to the domain. IP addresses, single-label names,
special-use names (`.local`, `.test`, `.onion`, ...) and bare public suffixes are rejected.

### Example output

Real runs (results change when the domains change their DNS):

```
$ mailsec-check gmail.com
mailsec-check 0.1.0  gmail.com  (6.6 s, 95 DNS queries, 1 network connections)

[PASS]   mx            Email: Google Workspace
[PASS]   spf.record    An SPF record exists and its syntax is valid.
[PASS]   spf.all       Policy through redirect=_spf.google.com.
[PASS]   spf.lookups   1 of 10 allowed DNS lookups.
[WARN]   dkim          No DKIM key found under the selectors used by Google Workspace, nor under other common names (73). Either DKIM is not enabled, or the domain uses a custom selector: pass it with --selector (the s= tag of the DKIM-Signature header in a message sent from the domain).
[PASS]   dmarc.record  A DMARC record exists.
[WARN]   dmarc.policy  p=none: monitoring only, spoofing is not blocked. After reviewing the reports move to quarantine, then reject.
[PASS]   dmarc.rua     Aggregate reports (rua) are being sent.
[PASS]   mta_sts       MTA-STS in enforce mode.
[PASS]   tls_rpt       TLS-RPT: reports on encryption problems are being sent.
[PASS]   mx.starttls   Email at a large provider (Google Workspace) - STARTTLS and certificates are standard there (not probed).
[PASS]   mx.ptr        PTR 142.250.147.27 -> rd-in-f27.1e100.net (matches the address).

10 pass, 2 warn, 0 fail, 0 skipped, 0 not applicable. Exit code 1.
```

The `dkim` warning for gmail.com is a limit of selector guessing, not a statement about Google: the domain signs
with selectors that are not in the built-in list (see limitations).

```
$ mailsec-check proton.me
mailsec-check 0.1.0  proton.me  (6.2 s, 48 DNS queries, 1 network connections)

[PASS]   mx            Email: Proton Mail
[PASS]   spf.record    An SPF record exists and its syntax is valid.
[WARN]   spf.all       "~all" (softfail): senders outside the list are only marked. Once the list of senders is confirmed, change it to "-all".
[PASS]   spf.lookups   2 of 10 allowed DNS lookups.
[PASS]   dkim          DKIM: protonmail (rsa 2048), protonmail2 (rsa 2048)
[PASS]   dmarc.record  A DMARC record exists.
[WARN]   dmarc.policy  p=quarantine: spoofed email goes to spam at most receivers. The goal is p=reject.
[WARN]   dmarc.rua     No rua - you get no reports on who sends email on behalf of the domain.
[PASS]   mta_sts       MTA-STS in enforce mode.
[PASS]   tls_rpt       TLS-RPT: reports on encryption problems are being sent.
[PASS]   mx.starttls   Email at a large provider (Proton Mail) - STARTTLS and certificates are standard there (not probed).
[PASS]   mx.ptr        PTR 176.119.200.128 -> mail.protonmail.ch.

9 pass, 3 warn, 0 fail, 0 skipped, 0 not applicable. Exit code 1.
```

```
$ mailsec-check example.com
mailsec-check 0.1.0  example.com  (0.2 s, 3 DNS queries, 0 network connections)

[INFO]   mx            The domain declares that it does not accept email (Null MX). Only the protection against spoofing is checked.
[PASS]   spf.record    An SPF record exists and its syntax is valid.
[PASS]   spf.all       "-all": email from outside the list is rejected.
[PASS]   spf.lookups   0 of 10 allowed DNS lookups.
[INFO]   dkim          Not applicable: domain without email (Null MX).
[PASS]   dmarc.record  A DMARC record exists.
[PASS]   dmarc.policy  p=reject: spoofed messages are rejected.
[WARN]   dmarc.rua     No rua - you get no reports on who sends email on behalf of the domain.
[INFO]   mta_sts       Not applicable: domain without MX.
[INFO]   tls_rpt       Not applicable: domain without MX.
[INFO]   mx.starttls   Not applicable: domain without MX.
[INFO]   mx.ptr        Not applicable: domain without MX.

5 pass, 1 warn, 0 fail, 0 skipped, 6 not applicable. Exit code 1.
```

## Exit codes

| Code | Meaning |
|---|---|
| 0 | No WARN or FAIL. SKIP and INFO lines do not change the code. |
| 1 | At least one WARN, no FAIL. |
| 2 | At least one FAIL. |
| 3 | The tool could not run: invalid input, a missing dependency, or no check produced PASS, WARN or FAIL (for example every DNS query timed out). |

Statuses: PASS, WARN, FAIL, INFO (not applicable, for example a domain with a Null MX), SKIP (the check could not
be completed, for example port 25 is blocked or a DNS query timed out).

## JSON output

```json
{
  "tool": "mailsec-check",
  "version": "0.1.0",
  "domain": "example.com",
  "domain_unicode": "example.com",
  "organizational_domain": "example.com",
  "duration_s": 0.1,
  "exit_code": 1,
  "summary": {"pass": 5, "warn": 1, "fail": 0, "info": 6, "skip": 0},
  "checks": [
    {"check": "spf.all", "status": "PASS", "severity": null,
     "message": "\"-all\": email from outside the list is rejected.",
     "data": {"record": "v=spf1 -all", "lookups": 0, "void": 0, "redirect": null}}
  ],
  "context": {"mail_provider": null, "null_mx": true},
  "budget": {"http": 0, "dns": 3},
  "log": []
}
```

- `status` is one of `PASS`, `WARN`, `FAIL`, `INFO`, `SKIP`.
- `severity` is `"critical"` or `"error"` for FAIL results and `null` otherwise. Critical findings are: NXDOMAIN, no MX
  host with an address, `+all` in SPF, a missing DMARC record on a domain that receives mail, and an MX host without STARTTLS.
- `data` holds the evidence for the check (the record found, counted lookups, the probed hosts, TLS details, and so on).
  Its keys depend on the check and are not a stable interface yet.
- `log` holds internal notes about errors that made a check SKIP.

## What it deliberately does not do

- It is not an open-relay tester: it never issues `MAIL FROM`, `RCPT TO` or `DATA`.
- It is not a blocklist checker: it does not look up the IP addresses of the domain in DNSBLs.
- It does not authenticate to anything and sends no mail.
- It does not check DNSSEC, CAA, certificates of web sites or anything outside the mail group.
- It does not connect to private, loopback, link-local, shared-range or literal IP addresses. A mail or policy host
  that resolves to such an address is rejected; a name with a mix of public and private addresses is rejected as a whole.
- It does not read mail or verify that DKIM signatures on real messages are valid.

## Limits and known behavior

- DKIM selectors cannot be listed in DNS. The code tries these names under `<selector>._domainkey.<domain>`, in
  this order: selectors given with `--selector`, selectors known for the detected mail provider, then 73 common
  names (`default`, `selector1`, `google`, `k1`, `s1`, and so on, in `mailsec_check/providers.py`).
  The tail of that list (everything after the first 30 names that follow the extra and provider selectors) is tried only when nothing was found earlier. The scan stops
  after 3 keys. A random selector is queried first; if DNS answers it with a key (wildcard), the check is WARN and
  no selector is tried.
  If nothing is found the result is SKIP, not FAIL, because a selector with its own name (for example one with a
  date) cannot be guessed. Only when the mail provider is known and its selectors are listed, a miss is WARN.
  For OVH the result is always SKIP on a miss, because its selectors contain a service identifier.
- A key counts as weak when `p=` is empty (revoked), when `t=y` is set, or when an RSA key is shorter than 2048 bits.
- STARTTLS is probed on the first 2 MX hosts by priority, one connection each, preferring the IPv4 address.
  The certificate is verified against the MX host name with the system trust store. MX hosts of a few large providers
  (listed in `providers.py` with the trusted flag) are not probed and count as PASS.
  Outbound port 25 is blocked on many networks (home and cloud). Then the check is SKIP.
  If a server answers EHLO with a code other than 250, the check reports that STARTTLS is not offered.
- MTA-STS: the policy is fetched with a 16 KiB limit and redirects are not followed. The certificate of the policy host
  is not validated (the connection is accepted with a verification error, and the error is not reported).
  `max_age` is not evaluated.
- `mx.ptr` looks only at the first MX host and its first IPv4 address.
- At most 5 MX hosts are resolved. SPF lookup counting follows includes up to depth 10 and 30 queries.
- DMARC for a subdomain without its own record falls back to the organizational domain, using `sp=` if present.
  The organizational domain comes from the Public Suffix List. The tool reads the system file when it finds one
  (for example `/usr/share/publicsuffix/public_suffix_list.dat`, or `MAILSEC_PSL_FILE`, or `--psl-file`); otherwise it
  uses a small built-in list that is not complete. Rare suffixes can therefore be misjudged without the file.
- DNS goes to the resolvers `1.1.1.1` and `9.9.9.9` (override with `--resolver`), not to the system resolver. Run limits:
  90 s, 320 DNS queries, 25 HTTP requests.
- The tool runs the checks one after another; a full run takes from under a second to about 30 seconds,
  mostly the DKIM selector queries and the connection timeout on port 25.

## Tests

```
python -m unittest discover -s tests -t .
```

The tests run offline with fake DNS and HTTP responses; the HTTP client tests use a local server on 127.0.0.1.

## License

MIT, see `LICENSE`.
