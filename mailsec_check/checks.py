"""Mail checks: MX, SPF (with recursive include and lookup counting), DKIM (common selectors), DMARC, MTA-STS,
TLS-RPT, STARTTLS and certificate of the MX hosts, PTR. No mail is sent."""
import base64
import re
import secrets

from . import net, providers
from . import result as R

CHECK_IDS = ("mx", "spf.record", "spf.all", "spf.lookups", "dkim", "dmarc.record", "dmarc.policy", "dmarc.rua",
             "mta_sts", "tls_rpt", "mx.starttls", "mx.ptr")


def run_all(ctx):
    w = []
    w += R.guarded(ctx, _mx, ["mx"])
    w += R.guarded(ctx, _spf, ["spf.record", "spf.all", "spf.lookups"])
    w += R.guarded(ctx, _dkim, ["dkim"])
    w += R.guarded(ctx, _dmarc, ["dmarc.record", "dmarc.policy", "dmarc.rua"])
    w += R.guarded(ctx, _mta_sts, ["mta_sts"])
    w += R.guarded(ctx, _tls_rpt, ["tls_rpt"])
    w += R.guarded(ctx, _starttls, ["mx.starttls"])
    w += R.guarded(ctx, _ptr, ["mx.ptr"])
    return w


# --- MX
def _mx(ctx):
    d = ctx.domain.name
    ans = ctx.resolver.query(d, "MX")
    if ans.state in ("timeout", "error"):
        return [R.skipped("mx", f"DNS: {ans.state}")]
    if ans.state == "nxdomain":
        ctx.shared["mx"] = []
        return [R.critical("mx", "The domain does not exist in DNS (NXDOMAIN).")]
    mx = []
    for r in ans.records:
        parts = r.split(None, 1)
        try:
            pref = int(parts[0])
        except (ValueError, IndexError):
            continue
        name = parts[1].strip().rstrip(".").lower() if len(parts) > 1 else ""
        mx.append((pref, name))
    mx.sort()
    if len(mx) == 1 and mx[0][1] == "":
        ctx.shared["mx"], ctx.shared["null_mx"] = [], True
        return [R.info("mx", "The domain declares that it does not accept email (Null MX). Only the protection against spoofing is checked.")]
    if not mx:
        a = ctx.resolver.query(d, "A")
        ctx.shared["mx"] = []
        if a.ok:
            # mail goes to the A address: STARTTLS, PTR, MTA-STS and TLS-RPT apply, but are not checked
            ctx.shared["implicit_mx"] = True
            return [R.warn("mx", "No MX record - email goes to the A address of the domain (implicit MX). If the domain is meant to "
                                 "receive email, add an MX record; if not, add a Null MX (0 .) and SPF \"v=spf1 -all\".")]
        return [R.error("mx", "No MX record and no A address - the domain does not receive email.")]
    ctx.shared["mx"] = mx[:5]
    resolved, mx_ips = 0, {}
    for _pref, name in mx[:5]:
        addresses = []
        for rtype in ("A", "AAAA"):
            o = ctx.resolver.query(name, rtype)
            if o.ok:
                addresses += o.records
        if addresses:
            resolved += 1
            mx_ips[name] = addresses
    ctx.shared["mx_ips"] = mx_ips
    provider, selectors, trusted = providers.provider_for_mx([n for _, n in mx])
    ctx.shared["mail_provider"] = provider
    ctx.shared["provider_selectors"] = selectors
    ctx.shared["provider_trusted"] = trusted
    data = {"mx": [f"{p} {n}" for p, n in mx], "provider": provider}
    if resolved == 0:
        return [R.critical("mx", "No MX server has an IP address - email to the domain is not delivered.", **data)]
    if resolved < len(mx[:5]):
        return [R.warn("mx", f"Some MX servers do not resolve ({resolved} of {len(mx[:5])}).", **data)]
    text = f"Email: {provider}" if provider else R.plural(len(mx), "MX server")
    return [R.ok("mx", text, **data)]


# --- SPF
_MECH = re.compile(r"^([+\-~?]?)(all|include|a|mx|ptr|ip4|ip6|exists)(?:[:=](.*))?$", re.I)
_MOD = re.compile(r"^(redirect|exp)=(.+)$", re.I)


def _spf_records(ctx, name):
    ans = ctx.resolver.query(name, "TXT")
    if ans.state in ("timeout", "error"):
        return None, ans.state
    return [r for r in ans.records if r.lower().startswith("v=spf1") and (len(r) == 6 or r[6] == " ")], ans.state


def _spf_lookups(ctx, name, st, depth=0):
    """Recursively counts DNS lookups (include, a, mx, ptr, exists, redirect) and empty (void) references."""
    if depth > 10 or st["queries"] >= st["limit"]:
        st["incomplete"] = True
        return
    records, _ = _spf_records(ctx, name)
    st["queries"] += 1
    if not records:
        st["void"] += 1
        return
    if len(records) > 1:
        st["multiple"].append(name)
    for term in records[0].split()[1:]:
        m = _MECH.match(term)
        if m:
            mech, arg = m.group(2).lower(), m.group(3)
            if mech in ("include", "a", "mx", "ptr", "exists"):
                st["lookups"] += 1
                if mech == "ptr":
                    st["ptr"] = True
                if mech == "include" and arg and "%{" not in arg:
                    _spf_lookups(ctx, arg.strip("."), st, depth + 1)
            if "%{" in term:
                st["macros"] = True
            continue
        m = _MOD.match(term)
        if m:
            if m.group(1).lower() == "redirect":
                st["lookups"] += 1
                st["redirect"] = m.group(2)
                _spf_lookups(ctx, m.group(2).strip("."), st, depth + 1)
            continue
        st["unknown"].append(term[:40])


def _spf(ctx):
    d = ctx.domain.name
    ids = ("spf.record", "spf.all", "spf.lookups")
    records, dns_state = _spf_records(ctx, d)
    if records is None:
        return [R.skipped(k, f"DNS: {dns_state}") for k in ids]
    if not records:
        return [R.error("spf.record", "No SPF record. Receivers cannot check who is allowed to send email from this domain."),
                R.skipped("spf.all", "no SPF"), R.skipped("spf.lookups", "no SPF")]
    if len(records) > 1:
        return [R.error("spf.record", f"{R.plural(len(records), 'SPF record')} instead of one - receivers treat this as an error (permerror) and ignore all of them.",
                        records=records),
                R.skipped("spf.all", "multiple records"), R.skipped("spf.lookups", "multiple records")]
    record = records[0]
    st = {"lookups": 0, "void": 0, "queries": 0, "limit": int(ctx.config.get("SPF_MAX_QUERIES", 30)), "unknown": [],
          "multiple": [], "ptr": False, "macros": False, "redirect": None, "incomplete": False}
    _spf_lookups(ctx, d, st)
    w = []
    data = {"record": record, "lookups": st["lookups"], "void": st["void"], "redirect": st["redirect"]}
    if st["unknown"]:
        w.append(R.error("spf.record", f"Unknown elements in SPF: {', '.join(st['unknown'][:3])} - the record may be ignored.", **data))
    elif len(record) > 255 * 2:
        w.append(R.warn("spf.record", "The SPF record is very long.", **data))
    else:
        w.append(R.ok("spf.record", "An SPF record exists and its syntax is valid.", **data))
    # the "all" qualifier (last term) or redirect
    terms = record.split()[1:]
    all_term = next((x for x in reversed(terms) if _MECH.match(x) and _MECH.match(x).group(2).lower() == "all"), None)
    if all_term is None and st["redirect"]:
        w.append(R.ok("spf.all", f"Policy through redirect={st['redirect']}.", **data))
    elif all_term is None:
        w.append(R.warn("spf.all", "SPF record without \"all\" - neutral by default, which means no protection against spoofing.", **data))
    else:
        q = (_MECH.match(all_term).group(1) or "+")
        if q == "-":
            w.append(R.ok("spf.all", "\"-all\": email from outside the list is rejected.", **data))
        elif q == "~":
            w.append(R.warn("spf.all", "\"~all\" (softfail): senders outside the list are only marked. Once the list "
                                       "of senders is confirmed, change it to \"-all\".", **data))
        elif q == "?":
            w.append(R.warn("spf.all", "\"?all\" (neutral): SPF does not protect against spoofing.", **data))
        else:
            w.append(R.critical("spf.all", "\"+all\": any server in the world can send email on behalf of the domain.", **data))
    if st["lookups"] > 10:
        w.append(R.error("spf.lookups", f"{st['lookups']} DNS lookups in SPF (limit 10) - receivers return permerror and ignore SPF.", **data))
    elif st["void"] > 2:
        w.append(R.warn("spf.lookups", f"{st['void']} empty lookups (void) in SPF (limit 2).", **data))
    elif st["ptr"]:
        w.append(R.warn("spf.lookups", "The \"ptr\" mechanism is deprecated and slow; remove it from SPF.", **data))
    elif st["incomplete"]:
        w.append(R.warn("spf.lookups", "Could not count all lookups (recursion too deep).", **data))
    else:
        w.append(R.ok("spf.lookups", f"{st['lookups']} of 10 allowed DNS lookups.", **data))
    return w


# --- DKIM
_TAG = re.compile(r"\s*([a-z]+)\s*=\s*([^;]*)")


def _tags(record):
    return {m.group(1).lower(): m.group(2).strip() for m in _TAG.finditer(record)}


def _key_length(p_b64):
    try:
        der = base64.b64decode("".join(p_b64.split()) + "==", validate=False)
    except (ValueError, TypeError):
        return None
    try:
        from cryptography.hazmat.primitives.serialization import load_der_public_key
        key = load_der_public_key(der)
        return getattr(key, "key_size", 256)
    except Exception:   # noqa: BLE001 - without cryptography: estimate from the DER length
        n = len(der)
        if n < 100:
            return 256
        if n < 200:
            return 1024
        if n < 420:
            return 2048
        return 4096


def _dkim(ctx):
    d = ctx.domain.name
    if ctx.shared.get("null_mx"):
        return [R.not_applicable("dkim", "domain without email (Null MX)")]
    random_selector = "zz" + secrets.token_hex(4)
    wild = ctx.resolver.query(f"{random_selector}._domainkey.{d}", "TXT")
    if wild.ok and any("p=" in r for r in wild.records):
        return [R.warn("dkim", "DNS answers with a DKIM record for any selector (wildcard) - it is not possible to check which "
                               "selectors really exist.", wildcard=True)]
    extra = list(ctx.option("extra_selectors", []) or [])
    listing = extra + list(ctx.shared.get("provider_selectors", [])) + providers.COMMON_SELECTORS
    seen, selectors = set(), []
    for s in listing:
        s = s.strip().lower()
        if s and s not in seen:
            seen.add(s)
            selectors.append(s)
    found, weak, checked, stopped = [], [], 0, False
    core = len(extra) + len(ctx.shared.get("provider_selectors", [])) + 30
    for nr, s in enumerate(selectors):
        if nr >= core and (found or weak):
            break   # the tail of the list is tried only when the core found nothing
        try:
            ans = ctx.resolver.query(f"{s}._domainkey.{d}", "TXT")
        except net.BudgetExceeded:
            stopped = True
            break
        checked += 1
        if ans.state in ("timeout",):
            continue
        rec = next((r for r in ans.records if "p=" in r.replace(" ", "")), None) if ans.ok else None
        if rec is None:
            continue
        tg = _tags(rec)
        p = tg.get("p", "")
        item = {"selector": s, "k": tg.get("k", "rsa"), "test_mode": "y" in tg.get("t", "")}
        if not p:
            item["note"] = "key revoked (empty p=)"
            weak.append(item)
        else:
            bits = _key_length(p) if item["k"] == "rsa" else 256
            item["bits"] = bits
            if item["k"] == "rsa" and bits and bits < 2048:
                item["note"] = f"RSA key of {bits} bits (2048 recommended)"
                weak.append(item)
            elif item["test_mode"]:
                item["note"] = "test mode (t=y)"
                weak.append(item)
            else:
                found.append(item)
        if len(found) + len(weak) >= 3:
            break
    data = {"found": found, "weak": weak, "selectors_checked": checked}
    if found and not weak:
        return [R.ok("dkim", "DKIM: " + ", ".join(f"{z['selector']} ({z['k']} {z.get('bits', '')})".replace(" )", ")") for z in found), **data)]
    if found or weak:
        notes = "; ".join(f"{s['selector']}: {s['note']}" for s in weak)
        return [R.warn("dkim", f"DKIM detected, but with reservations: {notes}", **data)]
    suffix = " (stopped - run limit)" if stopped else ""
    individual = providers.INDIVIDUAL_SELECTORS.get(ctx.shared.get("mail_provider") or "")
    if individual:
        return [R.skipped("dkim", individual, **data)]
    provider = ctx.shared.get("mail_provider")
    if provider and ctx.shared.get("provider_selectors"):
        return [R.warn("dkim", f"No DKIM key found under the selectors used by {provider}, nor under other common names "
                               f"({checked}){suffix}. Either DKIM is not enabled, or the domain uses a custom selector: pass it with --selector (the s= tag of the DKIM-Signature header in a message sent from the domain).", **data)]
    return [R.skipped("dkim", f"No DKIM key found under {checked} common selectors{suffix}. The selector may have its own "
                              "name (e.g. with a date) that cannot be guessed from outside, so this is not proof that there is no signature. "
                              "The selector is the s= value in the DKIM-Signature header of any sent message - pass it with "
                              "--selector and the key will be checked.", **data)]


# --- DMARC
def _dmarc(ctx):
    d = ctx.domain.name
    has_mail = bool(ctx.shared.get("mx")) and not ctx.shared.get("null_mx")
    place = d
    ans = ctx.resolver.query(f"_dmarc.{d}", "TXT")
    records = [r for r in ans.records if r.lower().replace(" ", "").startswith("v=dmarc1")] if ans.ok else []
    if not records and ctx.domain.is_subdomain:
        o2 = ctx.resolver.query(f"_dmarc.{ctx.domain.organizational}", "TXT")
        if o2.ok:
            records = [r for r in o2.records if r.lower().replace(" ", "").startswith("v=dmarc1")]
            place = ctx.domain.organizational
    if ans.state in ("timeout", "error") and not records:
        return [R.skipped(k, f"DNS: {ans.state}") for k in ("dmarc.record", "dmarc.policy", "dmarc.rua")]
    if not records:
        text = "No DMARC record - anyone can send messages \"from\" this domain, and receivers get no instruction on what to do with them."
        return [(R.critical if has_mail else R.error)("dmarc.record", text),
                R.skipped("dmarc.policy", "there is no DMARC record to assess"), R.skipped("dmarc.rua", "there is no DMARC record to assess")]
    if len(records) > 1:
        return [R.error("dmarc.record", f"{R.plural(len(records), 'DMARC record')} instead of one - receivers ignore all of them.", records=records),
                R.skipped("dmarc.policy", "multiple records"), R.skipped("dmarc.rua", "multiple records")]
    tg = _tags(records[0])
    data = {"record": records[0], "place": place, "p": tg.get("p"), "sp": tg.get("sp"), "pct": tg.get("pct"), "t": tg.get("t"), "rua": tg.get("rua")}
    w = [R.ok("dmarc.record", "A DMARC record exists" + (f" (inherited from {place})" if place != d else "") + ".", **data)]
    p = (tg.get("p") or "").lower()
    if place != d and tg.get("sp"):
        p = tg["sp"].lower()
    try:
        pct = int(tg.get("pct", "100"))
    except ValueError:
        pct = 100
    if (tg.get("t") or "n").strip().lower() == "y" and p in ("reject", "quarantine"):
        # RFC 9989: test mode, receivers apply a policy one level milder (reject -> quarantine, quarantine -> none)
        lower = "quarantine" if p == "reject" else "none"
        w.append(R.warn("dmarc.policy", f"p={p} with t=y (RFC 9989 test mode): receivers apply p={lower}. After testing, remove t=y.", **data))
    elif p == "reject" and pct >= 100:
        w.append(R.ok("dmarc.policy", "p=reject: spoofed messages are rejected.", **data))
    elif p == "quarantine" and pct >= 100:
        w.append(R.warn("dmarc.policy", "p=quarantine: spoofed email goes to spam at most receivers. The goal is p=reject.", **data))
    elif p in ("reject", "quarantine"):
        w.append(R.warn("dmarc.policy", f"p={p}, but pct={pct}: the policy is applied to only part of the messages.", **data))
    elif p == "none":
        w.append(R.warn("dmarc.policy", "p=none: monitoring only, spoofing is not blocked. After reviewing the reports "
                                        "move to quarantine, then reject.", **data))
    else:
        w.append(R.error("dmarc.policy", "Missing or invalid p= tag in DMARC.", **data))
    rua = tg.get("rua", "")
    unauthorized = _rua_unauthorized(ctx, place, rua) if rua else []
    if unauthorized:
        data = dict(data, rua_unauthorized=unauthorized)
        w.append(R.warn("dmarc.rua", f"Reports (rua) go to an address in another domain ({', '.join(unauthorized)}) that has not confirmed in DNS that it wants "
                                     f"them (no TXT record {place}._report._dmarc.{unauthorized[0]} = \"v=DMARC1\"). Receivers do not send such "
                                     "reports.", **data))
    elif rua:
        w.append(R.ok("dmarc.rua", "Aggregate reports (rua) are being sent.", **data))
    else:
        w.append(R.warn("dmarc.rua", "No rua - you get no reports on who sends email on behalf of the domain.", **data))
    return w


def _rua_unauthorized(ctx, dmarc_domain, rua):
    """Domains of rua addresses outside the organizational domain that have no authorization record
    <domain>._report._dmarc.<address domain> (RFC 7489 section 7.1). At most 3 queries; a DNS error or an exhausted
    budget means no verdict."""
    org = ctx.domain.organizational
    domains = []
    for address in rua.split(","):
        address = address.strip().split("!")[0]
        if address.lower().startswith("mailto:") and "@" in address:
            dom = address.rsplit("@", 1)[1].strip().rstrip(".").lower()
            if dom and dom != org and not dom.endswith("." + org) and dom not in domains:
                domains.append(dom)
    missing = []
    for dom in domains[:3]:
        try:
            o = ctx.resolver.query(f"{dmarc_domain}._report._dmarc.{dom}", "TXT")
        except net.BudgetExceeded:
            break
        if o.state in ("timeout", "error"):
            continue
        if not (o.ok and any(r.lower().replace(" ", "").startswith("v=dmarc1") for r in o.records)):
            missing.append(dom)
    return missing


def _mx_outside_policy(ctx, patterns):
    """MX hosts of the domain not covered by any mx: line of the MTA-STS policy (exact name or *.domain - one label)."""
    outside = []
    for _pref, host in ctx.shared.get("mx") or []:
        h = host.rstrip(".").lower()
        covered = False
        for pat in patterns:
            pat = pat.rstrip(".").lower()
            if pat == h or (pat.startswith("*.") and "." in h and h.split(".", 1)[1] == pat[2:]):
                covered = True
                break
        if not covered:
            outside.append(h)
    return outside


def _no_mx(ctx, ident):
    """A domain without an explicit MX: with an A address mail is still delivered (implicit MX), so this is an omission,
    not "not applicable"."""
    if ctx.shared.get("implicit_mx"):
        return [R.skipped(ident, "no MX, email goes to the A address of the domain")]
    return [R.not_applicable(ident, "domain without MX")]


# --- MTA-STS, TLS-RPT
def _mta_sts(ctx):
    d = ctx.domain.name
    if ctx.shared.get("null_mx") or not ctx.shared.get("mx"):
        return _no_mx(ctx, "mta_sts")
    ans = ctx.resolver.query(f"_mta-sts.{d}", "TXT")
    if ans.state in ("timeout", "error"):
        return [R.skipped("mta_sts", f"DNS: {ans.state}")]
    rec = [r for r in ans.records if r.lower().startswith("v=stsv1")] if ans.ok else []
    if not rec:
        return [R.warn("mta_sts", "No MTA-STS - encryption when receiving email is not enforced (recommended for companies).")]
    try:
        o = ctx.fetch(f"https://mta-sts.{d}/.well-known/mta-sts.txt", max_b=16384, redirects="none")
    except (net.NetworkError, net.ForbiddenTarget) as e:
        return [R.warn("mta_sts", f"An MTA-STS record exists, but the policy cannot be fetched ({type(e).__name__}).")]
    if o.status != 200:
        return [R.warn("mta_sts", f"An MTA-STS record exists, but the policy returns HTTP {o.status}.")]
    pol, patterns = {}, []
    for line in o.body.decode("utf-8", "replace").splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            pol.setdefault(k.strip().lower(), v.strip())
            if k.strip().lower() == "mx" and v.strip():
                patterns.append(v.strip())
    mode = pol.get("mode", "")
    outside = _mx_outside_policy(ctx, patterns) if mode in ("enforce", "testing") else []
    if outside:
        pol = dict(pol, mx=", ".join(patterns))
        if mode == "enforce":
            return [R.error("mta_sts", f"The MTA-STS policy (enforce) does not cover the mail server {', '.join(outside)} - senders that honour it "
                                       "will not deliver email to that server. Fix the mx: lines in the policy file.", policy=pol, mx_outside=outside)]
        return [R.warn("mta_sts", f"The MTA-STS policy (testing) does not cover the mail server {', '.join(outside)}. Fix the mx: lines before "
                                  "switching to enforce, otherwise part of the email will stop arriving.", policy=pol, mx_outside=outside)]
    if mode == "enforce":
        return [R.ok("mta_sts", "MTA-STS in enforce mode.", policy=pol)]
    if mode == "testing":
        return [R.warn("mta_sts", "MTA-STS in testing mode - after the test period switch to enforce.", policy=pol)]
    return [R.warn("mta_sts", "MTA-STS policy without a valid mode.", policy=pol)]


def _tls_rpt(ctx):
    d = ctx.domain.name
    if ctx.shared.get("null_mx") or not ctx.shared.get("mx"):
        return _no_mx(ctx, "tls_rpt")
    ans = ctx.resolver.query(f"_smtp._tls.{d}", "TXT")
    if ans.state in ("timeout", "error"):
        return [R.skipped("tls_rpt", f"DNS: {ans.state}")]
    if ans.ok and any(r.lower().startswith("v=tlsrptv1") for r in ans.records):
        return [R.ok("tls_rpt", "TLS-RPT: reports on encryption problems are being sent.")]
    return [R.warn("tls_rpt", "No TLS-RPT (reports on TLS errors during delivery).")]


# --- STARTTLS and PTR
def _starttls(ctx):
    mx = ctx.shared.get("mx") or []
    if not mx or ctx.shared.get("null_mx"):
        return _no_mx(ctx, "mx.starttls")
    if ctx.option("starttls", True) is False:
        return [R.skipped("mx.starttls", "STARTTLS probe disabled")]
    if ctx.shared.get("provider_trusted"):
        return [R.ok("mx.starttls", f"Email at a large provider ({ctx.shared.get('mail_provider')}) - STARTTLS and certificates "
                                    "are standard there (not probed).", provider=ctx.shared.get("mail_provider"))]
    mx_ips = ctx.shared.get("mx_ips") or {}
    results, policy = [], net.TargetPolicy()
    for _pref, name in mx[: int(ctx.config.get("STARTTLS_MAX_MX", 2))]:
        addresses = mx_ips.get(name) or []
        addresses = [a for a in addresses if policy.allowed(a)]
        if not addresses:
            continue
        ctx.budget.http(name)
        ip = next((a for a in addresses if ":" not in a), addresses[0])
        w = net.probe_starttls(name, ip, ctx.config.get("EHLO", "localhost"), ctx.budget.timeout(int(ctx.config.get("STARTTLS_TIMEOUT_S", 12))))
        results.append(w)
    if not results or not any(x["connected"] for x in results):
        return [R.skipped("mx.starttls", "could not connect to the MX on port 25 (blocked or no response)", probes=results)]
    connected = [x for x in results if x["connected"]]
    if all(x["starttls_ok"] for x in connected):
        days = min((x["tls"] or {}).get("days_to_expiry") or 9999 for x in connected)
        if days < 14:
            return [R.warn("mx.starttls", f"STARTTLS works, but the MX certificate expires in {days} days.", probes=results)]
        return [R.ok("mx.starttls", "The MX server encrypts connections (STARTTLS) and has a valid certificate.", probes=results)]
    if any(x["starttls_offered"] for x in connected):
        errors = "; ".join(x["error"] or "" for x in connected if x["error"])
        return [R.warn("mx.starttls", f"STARTTLS is offered, but the MX certificate does not verify ({errors}). Other servers may "
                                      "send email to this domain without encryption or not at all.", probes=results)]
    return [R.critical("mx.starttls", "The MX server does not offer STARTTLS - incoming email travels as plain text.", probes=results)]


def _ptr(ctx):
    mx = ctx.shared.get("mx") or []
    if not mx or ctx.shared.get("null_mx"):
        return _no_mx(ctx, "mx.ptr")
    name = mx[0][1]
    addresses = [a for a in (ctx.shared.get("mx_ips") or {}).get(name, []) if ":" not in a]
    if not addresses:
        return [R.skipped("mx.ptr", "MX without an IPv4 address")]
    ip = addresses[0]
    ans = ctx.resolver.ptr(ip)
    if ans.state in ("timeout", "error"):
        return [R.skipped("mx.ptr", f"DNS: {ans.state}")]
    if not ans.ok:
        return [R.warn("mx.ptr", f"No PTR record for {ip} ({name}) - some servers reject email from addresses without PTR.", ip=ip)]
    ptr = ans.records[0].lower()
    if ptr == name:
        return [R.ok("mx.ptr", f"PTR {ip} -> {ptr}.", ip=ip, ptr=ptr)]
    a = ctx.resolver.query(ptr, "A")
    if a.ok and ip in a.records:
        return [R.ok("mx.ptr", f"PTR {ip} -> {ptr} (matches the address).", ip=ip, ptr=ptr)]
    return [R.warn("mx.ptr", f"PTR {ip} -> {ptr} does not point back to this address.", ip=ip, ptr=ptr)]
