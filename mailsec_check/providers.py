"""Reference data: common DKIM selectors and recognition of mail providers by MX host name.

A provider entry gives the selectors to try first and whether the provider is trusted (its MX hosts are not probed for
STARTTLS). Changing these lists changes which names are guessed, not how a finding is judged."""

# Common DKIM selectors: generic names, popular sending systems and regional hosting providers. They are guessed by
# name, so "not found" means "not detected", never "absent".
COMMON_SELECTORS = [
    "default", "dkim", "mail", "selector1", "selector2", "google", "k1", "k2", "k3", "s1", "s2", "smtp", "key1",
    "key2", "mail1", "mail2", "dkim1", "dkim2", "selector", "mx", "email", "mailo", "x", "s", "dk", "sig1", "pm",
    "mandrill", "mailjet", "cm", "ctct1", "ctct2", "hs1", "hs2", "zoho", "protonmail", "protonmail2", "protonmail3",
    "fm1", "fm2", "fm3", "everlytickey1", "everlytickey2", "mte1", "mte2", "smtpapi", "amazonses", "ses", "sendgrid",
    "mailgun", "mg", "krs", "nazwa", "nazwapl", "home", "homepl", "ovh", "cyberfolks", "zenbox", "lh", "emaillabs",
    "el1", "freshmail", "getresponse", "gr", "sare", "mailerlite", "ml", "klaviyo", "wp", "onet", "o2", "interia",
]
# Providers whose DKIM selector contains a service identifier that cannot be guessed from outside: no hit gives a
# skipped check with this text instead of a warning.
INDIVIDUAL_SELECTORS = {
    "OVH": "OVHcloud email DKIM selectors contain a service identifier in the name (e.g. ovhmo...-selector1), so they "
           "cannot be guessed from outside. OVHcloud enables DKIM by default; you can check the status in the panel "
           "(email service diagnostics) or provide the selector with --selector.",
}
# Provider by MX host name: (fragment, provider name, selectors to try first, trusted = no STARTTLS probe)
MX_PROVIDERS = [
    ("google.com", "Google Workspace", ["google"], True),
    ("googlemail.com", "Google Workspace", ["google"], True),
    ("protection.outlook.com", "Microsoft 365", ["selector1", "selector2"], True),
    ("outlook.com", "Microsoft 365", ["selector1", "selector2"], True),
    ("zoho.eu", "Zoho Mail", ["zoho"], True),
    ("zoho.com", "Zoho Mail", ["zoho"], True),
    ("protonmail.ch", "Proton Mail", ["protonmail", "protonmail2", "protonmail3"], True),
    ("messagingengine.com", "Fastmail", ["fm1", "fm2", "fm3"], True),
    ("mail.icloud.com", "iCloud Mail", ["sig1"], True),
    ("home.pl", "home.pl", ["home", "default"], False),
    ("nazwa.pl", "nazwa.pl", ["nazwa", "default", "nazwapl"], False),
    ("mail.ovh.net", "OVH", ["ovh", "default"], False),
    ("ovh.net", "OVH", ["ovh", "default"], False),
    ("cyberfolks.pl", "cyber_Folks", ["x", "default", "cyberfolks"], False),
    ("cyber-folks.pl", "cyber_Folks", ["x", "default", "cyberfolks"], False),
    ("zenbox.pl", "Zenbox", ["x", "default", "zenbox"], False),
    ("lh.pl", "LH.pl", ["default", "lh"], False),
    ("hostinger", "Hostinger", ["hostingermail-a", "hostingermail-b", "hostingermail-c", "default"], False),
    ("mx.cloudflare.net", "Cloudflare Email Routing", ["cf2024-1"], True),
    ("dhosting.pl", "dhosting", ["default"], False),
    ("kei.pl", "Kei.pl", ["default"], False),
    ("smarthost.pl", "Smarthost", ["default"], False),
    ("linuxpl.com", "LinuxPL", ["default"], False),
    ("hekko.net.pl", "Hekko", ["default"], False),
    ("mimecast.com", "Mimecast", [], False),
    ("pphosted.com", "Proofpoint", [], False),
    ("barracudanetworks.com", "Barracuda", [], False),
    ("emaillabs.net.pl", "EmailLabs", ["emaillabs", "el1"], False),
    ("mailgun.org", "Mailgun", ["mg", "mailo", "k1"], False),
    ("yandex.net", "Yandex", ["mail"], False),
    ("mx.wp.pl", "WP Poczta", ["wp"], False),
    ("onet.pl", "Onet", ["onet"], False),
    ("interia.pl", "Interia", ["interia"], False),
    ("o2.pl", "o2", ["o2"], False),
]


def provider_for_mx(mx_names):
    """(provider name, selectors first, trusted) for the first recognized MX, or (None, [], False)."""
    for mx in mx_names:
        m = mx.lower().rstrip(".")
        for suffix, name, selectors, trusted in MX_PROVIDERS:
            if m == suffix or m.endswith("." + suffix) or suffix in m:
                return name, selectors, trusted
    return None, [], False
