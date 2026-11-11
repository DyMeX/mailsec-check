"""User input -> domain name to check. Rejects IP addresses, localhost, single-label names, special-use domains
(.local, .onion, .arpa, .test ...) and public suffixes without a registrable part. Returns
Domain(name, unicode, organizational, suffix)."""
import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from . import psl

_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
SPECIAL = {"local", "localhost", "internal", "onion", "arpa", "test", "example", "invalid", "home", "lan", "corp", "intranet"}


class InputError(ValueError):
    pass


@dataclass(frozen=True)
class Domain:
    name: str           # ASCII (punycode), lower case, no www.
    unicode: str        # for display
    organizational: str  # registrable domain (used for the organizational DMARC lookup and rua authorization)
    suffix: str

    @property
    def is_subdomain(self):
        return self.name != self.organizational


def normalize_input(text, suffixes=None):
    if not isinstance(text, str):
        raise InputError("Enter a domain name.")
    tx = text.strip().strip(".").lower()
    if not tx or len(tx) > 300:
        raise InputError("Enter a domain name.")
    if "://" in tx:
        tx = urlsplit(tx).hostname or ""
    else:
        tx = re.split(r"[/?#\\]", tx, maxsplit=1)[0]
        if "@" in tx:
            tx = tx.rsplit("@", 1)[1]
        if ":" in tx and not tx.startswith("["):
            tx = tx.split(":", 1)[0]
    tx = tx.strip(".").strip("[]")
    if not tx or any(c.isspace() for c in tx):
        raise InputError("Invalid domain name.")
    try:
        ipaddress.ip_address(tx)
        raise InputError("Enter a domain name, not an IP address.")
    except ValueError:
        pass
    if tx.startswith("www."):
        tx = tx[4:]
    try:
        ascii_ = tx.encode("idna").decode("ascii")
    except UnicodeError:
        raise InputError("Invalid domain name.") from None
    labels = ascii_.split(".")
    if len(labels) < 2 or len(ascii_) > 253 or not all(_LABEL.match(e) for e in labels):
        raise InputError("Invalid domain name.")
    if labels[-1] in SPECIAL or labels[-1].isdigit():
        raise InputError("This is not a public domain name.")
    suffixes = suffixes or psl.get_list()
    org = suffixes.registrable(ascii_)
    if org is None:
        raise InputError("Enter a registrable domain (e.g. company.com), not just a suffix.")
    try:
        unicode_ = ascii_.encode("ascii").decode("idna")
    except UnicodeError:
        unicode_ = ascii_
    return Domain(ascii_, unicode_, org, suffixes.suffix(ascii_))
