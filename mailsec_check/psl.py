"""Public Suffix List: the registrable (organizational) domain of any host name.

The list is read from a file when one is available (the Debian `publicsuffix` package installs
/usr/share/publicsuffix/public_suffix_list.dat). Without a file a small built-in set is used; it is enough for
common cases but is not a full list."""
import os

CANDIDATE_FILES = (
    "/usr/share/publicsuffix/public_suffix_list.dat",
    "/usr/share/publicsuffix/effective_tld_names.dat",
    "/usr/local/share/publicsuffix/public_suffix_list.dat",
    "/opt/homebrew/share/publicsuffix/public_suffix_list.dat",
)

BUILTIN = """
com net org info biz eu de uk co.uk org.uk me.uk ac.uk gov.uk fr it es nl be cz sk at ch se no dk fi ie pt hu ro bg hr si
lt lv ee ua ru us ca com.au net.au org.au au jp co.jp ne.jp or.jp br com.br in co.in cn com.cn io dev app ai co me tv cc
xyz online site shop store tech cloud digital agency studio pro name mobi top club blog page link email
github.io gitlab.io herokuapp.com azurewebsites.net cloudfront.net amazonaws.com
""".split()


class SuffixList:
    def __init__(self, path=None):
        self.rules, self.wildcards, self.exceptions = set(), set(), set()
        loaded = False
        if path and os.path.exists(path):
            try:
                with open(path, encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("//"):
                            continue
                        self._add(line.split()[0])
                loaded = True
            except OSError:
                pass
        if not loaded:
            for r in BUILTIN:
                self._add(r)
        self.source = "file" if loaded else "built-in"

    def _add(self, r):
        r = r.lower().rstrip(".")
        try:
            r = r.encode("idna").decode("ascii")
        except UnicodeError:
            return
        if r.startswith("!"):
            self.exceptions.add(r[1:])
        elif r.startswith("*."):
            self.wildcards.add(r[2:])
        else:
            self.rules.add(r)

    def suffix(self, host):
        """Public suffix of a host per the PSL algorithm (no rule = the last label)."""
        labels = host.lower().rstrip(".").split(".")
        best = labels[-1]
        for i in range(len(labels)):
            candidate = ".".join(labels[i:])
            if candidate in self.exceptions:
                return ".".join(labels[i + 1:])
            if candidate in self.rules and len(candidate) > len(best):
                best = candidate
            parent = ".".join(labels[i + 1:])
            if i + 1 < len(labels) and parent in self.wildcards and len(candidate) > len(best):
                best = candidate
        return best

    def registrable(self, host):
        host = host.lower().rstrip(".")
        s = self.suffix(host)
        if host == s:
            return None
        rest = host[: -len(s) - 1].split(".")
        return rest[-1] + "." + s


_LIST = None


def get_list(path=None):
    global _LIST
    if _LIST is None or path:
        path = path or os.environ.get("MAILSEC_PSL_FILE") or next((p for p in CANDIDATE_FILES if os.path.exists(p)), None)
        _LIST = SuffixList(path)
    return _LIST
