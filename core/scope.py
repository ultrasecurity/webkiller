import re
from urllib.parse import urlparse


class Scope:
    def __init__(self, targets: list[str], out_of_scope: list[str] | None = None):
        self.targets = [t.strip().lower() for t in targets if t.strip()]
        self.out_of_scope = [o.strip().lower() for o in (out_of_scope or []) if o.strip()]
        self._in_patterns = [self._to_pattern(t) for t in self.targets]
        self._out_patterns = [self._to_pattern(o) for o in self.out_of_scope]

    @staticmethod
    def _to_pattern(entry: str) -> re.Pattern:
        if entry.startswith("*."):
            suffix = re.escape(entry[2:])
            return re.compile(rf"^(?:.*\.)?{suffix}$", re.IGNORECASE)
        return re.compile(rf"^{re.escape(entry)}$", re.IGNORECASE)

    def in_scope(self, domain: str) -> bool:
        domain = domain.strip().lower()
        if any(p.match(domain) for p in self._out_patterns):
            return False
        return any(p.match(domain) for p in self._in_patterns)

    def filter_domains(self, domains: list[str]) -> list[str]:
        return [d for d in domains if self.in_scope(d)]

    def filter_urls(self, urls: list[str]) -> list[str]:
        result = []
        for url in urls:
            try:
                host = urlparse(url).hostname or ""
                if self.in_scope(host):
                    result.append(url)
            except Exception:
                pass
        return result
