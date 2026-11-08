import subprocess
import json
from modules.base import BaseModule, ModuleResult
from core.runner import run_tool, run_tool_lines
from core.registry import is_installed


class OsintDNS(BaseModule):
    name = "osint_dns"
    phase = "P7"
    tools_needed = []

    def execute(self) -> ModuleResult:
        target = self.workspace.target
        results = []
        items = []

        self.emit("log", msg=f"WHOIS lookup for {target}")
        whois_data = self._whois(target)
        if whois_data:
            results.append({"type": "whois", "domain": target, "data": whois_data})
            items.append(f"WHOIS: {target}")

        self.emit("log", msg=f"DNS records for {target}")
        for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]:
            records = self._dns_query(target, rtype)
            if records:
                results.append({"type": "dns", "domain": target, "record_type": rtype, "records": records})
                items.append(f"DNS {rtype}: {len(records)} records")

        self.workspace.append_jsonl("osint.jsonl", results)
        return ModuleResult(module=self.name, items=items, records=results, tool_used="whois+dns")

    def _whois(self, domain: str) -> str:
        try:
            result = run_tool(f"whois {domain}", timeout=15)
            return result.stdout[:3000] if result.returncode == 0 else ""
        except Exception:
            return ""

    def _dns_query(self, domain: str, rtype: str) -> list[str]:
        if is_installed("dnsx"):
            lines = run_tool_lines(f"echo {domain} | dnsx -silent -resp-only -r {rtype}", timeout=15)
            return lines

        try:
            import dns.resolver
            answers = dns.resolver.resolve(domain, rtype)
            return [str(r) for r in answers]
        except Exception:
            return []
