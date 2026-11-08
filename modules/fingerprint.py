import json
from modules.base import BaseModule, ModuleResult
from core.runner import run_tool
from core.registry import is_installed


class Fingerprint(BaseModule):
    name = "fingerprint"
    phase = "P3"
    tools_needed = ["wafw00f"]

    def execute(self) -> ModuleResult:
        live = self.workspace.read_lines("live.txt")
        if not live:
            return ModuleResult(module=self.name, status="skipped", errors=["No live hosts"])

        results = []
        items = []

        if is_installed("wafw00f"):
            self.emit("log", msg=f"WAF detection on {len(live)} hosts")
            for url in live[:30]:
                result = run_tool(f"wafw00f {url} -o /dev/stdout -f json", timeout=30)
                try:
                    data = json.loads(result.stdout)
                    for entry in data:
                        waf = entry.get("firewall", "None")
                        if waf and waf != "None":
                            items.append(f"{url} → WAF: {waf}")
                            results.append({"url": url, "waf": waf})
                except (json.JSONDecodeError, TypeError):
                    pass

        hosts_data = self.workspace.read_jsonl("hosts.jsonl")
        tech_summary = {}
        for h in hosts_data:
            for t in h.get("tech", []):
                tech_summary[t] = tech_summary.get(t, 0) + 1

        if tech_summary:
            results.append({"type": "tech_summary", "technologies": tech_summary})

        self.workspace.append_jsonl("fingerprint.jsonl", results)
        return ModuleResult(module=self.name, items=items, records=results,
                            tool_used="wafw00f + httpx-tech")
