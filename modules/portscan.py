import json
from modules.base import BaseModule, ModuleResult
from core.runner import run_tool, run_tool_lines
from core.registry import is_installed


class Portscan(BaseModule):
    name = "portscan"
    phase = "P3"
    tools_needed = ["naabu"]

    def execute(self) -> ModuleResult:
        subs = self.workspace.read_lines("subdomains.txt")
        if not subs:
            return ModuleResult(module=self.name, status="skipped", errors=["No targets"])

        subs_file = self.workspace.file("subdomains.txt")
        results = []
        items = []

        if is_installed("naabu"):
            self.emit("log", msg=f"Port scanning {len(subs)} hosts with naabu")
            result = run_tool(
                f"naabu -l {subs_file} -silent -json -top-ports 1000 -rate {self.config.get('rate_limit', 50)}",
                timeout=300,
            )
            for line in result.stdout.splitlines():
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    host = data.get("host", data.get("ip", ""))
                    port = data.get("port", 0)
                    items.append(f"{host}:{port}")
                    results.append({"host": host, "port": port, "protocol": data.get("protocol", "tcp")})
                except json.JSONDecodeError:
                    pass
        elif is_installed("nmap"):
            self.emit("log", msg="naabu not found, falling back to nmap (slower)")
            targets_str = " ".join(subs[:50])
            result = run_tool(f"nmap -sT -T4 --top-ports 100 {targets_str}", timeout=300)
            items = [l for l in result.stdout.splitlines() if "/tcp" in l or "/udp" in l]
        else:
            return ModuleResult(module=self.name, status="skipped", errors=["No port scanner installed"])

        self.workspace.append_jsonl("ports.jsonl", results)
        return ModuleResult(module=self.name, items=items, records=results,
                            tool_used="naabu" if is_installed("naabu") else "nmap")
