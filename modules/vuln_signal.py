import json
from modules.base import BaseModule, ModuleResult
from core.runner import run_tool
from core.registry import is_installed


class VulnSignal(BaseModule):
    name = "vuln_signal"
    phase = "P6a"
    tools_needed = ["nuclei"]

    def execute(self) -> ModuleResult:
        live = self.workspace.read_lines("live.txt")
        if not live:
            return ModuleResult(module=self.name, status="skipped", errors=["No live hosts"])

        if not is_installed("nuclei"):
            return ModuleResult(module=self.name, status="skipped", errors=["nuclei not installed"])

        live_file = self.workspace.file("live.txt")
        findings = []
        items = []

        self.emit("log", msg=f"Running nuclei on {len(live)} targets (passive templates)")
        result = run_tool(
            f"nuclei -l {live_file} -silent -json "
            f"-severity critical,high,medium "
            f"-type http -rate-limit {self.config.get('rate_limit', 50)} "
            f"-timeout 15 -retries 1",
            timeout=600,
        )

        for line in result.stdout.splitlines():
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                finding = {
                    "template_id": data.get("template-id", ""),
                    "name": data.get("info", {}).get("name", ""),
                    "severity": data.get("info", {}).get("severity", ""),
                    "url": data.get("matched-at", data.get("host", "")),
                    "type": data.get("type", ""),
                    "matched": data.get("matcher-name", ""),
                    "extracted": data.get("extracted-results", []),
                    "tags": data.get("info", {}).get("tags", []),
                }
                findings.append(finding)
                items.append(f"[{finding['severity'].upper()}] {finding['name']} → {finding['url']}")
                self.emit("finding", severity=finding["severity"], name=finding["name"], url=finding["url"])
            except json.JSONDecodeError:
                pass

        self.workspace.append_jsonl("findings.jsonl", findings)
        return ModuleResult(module=self.name, items=items, records=findings, tool_used="nuclei")
