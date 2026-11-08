import json
from modules.base import BaseModule, ModuleResult
from core.runner import run_tool
from core.registry import is_installed


class VulnConfirm(BaseModule):
    name = "vuln_confirm"
    phase = "P6b"
    tools_needed = ["nuclei"]

    def execute(self) -> ModuleResult:
        urls = self.workspace.read_lines("urls.txt")
        if not urls:
            return ModuleResult(module=self.name, status="skipped", errors=["No URLs to test"])

        if not is_installed("nuclei"):
            return ModuleResult(module=self.name, status="skipped", errors=["nuclei not installed"])

        urls_file = self.workspace.file("urls.txt")
        confirmed = []
        items = []

        self.emit("log", msg=f"Running nuclei DAST on {len(urls)} URLs")
        result = run_tool(
            f"nuclei -l {urls_file} -silent -json -dast "
            f"-severity critical,high,medium "
            f"-rate-limit {self.config.get('rate_limit', 30)} "
            f"-timeout 20 -retries 0",
            timeout=900,
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
                    "type": "dast_confirmed",
                    "matched": data.get("matcher-name", ""),
                    "curl_command": data.get("curl-command", ""),
                    "extracted": data.get("extracted-results", []),
                    "evidence": {
                        "request": data.get("request", "")[:500],
                        "response": data.get("response", "")[:500],
                    },
                }
                confirmed.append(finding)
                items.append(f"[CONFIRMED:{finding['severity'].upper()}] {finding['name']} → {finding['url']}")
                self.emit("confirmed", severity=finding["severity"], name=finding["name"], url=finding["url"])
            except json.JSONDecodeError:
                pass

        self.workspace.append_jsonl("confirmed.jsonl", confirmed)
        return ModuleResult(module=self.name, items=items, records=confirmed, tool_used="nuclei-dast")
