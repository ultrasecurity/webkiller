import json
from modules.base import BaseModule, ModuleResult
from core.runner import run_tool
from core.registry import is_installed


class XssConfirm(BaseModule):
    name = "xss_confirm"
    phase = "P6b"
    tools_needed = ["dalfox"]

    def execute(self) -> ModuleResult:
        urls = self.workspace.read_lines("urls.txt")
        params_file = self.workspace.file("params.txt")
        param_urls = self.workspace.read_lines("params.txt") if params_file.exists() else []

        targets = list(set(urls + param_urls))
        targets = [u for u in targets if "?" in u or "=" in u]

        if not targets:
            findings = self.workspace.read_jsonl("findings.jsonl")
            xss_findings = [f for f in findings
                           if "xss" in f.get("name", "").lower()
                           or "xss" in f.get("template_id", "").lower()]
            if xss_findings:
                targets = [f["url"] for f in xss_findings if f.get("url")]

        if not targets:
            return ModuleResult(module=self.name, status="skipped",
                              errors=["No URLs with parameters for XSS testing"])

        max_urls = self.config.get("xss_max_urls", 50)
        targets = targets[:max_urls]
        all_confirmed: list[dict] = []
        tool_used = []
        fallback = False

        if is_installed("dalfox"):
            tool_used.append("dalfox")
            all_confirmed = self._run_dalfox(targets)
        else:
            fallback = True
            tool_used.append("python-reflect")
            self.emit("log", msg="dalfox not available, testing reflection only")
            all_confirmed = self._reflection_check(targets)

        if all_confirmed:
            self.workspace.append_jsonl("confirmed.jsonl", all_confirmed)
            self.workspace.append_jsonl("findings.jsonl", all_confirmed)

        return ModuleResult(
            module=self.name,
            items=[c["url"] for c in all_confirmed],
            records=all_confirmed,
            tool_used=", ".join(tool_used),
            fallback=fallback,
        )

    def _run_dalfox(self, targets: list[str]) -> list[dict]:
        confirmed = []
        urls_file = self.workspace.file("_xss_targets.txt")
        urls_file.write_text("\n".join(targets))

        self.emit("log", msg=f"dalfox: testing {len(targets)} URLs")
        result = run_tool(
            f"dalfox file {urls_file} --silence --format json --timeout 10",
            timeout=300,
        )
        urls_file.unlink(missing_ok=True)

        if result.returncode == 0 and result.stdout.strip():
            for line in result.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    confirmed.append({
                        "name": f"XSS: {data.get('type', 'reflected')}",
                        "severity": "high",
                        "url": data.get("data", ""),
                        "evidence": {
                            "type": data.get("type", ""),
                            "payload": data.get("payload", ""),
                            "param": data.get("param", ""),
                        },
                        "type": "dast_confirmed",
                        "vuln_class": "xss",
                        "module": self.name,
                    })
                except json.JSONDecodeError:
                    pass
        return confirmed

    def _reflection_check(self, targets: list[str]) -> list[dict]:
        import requests
        from urllib.parse import urlparse, parse_qs, urlencode

        canary = "wk2xss7probe"
        findings = []
        ua = self.config.get("user_agent", "WebKiller/2.0")

        for url in targets:
            try:
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                if not params:
                    continue
                for param_name in params:
                    test_params = dict(params)
                    test_params[param_name] = [canary]
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
                    resp = requests.get(test_url, timeout=8,
                                       headers={"User-Agent": ua}, verify=False)
                    if canary in resp.text:
                        findings.append({
                            "name": f"XSS Reflection: {param_name}",
                            "severity": "medium",
                            "url": url,
                            "evidence": {
                                "param": param_name,
                                "reflected": True,
                                "note": "Reflection found — needs manual confirmation",
                            },
                            "type": "potential",
                            "vuln_class": "xss",
                            "module": self.name,
                        })
                        break
            except requests.RequestException:
                pass
        return findings
