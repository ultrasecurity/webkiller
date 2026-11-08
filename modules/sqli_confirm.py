import json
import requests
import time
from urllib.parse import urlparse, parse_qs, urlencode
from modules.base import BaseModule, ModuleResult
from core.runner import run_tool
from core.registry import is_installed


class SqliConfirm(BaseModule):
    name = "sqli_confirm"
    phase = "P6b"
    tools_needed = ["ghauri"]

    def execute(self) -> ModuleResult:
        findings = self.workspace.read_jsonl("findings.jsonl")
        sqli_targets = [
            f["url"] for f in findings
            if ("sqli" in f.get("name", "").lower()
                or "sql" in f.get("template_id", "").lower())
            and f.get("url")
        ]

        param_urls = self.workspace.read_lines("params.txt")
        targets = list(set(sqli_targets + [u for u in param_urls if "?" in u]))

        if not targets:
            return ModuleResult(module=self.name, status="skipped",
                              errors=["No SQL injection candidates"])

        max_urls = self.config.get("sqli_max_urls", 20)
        targets = targets[:max_urls]
        all_confirmed: list[dict] = []
        tool_used = []
        fallback = False

        if is_installed("ghauri"):
            tool_used.append("ghauri")
            all_confirmed = self._run_ghauri(targets)
        else:
            fallback = True
            tool_used.append("python-timing")
            self.emit("log", msg="ghauri not available, using time-based heuristics")
            all_confirmed = self._timing_check(targets)

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

    def _run_ghauri(self, targets: list[str]) -> list[dict]:
        confirmed = []
        for url in targets:
            self.emit("log", msg=f"ghauri: {url}")
            result = run_tool(
                f'ghauri -u "{url}" --batch --level 2 --risk 1 --timeout 10 --retries 1',
                timeout=120,
            )
            if result.returncode == 0 and "is vulnerable" in result.stdout.lower():
                sqli_type = "unknown"
                for t in ("boolean-based", "time-based", "error-based", "union-based", "stacked"):
                    if t in result.stdout.lower():
                        sqli_type = t
                        break
                confirmed.append({
                    "name": f"SQLi: {sqli_type}",
                    "severity": "critical",
                    "url": url,
                    "evidence": {
                        "type": sqli_type,
                        "tool_output": result.stdout[:500],
                    },
                    "type": "dast_confirmed",
                    "vuln_class": "sqli",
                    "module": self.name,
                })
        return confirmed

    def _timing_check(self, targets: list[str]) -> list[dict]:
        findings = []
        ua = self.config.get("user_agent", "WebKiller/2.0")
        delay_threshold = 4.0
        payloads = [
            "' OR SLEEP(5)-- -",
            "1; WAITFOR DELAY '0:0:5'-- ",
            "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)-- ",
        ]

        for url in targets:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            if not params:
                continue

            for param_name in list(params.keys())[:3]:
                try:
                    base_start = time.time()
                    requests.get(url, timeout=10, headers={"User-Agent": ua}, verify=False)
                    base_time = time.time() - base_start
                except requests.RequestException:
                    continue

                for payload in payloads:
                    try:
                        test_params = dict(params)
                        test_params[param_name] = [payload]
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
                        start = time.time()
                        requests.get(test_url, timeout=15,
                                    headers={"User-Agent": ua}, verify=False)
                        elapsed = time.time() - start

                        if elapsed - base_time > delay_threshold:
                            findings.append({
                                "name": f"SQLi (time-based): {param_name}",
                                "severity": "high",
                                "url": url,
                                "evidence": {
                                    "param": param_name,
                                    "base_time": round(base_time, 2),
                                    "delay_time": round(elapsed, 2),
                                    "note": "Time-based heuristic — needs manual confirmation",
                                },
                                "type": "potential",
                                "vuln_class": "sqli",
                                "module": self.name,
                            })
                            break
                    except requests.RequestException:
                        pass
        return findings
