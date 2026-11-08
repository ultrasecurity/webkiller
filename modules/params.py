import re
import json
import requests
from urllib.parse import urlparse, parse_qs, urlencode
from modules.base import BaseModule, ModuleResult
from core.runner import run_tool, run_tool_lines
from core.registry import is_installed


class Params(BaseModule):
    name = "params"
    phase = "P4"
    tools_needed = ["arjun"]

    def execute(self) -> ModuleResult:
        live_hosts = self.workspace.read_lines("live.txt")
        urls = self.workspace.read_lines("urls.txt")

        if not live_hosts and not urls:
            return ModuleResult(module=self.name, status="skipped", errors=["No targets"])

        all_params: list[str] = []
        all_records: list[dict] = []
        tool_used = []
        fallback = False
        max_hosts = self.config.get("params_max_hosts", 10)

        params_from_urls = self._extract_params_from_urls(urls)
        if params_from_urls:
            all_records.extend(params_from_urls)
            tool_used.append("url-parse")

        if is_installed("arjun"):
            tool_used.append("arjun")
            for url in live_hosts[:max_hosts]:
                self.emit("log", msg=f"arjun: {url}")
                result = run_tool(
                    f"arjun -u {url} -oJ /dev/stdout -t 10 -q",
                    timeout=120,
                )
                if result.returncode == 0 and result.stdout.strip():
                    records = self._parse_arjun(result.stdout, url)
                    all_records.extend(records)
        else:
            fallback = True
            tool_used.append("python-probe")
            for url in live_hosts[:max_hosts]:
                self.emit("log", msg=f"Parameter probing: {url}")
                records = self._probe_params(url)
                all_records.extend(records)

        for rec in all_records:
            for p in rec.get("params", []):
                all_params.append(f"{rec.get('url', '')}?{p}")

        items = list(set(all_params))
        if items:
            self.workspace.append_lines("params.txt", items)
        if all_records:
            self.workspace.append_jsonl("params.jsonl", all_records)

        return ModuleResult(
            module=self.name,
            items=items,
            records=all_records,
            tool_used=", ".join(tool_used),
            fallback=fallback,
        )

    def _extract_params_from_urls(self, urls: list[str]) -> list[dict]:
        param_map: dict[str, set[str]] = {}
        for url in urls:
            parsed = urlparse(url)
            if parsed.query:
                base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                params = parse_qs(parsed.query)
                if base not in param_map:
                    param_map[base] = set()
                param_map[base].update(params.keys())
        return [
            {"url": url, "params": sorted(params), "source": "url_mining"}
            for url, params in param_map.items() if params
        ]

    def _parse_arjun(self, stdout: str, url: str) -> list[dict]:
        try:
            data = json.loads(stdout)
            records = []
            for target, params in data.items():
                records.append({
                    "url": target,
                    "params": params if isinstance(params, list) else list(params),
                    "source": "arjun",
                })
            return records
        except (json.JSONDecodeError, AttributeError):
            return []

    def _probe_params(self, url: str) -> list[dict]:
        common_params = [
            "id", "page", "q", "search", "query", "name", "user",
            "email", "file", "path", "url", "redirect", "next",
            "callback", "return", "token", "action", "type",
            "category", "sort", "order", "limit", "offset",
            "lang", "debug", "test", "admin", "cmd", "exec",
        ]
        found = []
        ua = self.config.get("user_agent", "WebKiller/2.0")
        try:
            base_resp = requests.get(url, timeout=5, headers={"User-Agent": ua})
            base_len = len(base_resp.content)
        except requests.RequestException:
            return []

        for param in common_params:
            try:
                test_url = f"{url.rstrip('/')}?{param}=webkiller_test_value"
                resp = requests.get(test_url, timeout=5, headers={"User-Agent": ua})
                diff = abs(len(resp.content) - base_len)
                if diff > 50 or resp.status_code != base_resp.status_code:
                    found.append(param)
            except requests.RequestException:
                pass

        if found:
            return [{"url": url, "params": found, "source": "python-probe"}]
        return []
