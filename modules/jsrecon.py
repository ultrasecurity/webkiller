import re
import json
import requests
from modules.base import BaseModule, ModuleResult
from core.runner import run_tool_lines
from core.registry import is_installed


class JsRecon(BaseModule):
    name = "jsrecon"
    phase = "P4"
    tools_needed = []

    def execute(self) -> ModuleResult:
        urls = self.workspace.read_lines("urls.txt")
        live_hosts = self.workspace.read_lines("live.txt")
        js_urls = [u for u in urls if self._is_js(u)]

        if not js_urls and live_hosts:
            self.emit("log", msg="No JS URLs found, scraping live hosts for scripts")
            for host in live_hosts[:10]:
                js_urls.extend(self._scrape_scripts(host))
            js_urls = list(set(js_urls))

        if not js_urls:
            return ModuleResult(module=self.name, status="skipped", errors=["No JS files found"])

        self.emit("log", msg=f"Analyzing {len(js_urls)} JS files")
        all_endpoints: list[str] = []
        all_secrets: list[dict] = []
        all_records: list[dict] = []

        max_files = self.config.get("jsrecon_max_files", 50)
        ua = self.config.get("user_agent", "WebKiller/2.0")

        for js_url in js_urls[:max_files]:
            try:
                resp = requests.get(js_url, timeout=10, headers={"User-Agent": ua})
                if resp.status_code != 200:
                    continue
                body = resp.text

                endpoints = self._extract_endpoints(body)
                secrets = self._extract_secrets(body, js_url)

                if endpoints:
                    all_endpoints.extend(endpoints)
                    all_records.append({
                        "file": js_url,
                        "endpoints": endpoints,
                        "type": "js_endpoints",
                    })
                if secrets:
                    all_secrets.extend(secrets)
            except requests.RequestException:
                pass

        items = list(set(all_endpoints))
        if items:
            self.workspace.append_lines("js_endpoints.txt", items)
        if all_secrets:
            self.workspace.append_jsonl("findings.jsonl", all_secrets)
        if all_records:
            self.workspace.append_jsonl("jsrecon.jsonl", all_records)

        return ModuleResult(
            module=self.name,
            items=items,
            records=all_records,
            tool_used="python-regex",
            fallback=True,
        )

    def _is_js(self, url: str) -> bool:
        path = url.split("?")[0].lower()
        return path.endswith(".js") or path.endswith(".mjs")

    def _scrape_scripts(self, host_url: str) -> list[str]:
        try:
            ua = self.config.get("user_agent", "WebKiller/2.0")
            resp = requests.get(host_url, timeout=10, headers={"User-Agent": ua})
            if resp.status_code != 200:
                return []
            srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', resp.text, re.I)
            result = []
            for src in srcs:
                if src.startswith("//"):
                    src = "https:" + src
                elif src.startswith("/"):
                    src = host_url.rstrip("/") + src
                elif not src.startswith("http"):
                    src = host_url.rstrip("/") + "/" + src
                result.append(src)
            return result
        except requests.RequestException:
            return []

    def _extract_endpoints(self, js_body: str) -> list[str]:
        patterns = [
            r'["\'](/api/[a-zA-Z0-9_/\-\.]+)["\']',
            r'["\'](/v[0-9]+/[a-zA-Z0-9_/\-\.]+)["\']',
            r'fetch\s*\(\s*["\']([^"\']+)["\']',
            r'\.(?:get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']',
            r'["\']https?://[a-zA-Z0-9\-\.]+(?:/[a-zA-Z0-9_/\-\.]*)+["\']',
        ]
        endpoints = set()
        for pat in patterns:
            for match in re.findall(pat, js_body):
                cleaned = match.strip("\"'")
                if len(cleaned) > 4 and not cleaned.endswith((".js", ".css", ".png", ".jpg", ".svg")):
                    endpoints.add(cleaned)
        return sorted(endpoints)

    def _extract_secrets(self, js_body: str, source_url: str) -> list[dict]:
        secret_patterns = {
            "aws_key": r'(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}',
            "google_api": r'AIza[0-9A-Za-z\-_]{35}',
            "slack_token": r'xox[bpsorta]-[0-9a-zA-Z\-]{10,}',
            "github_token": r'gh[ps]_[0-9a-zA-Z]{36}',
            "jwt": r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}',
            "private_key": r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',
            "bearer_token": r'[Bb]earer\s+[a-zA-Z0-9\-_.~+/]+=*',
            "generic_secret": r'(?:secret|password|api_?key|token)\s*[:=]\s*["\'][a-zA-Z0-9\-_.]{8,}["\']',
        }
        findings = []
        for name, pattern in secret_patterns.items():
            matches = re.findall(pattern, js_body)
            for match in matches:
                findings.append({
                    "name": f"JS Secret: {name}",
                    "severity": "high",
                    "url": source_url,
                    "evidence": {"pattern": name, "match": match[:60]},
                    "type": "js_secret",
                    "module": self.name,
                })
        return findings
