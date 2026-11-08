import requests
import json
from difflib import SequenceMatcher
from modules.base import BaseModule, ModuleResult


class AuthzProbe(BaseModule):
    name = "authz_probe"
    phase = "P6b"
    tools_needed = []

    BYPASS_HEADERS = [
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Original-URL": "/admin"},
        {"X-Rewrite-URL": "/admin"},
        {"X-Custom-IP-Authorization": "127.0.0.1"},
    ]

    METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]

    def execute(self) -> ModuleResult:
        urls = self.workspace.read_lines("urls.txt")
        if not urls:
            return ModuleResult(module=self.name, status="skipped", errors=["No URLs"])

        api_urls = [u for u in urls if "/api/" in u or "/v1/" in u or "/v2/" in u][:50]
        confirmed = []
        items = []

        ua = self.config.get("user_agent", "WebKiller/2.0")

        for url in api_urls:
            self.emit("log", msg=f"AuthZ probing {url}")

            auth_resp = self._safe_get(url, headers={"User-Agent": ua})
            noauth_resp = self._safe_get(url, headers={"User-Agent": ua, "Authorization": ""})

            if auth_resp and noauth_resp:
                ratio = SequenceMatcher(None, auth_resp["body"][:2000], noauth_resp["body"][:2000]).ratio()
                if ratio > 0.9 and auth_resp["status"] == noauth_resp["status"] == 200:
                    finding = {
                        "url": url,
                        "vuln_class": "broken_access_control",
                        "severity": "high",
                        "method": "response_diff",
                        "evidence": {"similarity": round(ratio, 3), "status": auth_resp["status"]},
                    }
                    confirmed.append(finding)
                    items.append(f"[AUTHZ] Response diff {ratio:.0%} — {url}")

            for method in ["PUT", "DELETE", "PATCH"]:
                resp = self._safe_request(method, url, headers={"User-Agent": ua})
                if resp and resp["status"] not in (405, 501, 404, 403, 401):
                    finding = {
                        "url": url,
                        "vuln_class": "method_tampering",
                        "severity": "medium",
                        "method": f"HTTP_{method}",
                        "evidence": {"status": resp["status"], "body_preview": resp["body"][:200]},
                    }
                    confirmed.append(finding)
                    items.append(f"[METHOD] {method} accepted ({resp['status']}) — {url}")

            if "/1" in url or "id=" in url:
                idor_url = url.replace("/1", "/2").replace("id=1", "id=2")
                resp = self._safe_get(idor_url, headers={"User-Agent": ua})
                if resp and resp["status"] == 200 and len(resp["body"]) > 50:
                    finding = {
                        "url": idor_url,
                        "vuln_class": "IDOR",
                        "severity": "high",
                        "method": "sequential_id",
                        "evidence": {"status": resp["status"], "body_length": len(resp["body"])},
                    }
                    confirmed.append(finding)
                    items.append(f"[IDOR] Sequential ID accessible — {idor_url}")

        self.workspace.append_jsonl("confirmed.jsonl", confirmed)
        return ModuleResult(module=self.name, items=items, records=confirmed, tool_used="python-authz")

    def _safe_get(self, url, headers=None):
        try:
            resp = requests.get(url, headers=headers, timeout=10, verify=False, allow_redirects=False)
            return {"status": resp.status_code, "body": resp.text, "headers": dict(resp.headers)}
        except Exception:
            return None

    def _safe_request(self, method, url, headers=None):
        try:
            resp = requests.request(method, url, headers=headers, timeout=10, verify=False, allow_redirects=False)
            return {"status": resp.status_code, "body": resp.text}
        except Exception:
            return None
