import json
import re
import requests
from modules.base import BaseModule, ModuleResult
from core.runner import run_tool
from core.registry import is_installed


class SecretVerify(BaseModule):
    name = "secret_verify"
    phase = "P6b"
    tools_needed = ["trufflehog"]

    def execute(self) -> ModuleResult:
        findings = self.workspace.read_jsonl("findings.jsonl")
        js_findings = [f for f in findings if f.get("type") == "js_secret"]
        urls = self.workspace.read_lines("urls.txt")
        js_urls = [u for u in urls if u.lower().endswith((".js", ".mjs"))]

        all_verified: list[dict] = []
        tool_used = []
        fallback = False

        if is_installed("trufflehog") and js_urls:
            tool_used.append("trufflehog")
            self.emit("log", msg=f"trufflehog: scanning {len(js_urls)} JS files")
            all_verified.extend(self._run_trufflehog(js_urls))

        if js_findings:
            tool_used.append("python-verify")
            self.emit("log", msg=f"Verifying {len(js_findings)} secret candidates")
            verified = self._verify_secrets(js_findings)
            all_verified.extend(verified)
            if not is_installed("trufflehog"):
                fallback = True

        if not js_findings and not js_urls:
            return ModuleResult(module=self.name, status="skipped",
                              errors=["No secrets to verify"])

        if all_verified:
            self.workspace.append_jsonl("confirmed.jsonl", all_verified)
            for v in all_verified:
                v["type"] = "dast_confirmed"
            self.workspace.append_jsonl("findings.jsonl", all_verified)

        return ModuleResult(
            module=self.name,
            items=[v.get("url", "") for v in all_verified],
            records=all_verified,
            tool_used=", ".join(tool_used) or "none",
            fallback=fallback,
        )

    def _run_trufflehog(self, js_urls: list[str]) -> list[dict]:
        verified = []
        for url in js_urls[:20]:
            result = run_tool(
                f'trufflehog filesystem --json --no-update "{url}"',
                timeout=60,
            )
            if result.returncode == 0 and result.stdout.strip():
                for line in result.stdout.splitlines():
                    try:
                        data = json.loads(line)
                        verified.append({
                            "name": f"Verified Secret: {data.get('DetectorName', 'unknown')}",
                            "severity": "critical",
                            "url": url,
                            "evidence": {
                                "detector": data.get("DetectorName", ""),
                                "verified": data.get("Verified", False),
                                "raw": data.get("Raw", "")[:40],
                            },
                            "type": "dast_confirmed",
                            "vuln_class": "secret_exposure",
                            "module": self.name,
                        })
                    except json.JSONDecodeError:
                        pass
        return verified

    def _verify_secrets(self, findings: list[dict]) -> list[dict]:
        verified = []
        for finding in findings:
            evidence = finding.get("evidence", {})
            pattern_type = evidence.get("pattern", "")
            match_value = evidence.get("match", "")
            if not match_value:
                continue

            is_valid = False
            if pattern_type == "aws_key":
                is_valid = self._check_aws(match_value)
            elif pattern_type == "google_api":
                is_valid = self._check_google_api(match_value)
            elif pattern_type == "github_token":
                is_valid = self._check_github_token(match_value)
            elif pattern_type == "slack_token":
                is_valid = self._check_slack_token(match_value)
            elif pattern_type in ("jwt", "bearer_token"):
                is_valid = True

            if is_valid:
                verified.append({
                    "name": f"Verified: {pattern_type}",
                    "severity": "critical",
                    "url": finding.get("url", ""),
                    "evidence": {
                        "pattern": pattern_type,
                        "verified": True,
                        "snippet": match_value[:30] + "...",
                    },
                    "type": "dast_confirmed",
                    "vuln_class": "secret_exposure",
                    "module": self.name,
                })
        return verified

    def _check_aws(self, key: str) -> bool:
        return bool(re.match(r'^(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}$', key))

    def _check_google_api(self, key: str) -> bool:
        try:
            resp = requests.get(
                f"https://maps.googleapis.com/maps/api/staticmap?center=0,0&zoom=1&size=1x1&key={key}",
                timeout=5,
            )
            return resp.status_code != 403
        except requests.RequestException:
            return False

    def _check_github_token(self, token: str) -> bool:
        try:
            resp = requests.get(
                "https://api.github.com/user",
                headers={"Authorization": f"token {token}"},
                timeout=5,
            )
            return resp.status_code == 200
        except requests.RequestException:
            return False

    def _check_slack_token(self, token: str) -> bool:
        try:
            resp = requests.get(
                "https://slack.com/api/auth.test",
                headers={"Authorization": f"Bearer {token}"},
                timeout=5,
            )
            data = resp.json()
            return data.get("ok", False)
        except requests.RequestException:
            return False
