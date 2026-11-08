import json
import requests
from modules.base import BaseModule, ModuleResult
from core.runner import run_tool_lines
from core.registry import is_installed


class SubdomainsPassive(BaseModule):
    name = "subdomains_passive"
    phase = "P1"
    tools_needed = ["subfinder"]

    def execute(self) -> ModuleResult:
        target = self.workspace.target
        all_subs: set[str] = set()
        tool_used = []
        fallback = False

        if is_installed("subfinder"):
            self.emit("log", msg=f"Running subfinder on {target}")
            lines = run_tool_lines(
                f"subfinder -d {target} -silent -all -timeout 30",
                timeout=120,
            )
            all_subs.update(lines)
            tool_used.append("subfinder")

        self.emit("log", msg=f"Querying crt.sh for {target}")
        crt_subs = self._crtsh(target)
        if crt_subs:
            all_subs.update(crt_subs)
            tool_used.append("crt.sh")
            if not is_installed("subfinder"):
                fallback = True

        if is_installed("subfinder") and is_installed("github-subdomains"):
            lines = run_tool_lines(
                f"github-subdomains -d {target} -raw -o /dev/stdout",
                timeout=60,
            )
            all_subs.update(lines)
            tool_used.append("github-subdomains")

        filtered = self.scope.filter_domains(list(all_subs))
        filtered = sorted(set(s.lower().strip() for s in filtered if s.strip()))

        self.workspace.append_lines("subdomains.txt", filtered)
        self.workspace.append_jsonl("hosts.jsonl", [
            {"subdomain": s, "source": "passive", "target": target} for s in filtered
        ])

        return ModuleResult(
            module=self.name,
            items=filtered,
            tool_used=", ".join(tool_used),
            fallback=fallback,
        )

    def _crtsh(self, domain: str) -> list[str]:
        try:
            resp = requests.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                timeout=30,
                headers={"User-Agent": self.config.get("user_agent", "WebKiller/2.0")},
            )
            if resp.status_code != 200:
                return []
            subs = set()
            for entry in resp.json():
                name = entry.get("name_value", "")
                for line in name.split("\n"):
                    line = line.strip().lower()
                    if line and not line.startswith("*"):
                        subs.add(line)
            return list(subs)
        except Exception as e:
            self.emit("log", msg=f"crt.sh error: {e}")
            return []
