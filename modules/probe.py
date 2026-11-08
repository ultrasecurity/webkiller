import json
import socket
import requests
from modules.base import BaseModule, ModuleResult
from core.runner import run_tool, run_tool_lines
from core.registry import is_installed


class Probe(BaseModule):
    name = "probe"
    phase = "P3"
    tools_needed = ["httpx"]

    def execute(self) -> ModuleResult:
        subs = self.workspace.read_lines("subdomains.txt")
        if not subs:
            return ModuleResult(module=self.name, status="skipped", errors=["No subdomains to probe"])

        subs_file = self.workspace.file("subdomains.txt")
        live: list[str] = []
        records: list[dict] = []

        used_httpx = False
        if is_installed("httpx"):
            self.emit("log", msg=f"Probing {len(subs)} hosts with httpx")
            result = run_tool(
                f"httpx -l {subs_file} -silent -json -status-code -title -tech-detect -follow-redirects -timeout 15",
                timeout=300,
            )
            if result.returncode == 0 and result.stdout.strip():
                used_httpx = True
                for line in result.stdout.splitlines():
                    if not line.strip():
                        continue
                    try:
                        data = json.loads(line)
                        url = data.get("url", "")
                        if url:
                            live.append(url)
                            records.append({
                                "url": url,
                                "host": data.get("host", ""),
                                "status_code": data.get("status_code", 0),
                                "title": data.get("title", ""),
                                "tech": data.get("tech", []),
                                "content_length": data.get("content_length", 0),
                                "webserver": data.get("webserver", ""),
                            })
                    except json.JSONDecodeError:
                        if line.strip().startswith("http"):
                            live.append(line.strip())

        if not used_httpx:
            self.emit("log", msg=f"httpx not found, using Python fallback for {len(subs)} hosts")
            live, records = self._fallback_probe(subs)

        self.workspace.append_lines("live.txt", live)
        self.workspace.append_jsonl("hosts.jsonl", records)

        return ModuleResult(
            module=self.name,
            items=live,
            records=records,
            tool_used="httpx" if used_httpx else "python-requests",
            fallback=not used_httpx,
        )

    def _fallback_probe(self, subs: list[str]) -> tuple[list[str], list[dict]]:
        live = []
        records = []
        for sub in subs:
            for scheme in ("https", "http"):
                url = f"{scheme}://{sub}"
                try:
                    resp = requests.get(url, timeout=10, allow_redirects=True,
                                        headers={"User-Agent": self.config.get("user_agent", "")},
                                        verify=False)
                    live.append(resp.url)
                    title = ""
                    if "<title>" in resp.text.lower():
                        start = resp.text.lower().index("<title>") + 7
                        end = resp.text.lower().index("</title>", start)
                        title = resp.text[start:end].strip()
                    records.append({
                        "url": resp.url,
                        "host": sub,
                        "status_code": resp.status_code,
                        "title": title[:200],
                        "tech": [],
                        "content_length": len(resp.content),
                    })
                    self.emit("log", msg=f"[LIVE] {resp.status_code} {resp.url}")
                    break
                except Exception:
                    continue
        return live, records
