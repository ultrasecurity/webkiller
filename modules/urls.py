import requests
from modules.base import BaseModule, ModuleResult
from core.runner import run_tool_lines
from core.registry import is_installed


class URLs(BaseModule):
    name = "urls"
    phase = "P4"
    tools_needed = ["gau", "katana"]

    def execute(self) -> ModuleResult:
        target = self.workspace.target
        live = self.workspace.read_lines("live.txt")
        all_urls: set[str] = set()
        tool_used = []
        fallback = False

        if is_installed("gau"):
            self.emit("log", msg=f"Running gau on {target}")
            lines = run_tool_lines(f"gau {target} --threads 5 --timeout 30", timeout=120)
            all_urls.update(lines)
            tool_used.append("gau")

        if is_installed("katana") and live:
            live_file = self.workspace.file("live.txt")
            self.emit("log", msg=f"Running katana on {len(live)} live hosts")
            lines = run_tool_lines(
                f"katana -list {live_file} -silent -jc -d 3 -timeout 15",
                timeout=180,
            )
            all_urls.update(lines)
            tool_used.append("katana")

        if not tool_used:
            self.emit("log", msg="No URL tools found, using Wayback Machine fallback")
            wb_urls = self._wayback_fallback(target)
            all_urls.update(wb_urls)
            tool_used.append("wayback-api")
            fallback = True

        filtered = self.scope.filter_urls(list(all_urls))
        filtered = sorted(set(filtered))

        self.workspace.append_lines("urls.txt", filtered)

        return ModuleResult(
            module=self.name,
            items=filtered,
            tool_used=", ".join(tool_used),
            fallback=fallback,
        )

    def _wayback_fallback(self, domain: str) -> list[str]:
        try:
            resp = requests.get(
                f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=text&fl=original&collapse=urlkey",
                timeout=30,
                headers={"User-Agent": self.config.get("user_agent", "WebKiller/2.0")},
            )
            if resp.status_code == 200:
                return [l.strip() for l in resp.text.splitlines() if l.strip()]
        except Exception as e:
            self.emit("log", msg=f"Wayback error: {e}")
        return []
