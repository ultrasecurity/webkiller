import json
from pathlib import Path
from modules.base import BaseModule, ModuleResult
from core.runner import run_tool
from core.registry import is_installed


class Screenshots(BaseModule):
    name = "screenshots"
    phase = "P5"
    tools_needed = ["gowitness"]

    def execute(self) -> ModuleResult:
        live_hosts = self.workspace.read_lines("live.txt")
        if not live_hosts:
            return ModuleResult(module=self.name, status="skipped", errors=["No live hosts"])

        max_hosts = self.config.get("screenshot_max_hosts", 50)
        targets = live_hosts[:max_hosts]
        tool_used = []
        fallback = False
        items: list[str] = []
        records: list[dict] = []

        if is_installed("gowitness"):
            tool_used.append("gowitness")
            items, records = self._gowitness(targets)
        else:
            fallback = True
            tool_used.append("python-headers")
            self.emit("log", msg="gowitness not available, collecting page metadata")
            items, records = self._metadata_fallback(targets)

        if records:
            self.workspace.append_jsonl("screenshots.jsonl", records)

        return ModuleResult(
            module=self.name,
            items=items,
            records=records,
            tool_used=", ".join(tool_used),
            fallback=fallback,
        )

    def _gowitness(self, targets: list[str]) -> tuple[list[str], list[dict]]:
        urls_file = self.workspace.file("_screenshot_urls.txt")
        urls_file.write_text("\n".join(targets))
        out_dir = self.workspace.file("screenshots")
        out_dir.mkdir(exist_ok=True)

        self.emit("log", msg=f"gowitness: screenshotting {len(targets)} hosts")
        result = run_tool(
            f"gowitness file -f {urls_file} -P {out_dir} --timeout 15 "
            f"--resolution-x 1280 --resolution-y 800",
            timeout=300,
        )
        urls_file.unlink(missing_ok=True)

        items = []
        records = []
        if out_dir.exists():
            for f in sorted(out_dir.iterdir()):
                if f.suffix in (".png", ".jpg", ".jpeg"):
                    items.append(str(f.relative_to(self.workspace.root)))
                    records.append({
                        "url": f.stem.replace("_", "://", 1).replace("_", "/"),
                        "screenshot": str(f.relative_to(self.workspace.root)),
                        "type": "screenshot",
                    })
        db_path = out_dir / "gowitness.sqlite3"
        if db_path.exists():
            records.extend(self._parse_gowitness_db(db_path))

        return items, records

    def _parse_gowitness_db(self, db_path: Path) -> list[dict]:
        try:
            import sqlite3
            conn = sqlite3.connect(str(db_path))
            cursor = conn.execute(
                "SELECT final_url, response_code, title FROM urls ORDER BY id"
            )
            records = []
            for row in cursor:
                records.append({
                    "url": row[0],
                    "status": row[1],
                    "title": row[2],
                    "type": "screenshot_meta",
                })
            conn.close()
            return records
        except Exception:
            return []

    def _metadata_fallback(self, targets: list[str]) -> tuple[list[str], list[dict]]:
        import requests
        import re

        items = []
        records = []
        ua = self.config.get("user_agent", "WebKiller/2.0")

        for url in targets:
            try:
                resp = requests.get(url, timeout=8, headers={"User-Agent": ua},
                                    allow_redirects=True, verify=False)
                title_match = re.search(r"<title[^>]*>([^<]+)</title>", resp.text, re.I)
                title = title_match.group(1).strip() if title_match else ""
                server = resp.headers.get("Server", "")
                tech_headers = {
                    k: v for k, v in resp.headers.items()
                    if k.lower() in ("x-powered-by", "x-generator", "x-aspnet-version")
                }
                records.append({
                    "url": url,
                    "status": resp.status_code,
                    "title": title,
                    "server": server,
                    "headers": tech_headers,
                    "length": len(resp.content),
                    "type": "page_meta",
                })
                items.append(url)
            except requests.RequestException:
                pass

        return items, records
