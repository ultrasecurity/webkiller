import json
from pathlib import Path
from modules.base import BaseModule, ModuleResult
from core.runner import run_tool, run_tool_lines
from core.registry import is_installed


class Content(BaseModule):
    name = "content"
    phase = "P4"
    tools_needed = ["ffuf"]

    def execute(self) -> ModuleResult:
        live_hosts = self.workspace.read_lines("live.txt")
        if not live_hosts:
            return ModuleResult(module=self.name, status="skipped", errors=["No live hosts"])

        all_paths: list[str] = []
        all_records: list[dict] = []
        tool_used = []
        fallback = False

        max_hosts = self.config.get("content_max_hosts", 10)
        wordlist = self.config.get("content_wordlist", "")
        targets = live_hosts[:max_hosts]

        if not wordlist:
            wordlist = self._find_default_wordlist()

        if is_installed("ffuf") and wordlist:
            tool_used.append("ffuf")
            for url in targets:
                self.emit("log", msg=f"ffuf: {url}")
                result = run_tool(
                    f"ffuf -u {url}/FUZZ -w {wordlist} -mc 200,301,302,403 "
                    f"-t 40 -timeout 10 -o /dev/stdout -of json -s",
                    timeout=180,
                )
                if result.returncode == 0 and result.stdout.strip():
                    records = self._parse_ffuf(result.stdout, url)
                    all_records.extend(records)
                    all_paths.extend(r["url"] for r in records)
        else:
            fallback = True
            tool_used.append("python-requests")
            self.emit("log", msg="ffuf not available, using Python fallback")
            for url in targets:
                records = self._brute_fallback(url)
                all_records.extend(records)
                all_paths.extend(r["url"] for r in records)

        if all_paths:
            self.workspace.append_lines("content.txt", all_paths)
        if all_records:
            self.workspace.append_jsonl("content.jsonl", all_records)

        return ModuleResult(
            module=self.name,
            items=all_paths,
            records=all_records,
            tool_used=", ".join(tool_used),
            fallback=fallback,
        )

    _BUILTIN_WORDS = [
        "admin", "login", "dashboard", "api", "docs", "swagger",
        ".env", "config", "backup", "robots.txt", "sitemap.xml",
        ".git/HEAD", "wp-admin", "wp-login.php", "server-status",
        "phpinfo.php", ".well-known/security.txt", "graphql",
        "debug", "test", "status", "health", "info",
        "console", "portal", "panel", "manager", "upload",
        "uploads", "assets", "static", "media", "images",
        "css", "js", "fonts", "vendor", "node_modules",
        "package.json", "composer.json", ".htaccess", "web.config",
        "crossdomain.xml", "clientaccesspolicy.xml",
        "actuator", "actuator/health", "actuator/env",
        ".DS_Store", "README.md", "LICENSE", "CHANGELOG.md",
        "v1", "v2", "api/v1", "api/v2", "api/docs",
        "swagger-ui.html", "api-docs", "openapi.json",
        "wp-content", "wp-includes", "wp-json",
        "cgi-bin", "server-info", "trace.axd",
        "elmah.axd", "error_log", "debug.log",
    ]

    def _find_default_wordlist(self) -> str:
        candidates = [
            Path("/opt/homebrew/share/seclists/Discovery/Web-Content/common.txt"),
            Path("/usr/share/seclists/Discovery/Web-Content/common.txt"),
            Path("/usr/share/wordlists/dirb/common.txt"),
        ]
        for p in candidates:
            if p.exists():
                return str(p)
        builtin = Path(__file__).parent.parent / "wordlists" / "common.txt"
        builtin.parent.mkdir(parents=True, exist_ok=True)
        if not builtin.exists():
            builtin.write_text("\n".join(self._BUILTIN_WORDS) + "\n")
        return str(builtin)

    def _parse_ffuf(self, stdout: str, base_url: str) -> list[dict]:
        records = []
        try:
            data = json.loads(stdout)
            for r in data.get("results", []):
                records.append({
                    "url": r.get("url", ""),
                    "status": r.get("status", 0),
                    "length": r.get("length", 0),
                    "words": r.get("words", 0),
                    "source": base_url,
                })
        except (json.JSONDecodeError, KeyError):
            for line in stdout.splitlines():
                line = line.strip()
                if line and not line.startswith("{"):
                    records.append({"url": f"{base_url}/{line}", "source": base_url})
        return records

    def _brute_fallback(self, base_url: str) -> list[dict]:
        import requests

        common = [
            "admin", "login", "dashboard", "api", "docs", "swagger",
            ".env", "config", "backup", "robots.txt", "sitemap.xml",
            ".git/HEAD", "wp-admin", "wp-login.php", "server-status",
            "phpinfo.php", ".well-known/security.txt", "graphql",
            "debug", "test", "status", "health", "info",
        ]
        records = []
        ua = self.config.get("user_agent", "WebKiller/2.0")
        for path in common:
            try:
                url = f"{base_url.rstrip('/')}/{path}"
                resp = requests.get(url, timeout=5, allow_redirects=False,
                                    headers={"User-Agent": ua})
                if resp.status_code in (200, 301, 302, 403):
                    records.append({
                        "url": url,
                        "status": resp.status_code,
                        "length": len(resp.content),
                        "source": base_url,
                    })
            except requests.RequestException:
                pass
        return records
