import json
from modules.base import BaseModule, ModuleResult
from core.runner import run_tool, run_tool_lines
from core.registry import is_installed


class SubdomainsActive(BaseModule):
    name = "subdomains_active"
    phase = "P2"
    tools_needed = ["dnsx"]

    def execute(self) -> ModuleResult:
        target = self.workspace.target
        existing = set(self.workspace.read_lines("subdomains.txt"))
        new_subs: set[str] = set()
        tool_used = []
        fallback = False

        if is_installed("dnsx"):
            self.emit("log", msg=f"Running dnsx brute-force on {target}")
            wordlist = self.config.get("dns_wordlist", "")
            if wordlist:
                cmd = f"dnsx -d {target} -w {wordlist} -silent -resp-only"
            else:
                cmd = f"dnsx -d {target} -silent -resp-only"
            lines = run_tool_lines(cmd, timeout=300)
            new_subs.update(lines)
            tool_used.append("dnsx")

        if is_installed("gotator") and existing:
            self.emit("log", msg="Running gotator permutations")
            subs_file = self.workspace.file("subdomains.txt")
            result = run_tool(
                f"gotator -sub {subs_file} -perm -depth 1 -numbers 3 -mindup -adv -silent",
                timeout=120,
            )
            if result.returncode == 0:
                perms = [l.strip() for l in result.stdout.splitlines() if l.strip()]
                new_subs.update(perms)
                tool_used.append("gotator")

        if is_installed("puredns") and new_subs:
            self.emit("log", msg=f"Resolving {len(new_subs)} permutations with puredns")
            perm_file = self.workspace.file("_perms_tmp.txt")
            perm_file.write_text("\n".join(new_subs))
            result = run_tool(
                f"puredns resolve {perm_file} --quiet",
                timeout=300,
            )
            if result.returncode == 0:
                resolved = {l.strip() for l in result.stdout.splitlines() if l.strip()}
                new_subs = resolved
                tool_used.append("puredns")
            perm_file.unlink(missing_ok=True)

        if not tool_used:
            fallback = True
            self.emit("log", msg="No active tools available, using DNS A-record check")
            new_subs = self._dns_resolve_fallback(existing)
            tool_used.append("python-dns")

        combined = existing | new_subs
        filtered = self.scope.filter_domains(sorted(combined))
        diff = sorted(set(filtered) - existing)

        if diff:
            self.workspace.append_lines("subdomains.txt", diff)
            self.workspace.append_jsonl("hosts.jsonl", [
                {"subdomain": s, "source": "active", "target": target} for s in diff
            ])

        return ModuleResult(
            module=self.name,
            items=diff,
            tool_used=", ".join(tool_used),
            fallback=fallback,
        )

    def _dns_resolve_fallback(self, known: set[str]) -> set[str]:
        import socket
        resolved = set()
        common_prefixes = [
            "www", "mail", "ftp", "admin", "dev", "staging", "api",
            "app", "beta", "test", "portal", "vpn", "ns1", "ns2",
            "cdn", "static", "assets", "media", "blog", "shop",
        ]
        target = self.workspace.target
        for prefix in common_prefixes:
            sub = f"{prefix}.{target}"
            if sub in known:
                continue
            try:
                socket.getaddrinfo(sub, None, socket.AF_INET, socket.SOCK_STREAM)
                resolved.add(sub)
            except socket.gaierror:
                pass
        return resolved
