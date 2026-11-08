import json
import re
import hashlib
from modules.base import BaseModule, ModuleResult


class Tagging(BaseModule):
    name = "tagging"
    phase = "P8"
    tools_needed = []

    SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    def execute(self) -> ModuleResult:
        findings = self.workspace.read_jsonl("findings.jsonl")
        confirmed = self.workspace.read_jsonl("confirmed.jsonl")

        if not findings and not confirmed:
            return ModuleResult(module=self.name, status="skipped",
                              errors=["No findings to process"])

        self.emit("log", msg=f"Processing {len(findings)} findings + {len(confirmed)} confirmed")

        deduped = self._dedup(findings)
        tagged = self._tag_severity(deduped)
        grouped = self._group_by_class(tagged)

        summary = {
            "total_raw": len(findings),
            "total_confirmed": len(confirmed),
            "total_unique": len(deduped),
            "by_severity": {},
            "by_class": {},
        }

        for sev in ("critical", "high", "medium", "low", "info"):
            count = len([f for f in tagged if f.get("severity") == sev])
            if count:
                summary["by_severity"][sev] = count

        for cls, items in grouped.items():
            summary["by_class"][cls] = len(items)

        self.workspace.append_jsonl("findings_deduped.jsonl", deduped)

        report_lines = self._build_report(summary, tagged, confirmed)
        report_path = self.workspace.file("report.md")
        report_path.write_text("\n".join(report_lines))

        summary_path = self.workspace.file("summary.json")
        summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False))

        return ModuleResult(
            module=self.name,
            items=[f"{k}: {v}" for k, v in summary["by_severity"].items()],
            records=[summary],
            tool_used="python-tagger",
            fallback=False,
        )

    def _dedup(self, findings: list[dict]) -> list[dict]:
        seen: set[str] = set()
        unique = []
        for f in findings:
            key = self._finding_key(f)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    def _finding_key(self, f: dict) -> str:
        parts = [
            f.get("name", ""),
            f.get("url", ""),
            f.get("vuln_class", ""),
            f.get("template_id", ""),
        ]
        raw = "|".join(str(p) for p in parts)
        return hashlib.md5(raw.encode()).hexdigest()

    def _tag_severity(self, findings: list[dict]) -> list[dict]:
        for f in findings:
            if not f.get("severity"):
                f["severity"] = self._infer_severity(f)
        return sorted(findings, key=lambda f: self.SEVERITY_ORDER.get(f.get("severity", "info"), 4))

    def _infer_severity(self, f: dict) -> str:
        name = (f.get("name", "") + " " + f.get("vuln_class", "")).lower()
        if any(w in name for w in ("sqli", "rce", "command injection", "ssrf", "ssti")):
            return "critical"
        if any(w in name for w in ("xss", "idor", "secret", "private key", "token")):
            return "high"
        if any(w in name for w in ("redirect", "cors", "csrf", "header injection")):
            return "medium"
        if any(w in name for w in ("info", "disclosure", "version", "server")):
            return "low"
        return "info"

    def _group_by_class(self, findings: list[dict]) -> dict[str, list[dict]]:
        groups: dict[str, list[dict]] = {}
        for f in findings:
            cls = f.get("vuln_class", f.get("type", "other"))
            if cls not in groups:
                groups[cls] = []
            groups[cls].append(f)
        return groups

    def _build_report(self, summary: dict, findings: list[dict], confirmed: list[dict]) -> list[str]:
        lines = [
            "# WebKiller 2.0 — Recon Report",
            "",
            f"**Total findings:** {summary['total_unique']} unique "
            f"({summary['total_confirmed']} confirmed)",
            "",
            "## Severity Breakdown",
            "",
        ]

        for sev, count in summary["by_severity"].items():
            emoji = {"critical": "!!!", "high": "!!", "medium": "!", "low": ".", "info": "-"}
            lines.append(f"- [{emoji.get(sev, '?')}] {sev.upper()}: {count}")

        lines += ["", "## Vulnerability Classes", ""]
        for cls, count in summary["by_class"].items():
            lines.append(f"- {cls}: {count}")

        if confirmed:
            lines += ["", "## Confirmed Vulnerabilities", ""]
            for c in confirmed:
                lines.append(f"### {c.get('name', 'Unknown')}")
                lines.append(f"- **URL:** `{c.get('url', '')}`")
                lines.append(f"- **Severity:** {c.get('severity', 'unknown')}")
                ev = c.get("evidence", {})
                if ev:
                    lines.append(f"- **Evidence:** `{json.dumps(ev)[:200]}`")
                lines.append("")

        if findings:
            lines += ["", "## All Findings", ""]
            for f in findings[:50]:
                lines.append(f"- [{f.get('severity', '?')}] {f.get('name', '?')} — `{f.get('url', '')}`")

        return lines
