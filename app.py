import json
import time
import os
from pathlib import Path
from flask import Flask, jsonify, request, send_from_directory, Response
from core.engine import ScanEngine
from core.registry import check_all, TOOLS
from core.config import list_profiles, load_profile, OUTPUT_DIR

app = Flask(__name__, static_folder="web", static_url_path="")
engine = ScanEngine()


@app.route("/")
def index():
    return send_from_directory("web", "index.html")


@app.route("/api/scan", methods=["POST"])
def start_scan():
    data = request.json or {}
    target = data.get("target", "").strip()
    if not target:
        return jsonify({"error": "target required"}), 400
    profile = data.get("profile", "quick")
    out_of_scope = data.get("out_of_scope", [])
    scan_id = engine.start_scan(target, profile, out_of_scope)
    return jsonify({"scan_id": scan_id, "status": "started"})


@app.route("/api/scan/<scan_id>")
def get_scan(scan_id):
    scan = engine.get_scan(scan_id)
    if not scan:
        return jsonify({"error": "not found"}), 404
    return jsonify(scan)


@app.route("/api/scans")
def list_scans():
    return jsonify(engine.list_scans())


@app.route("/api/scan/<scan_id>/events")
def stream_events(scan_id):
    def generate():
        last_seq = 0
        while True:
            events = engine.get_events(scan_id, after=last_seq)
            for ev in events:
                last_seq = ev["seq"]
                yield f"data: {json.dumps(ev)}\n\n"
            scan = engine.get_scan(scan_id)
            if scan and scan["status"] in ("completed", "error"):
                yield f"data: {json.dumps({'type': 'end', 'status': scan['status']})}\n\n"
                break
            time.sleep(0.5)
    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/api/scan/<scan_id>/results/<filename>")
def get_result_file(scan_id, filename):
    scan = engine.get_scan(scan_id)
    if not scan:
        return jsonify({"error": "not found"}), 404
    ws_path = Path(scan["workspace_path"])
    fpath = ws_path / filename
    if not fpath.exists():
        return jsonify({"error": "file not found"}), 404
    if filename.endswith(".jsonl"):
        lines = []
        for line in fpath.read_text().splitlines():
            if line.strip():
                lines.append(json.loads(line))
        return jsonify(lines)
    return fpath.read_text(), 200, {"Content-Type": "text/plain"}


@app.route("/api/tools")
def get_tools():
    status = check_all()
    result = []
    for name, installed in status.items():
        info = TOOLS.get(name, {})
        result.append({
            "name": name,
            "installed": installed,
            "required_for": info.get("required_for", []),
        })
    return jsonify(result)


@app.route("/api/profiles")
def get_profiles():
    result = []
    for name in list_profiles():
        try:
            profile = load_profile(name)
            result.append(profile)
        except Exception:
            pass
    return jsonify(result)


@app.route("/api/scan/<scan_id>/export/json")
def export_json(scan_id):
    scan = engine.get_scan(scan_id)
    if not scan:
        return jsonify({"error": "not found"}), 404
    ws_path = Path(scan["workspace_path"])
    export = {
        "scan_id": scan_id,
        "target": scan["target"],
        "profile": scan["profile"],
        "status": scan["status"],
        "started_at": scan.get("started_at"),
        "finished_at": scan.get("finished_at"),
        "modules": scan.get("results", {}),
        "files": {},
    }
    for f in ws_path.iterdir():
        if f.is_file() and f.suffix in (".txt", ".jsonl", ".json", ".md"):
            try:
                text = f.read_text(errors="replace")
                if f.suffix == ".jsonl":
                    export["files"][f.name] = [json.loads(l) for l in text.splitlines() if l.strip()]
                elif f.suffix == ".json":
                    export["files"][f.name] = json.loads(text)
                else:
                    export["files"][f.name] = text.splitlines()
            except Exception:
                pass
    resp = Response(
        json.dumps(export, indent=2, default=str, ensure_ascii=False),
        mimetype="application/json",
        headers={"Content-Disposition": f'attachment; filename="webkiller_{scan["target"]}_{scan_id}.json"'},
    )
    return resp


@app.route("/api/scan/<scan_id>/export/html")
def export_html(scan_id):
    scan = engine.get_scan(scan_id)
    if not scan:
        return jsonify({"error": "not found"}), 404
    ws_path = Path(scan["workspace_path"])

    def read_lines(name):
        p = ws_path / name
        return p.read_text(errors="replace").splitlines() if p.exists() else []

    def read_jsonl(name):
        p = ws_path / name
        if not p.exists():
            return []
        out = []
        for line in p.read_text(errors="replace").splitlines():
            if line.strip():
                try:
                    out.append(json.loads(line))
                except Exception:
                    pass
        return out

    subdomains = read_lines("subdomains.txt")
    live = read_lines("live.txt")
    urls = read_lines("urls.txt")
    findings = read_jsonl("findings.jsonl")
    confirmed = read_jsonl("confirmed.jsonl")
    results = scan.get("results", {})
    started = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(scan.get("started_at", 0)))
    finished = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(scan.get("finished_at", 0))) if scan.get("finished_at") else "—"
    duration = f"{scan.get('finished_at', 0) - scan.get('started_at', 0):.0f}s" if scan.get("finished_at") else "—"

    sev_colors = {"critical": "#ff4444", "high": "#ff8c00", "medium": "#ffcc00", "low": "#00d4aa", "info": "#5a7a80"}

    findings_html = ""
    for f in findings[:100]:
        sev = f.get("severity", "info")
        c = sev_colors.get(sev, "#5a7a80")
        findings_html += f'<tr><td><span style="background:{c};color:#000;padding:2px 8px;border-radius:2px;font-size:11px;font-weight:700">{sev.upper()}</span></td>'
        findings_html += f'<td>{_esc(f.get("name", f.get("vuln_class", "Unknown")))}</td>'
        findings_html += f'<td style="word-break:break-all;font-size:12px">{_esc(f.get("url", ""))}</td></tr>'

    confirmed_html = ""
    for c in confirmed[:50]:
        sev = c.get("severity", "info")
        col = sev_colors.get(sev, "#5a7a80")
        confirmed_html += f'<div style="border-left:3px solid {col};padding:8px 16px;margin:8px 0;background:#161d1f">'
        confirmed_html += f'<strong>{_esc(c.get("name", ""))}</strong><br>'
        confirmed_html += f'<code style="font-size:12px;color:#5a7a80">{_esc(c.get("url", ""))}</code>'
        if c.get("evidence"):
            confirmed_html += f'<br><span style="font-size:11px;color:#888">Evidence: {_esc(json.dumps(c["evidence"])[:200])}</span>'
        confirmed_html += '</div>'

    modules_html = ""
    for name, r in results.items():
        status_color = "#00d4aa" if r["status"] == "success" else "#ff4444" if r["status"] == "error" else "#5a7a80"
        modules_html += f'<tr><td>{name}</td><td>{r.get("tool_used", "python")}</td>'
        modules_html += f'<td style="color:{status_color}">{r["status"]}</td>'
        modules_html += f'<td>{r["items_count"]}</td><td>{r["duration"]}s</td></tr>'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>WebKiller 2.0 — {_esc(scan['target'])}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{background:#0a0e0f;color:#c8d8da;font-family:'Inter',system-ui,sans-serif;padding:40px;line-height:1.6}}
h1{{color:#00d4aa;font-size:28px;margin-bottom:4px}}
h2{{color:#00d4aa;font-size:18px;margin:32px 0 12px;text-transform:uppercase;letter-spacing:2px;font-weight:600}}
h3{{font-size:14px;color:#5a7a80;margin-bottom:16px}}
.meta{{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin:24px 0}}
.meta-card{{background:#111618;border:1px solid #1a2528;border-radius:10px;padding:16px}}
.meta-label{{font-size:11px;text-transform:uppercase;letter-spacing:1.5px;color:#5a7a80;margin-bottom:4px}}
.meta-value{{font-size:24px;font-weight:700;font-family:'JetBrains Mono',monospace}}
.teal{{color:#00d4aa}} .amber{{color:#ffcc00}} .red{{color:#ff4444}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
th{{text-align:left;padding:8px 12px;border-bottom:1px solid #1a2528;color:#5a7a80;font-size:11px;text-transform:uppercase;letter-spacing:1px}}
td{{padding:8px 12px;border-bottom:1px solid #111618}}
code{{font-family:'JetBrains Mono',monospace;font-size:12px}}
.list{{background:#111618;border:1px solid #1a2528;border-radius:10px;padding:16px;max-height:400px;overflow-y:auto;font-family:'JetBrains Mono',monospace;font-size:12px;line-height:1.8}}
.footer{{margin-top:48px;padding-top:16px;border-top:1px solid #1a2528;font-size:11px;color:#5a7a80;text-align:center}}
@media(max-width:600px){{
  body{{padding:16px}}
  h1{{font-size:22px}}
  .meta{{grid-template-columns:1fr 1fr;gap:10px}}
  .meta-value{{font-size:20px}}
  table{{font-size:11px}}
  th,td{{padding:6px 8px}}
  th:nth-child(5),td:nth-child(5){{display:none}}
  .list{{font-size:11px;word-break:break-all;max-height:300px}}
}}
</style>
</head>
<body>
<h1>WebKiller 2.0 — Recon Report</h1>
<h3>{_esc(scan['target'])} · Profile: {_esc(scan['profile'])} · {started}</h3>

<div class="meta">
  <div class="meta-card"><div class="meta-label">Subdomains</div><div class="meta-value teal">{len(subdomains)}</div></div>
  <div class="meta-card"><div class="meta-label">Live Hosts</div><div class="meta-value teal">{len(live)}</div></div>
  <div class="meta-card"><div class="meta-label">Findings</div><div class="meta-value amber">{len(findings)}</div></div>
  <div class="meta-card"><div class="meta-label">Confirmed</div><div class="meta-value red">{len(confirmed)}</div></div>
</div>

<h2>Module Results</h2>
<table>
<thead><tr><th>Module</th><th>Tool</th><th>Status</th><th>Items</th><th>Duration</th></tr></thead>
<tbody>{modules_html}</tbody>
</table>

{"<h2>Confirmed Vulnerabilities</h2>" + confirmed_html if confirmed_html else ""}

{"<h2>Findings</h2><table><thead><tr><th>Severity</th><th>Name</th><th>URL</th></tr></thead><tbody>" + findings_html + "</tbody></table>" if findings_html else ""}

{"<h2>Subdomains (" + str(len(subdomains)) + ")</h2><div class='list'>" + "<br>".join(_esc(s) for s in subdomains[:500]) + "</div>" if subdomains else ""}

{"<h2>Live Hosts (" + str(len(live)) + ")</h2><div class='list'>" + "<br>".join(_esc(s) for s in live[:500]) + "</div>" if live else ""}

{"<h2>URLs (" + str(len(urls)) + ")</h2><div class='list'>" + "<br>".join(_esc(s) for s in urls[:500]) + "</div>" if urls else ""}

<div class="footer">
  Generated by WebKiller 2.0 · {started} — {finished} · Duration: {duration}
</div>
</body></html>"""

    return Response(
        html,
        mimetype="text/html",
        headers={"Content-Disposition": f'attachment; filename="webkiller_{scan["target"]}_{scan_id}.html"'},
    )


def _esc(s):
    return str(s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


@app.route("/api/workspace/<target>")
def list_workspace(target):
    target_dir = OUTPUT_DIR / target
    if not target_dir.exists():
        return jsonify([])
    scans = []
    for scan_dir in sorted(target_dir.iterdir(), reverse=True):
        if scan_dir.is_dir():
            state_file = scan_dir / "state.json"
            if state_file.exists():
                scans.append(json.loads(state_file.read_text()))
            else:
                scans.append({"scan_id": scan_dir.name, "target": target})
    return jsonify(scans)


@app.route("/api/tools/refresh", methods=["POST"])
def refresh_tools():
    from core.registry import clear_cache
    clear_cache()
    return get_tools()


if __name__ == "__main__":
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    port = int(os.environ.get("WEBKILLER_PORT", "8443"))
    debug = os.environ.get("WEBKILLER_DEBUG", "true").lower() == "true"
    app.run(host="127.0.0.1", port=port, debug=debug)
