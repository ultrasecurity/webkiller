import time
import threading
import json
from core.config import load_profile, get_config
from core.scope import Scope
from core.workspace import Workspace
from core.store import AssetStore

MODULE_MAP = {}


def _load_modules():
    global MODULE_MAP
    from modules.subdomains_passive import SubdomainsPassive
    from modules.subdomains_active import SubdomainsActive
    from modules.probe import Probe
    from modules.urls import URLs
    from modules.portscan import Portscan
    from modules.fingerprint import Fingerprint
    from modules.content import Content
    from modules.jsrecon import JsRecon
    from modules.params import Params
    from modules.screenshots import Screenshots
    from modules.vuln_signal import VulnSignal
    from modules.vuln_confirm import VulnConfirm
    from modules.xss_confirm import XssConfirm
    from modules.sqli_confirm import SqliConfirm
    from modules.authz_probe import AuthzProbe
    from modules.bypass_403 import Bypass403
    from modules.secret_verify import SecretVerify
    from modules.osint_dns import OsintDNS
    from modules.tagging import Tagging

    MODULE_MAP = {
        "subdomains_passive": SubdomainsPassive,
        "subdomains_active": SubdomainsActive,
        "probe": Probe,
        "urls": URLs,
        "portscan": Portscan,
        "fingerprint": Fingerprint,
        "content": Content,
        "jsrecon": JsRecon,
        "params": Params,
        "screenshots": Screenshots,
        "vuln_signal": VulnSignal,
        "vuln_confirm": VulnConfirm,
        "xss_confirm": XssConfirm,
        "sqli_confirm": SqliConfirm,
        "authz_probe": AuthzProbe,
        "bypass_403": Bypass403,
        "secret_verify": SecretVerify,
        "osint_dns": OsintDNS,
        "tagging": Tagging,
    }


_load_modules()


class ScanEngine:
    def __init__(self):
        self.scans: dict[str, dict] = {}
        self.events: dict[str, list] = {}
        self._lock = threading.Lock()

    def start_scan(self, target: str, profile_name: str = "quick",
                   out_of_scope: list[str] | None = None,
                   config_overrides: dict | None = None) -> str:
        profile = load_profile(profile_name)
        config = get_config(config_overrides)
        workspace = Workspace(target)
        scope = Scope([f"*.{target}", target], out_of_scope)
        store = AssetStore(workspace.root)
        scan_id = workspace.scan_id

        with self._lock:
            self.scans[scan_id] = {
                "scan_id": scan_id,
                "target": target,
                "profile": profile_name,
                "status": "running",
                "started_at": time.time(),
                "modules_total": len(profile["modules"]),
                "modules_done": 0,
                "current_module": None,
                "results": {},
                "workspace_path": str(workspace.root),
            }
            self.events[scan_id] = []

        def run():
            try:
                for mod_name in profile["modules"]:
                    if mod_name not in MODULE_MAP:
                        self._add_event(scan_id, "warn", f"Unknown module: {mod_name}")
                        continue

                    with self._lock:
                        self.scans[scan_id]["current_module"] = mod_name

                    self._add_event(scan_id, "module_start", mod_name)
                    workspace.mark_phase(mod_name, "running")

                    mod_cls = MODULE_MAP[mod_name]
                    mod = mod_cls(workspace, scope, config, event_callback=lambda t, **kw: self._add_event(scan_id, t, json.dumps(kw, default=str)))

                    result = mod.run()
                    workspace.mark_phase(mod_name, result.status)

                    with self._lock:
                        self.scans[scan_id]["results"][mod_name] = {
                            "status": result.status,
                            "items_count": len(result.items),
                            "duration": round(result.duration, 1),
                            "tool_used": result.tool_used,
                            "fallback": result.fallback,
                            "errors": result.errors,
                        }
                        self.scans[scan_id]["modules_done"] += 1

                    store.add_many(mod_name, result.items)
                    self._add_event(scan_id, "module_done", f"{mod_name}: {len(result.items)} items in {result.duration:.1f}s")

                with self._lock:
                    self.scans[scan_id]["status"] = "completed"
                    self.scans[scan_id]["finished_at"] = time.time()
                    self.scans[scan_id]["current_module"] = None
                self._add_event(scan_id, "scan_done", "completed")
            except Exception as e:
                with self._lock:
                    self.scans[scan_id]["status"] = "error"
                    self.scans[scan_id]["error"] = str(e)
                self._add_event(scan_id, "error", str(e))

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        return scan_id

    def get_scan(self, scan_id: str) -> dict | None:
        return self.scans.get(scan_id)

    def list_scans(self) -> list[dict]:
        return list(self.scans.values())

    def get_events(self, scan_id: str, after: int = 0) -> list[dict]:
        events = self.events.get(scan_id, [])
        return [e for e in events if e["seq"] > after]

    def _add_event(self, scan_id: str, event_type: str, data: str = ""):
        with self._lock:
            events = self.events.setdefault(scan_id, [])
            seq = len(events) + 1
            events.append({
                "seq": seq,
                "type": event_type,
                "data": data,
                "time": time.time(),
            })
