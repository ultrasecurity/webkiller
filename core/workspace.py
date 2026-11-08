import json
import time
from pathlib import Path
from core.config import OUTPUT_DIR


class Workspace:
    def __init__(self, target: str, scan_id: str | None = None):
        self.target = target.strip().lower()
        self.scan_id = scan_id or f"scan_{int(time.time())}"
        self.root = OUTPUT_DIR / self.target / self.scan_id
        self.root.mkdir(parents=True, exist_ok=True)
        self.state_file = self.root / "state.json"
        self.state = self._load_state()

    def _load_state(self) -> dict:
        if self.state_file.exists():
            with open(self.state_file) as f:
                return json.loads(f.read())
        return {
            "target": self.target,
            "scan_id": self.scan_id,
            "started_at": time.time(),
            "phases_completed": [],
            "current_phase": None,
            "status": "created",
        }

    def save_state(self):
        with open(self.state_file, "w") as f:
            json.dump(self.state, f, indent=2)

    def mark_phase(self, phase: str, status: str = "completed"):
        if status == "completed" and phase not in self.state["phases_completed"]:
            self.state["phases_completed"].append(phase)
        self.state["current_phase"] = phase if status == "running" else None
        self.save_state()

    def file(self, name: str) -> Path:
        return self.root / name

    def append_lines(self, name: str, lines: list[str]):
        with open(self.file(name), "a") as f:
            for line in lines:
                f.write(line.strip() + "\n")

    def read_lines(self, name: str) -> list[str]:
        path = self.file(name)
        if not path.exists():
            return []
        return [l.strip() for l in path.read_text().splitlines() if l.strip()]

    def append_jsonl(self, name: str, records: list[dict]):
        with open(self.file(name), "a") as f:
            for rec in records:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    def read_jsonl(self, name: str) -> list[dict]:
        path = self.file(name)
        if not path.exists():
            return []
        results = []
        for line in path.read_text().splitlines():
            if line.strip():
                results.append(json.loads(line))
        return results
