import json
import time
from pathlib import Path


class AssetStore:
    def __init__(self, workspace_root: Path):
        self.path = workspace_root / "assets.jsonl"
        self._seen: set[str] = set()
        self._load_existing()

    def _load_existing(self):
        if self.path.exists():
            for line in self.path.read_text().splitlines():
                if line.strip():
                    rec = json.loads(line)
                    key = rec.get("key", "")
                    if key:
                        self._seen.add(key)

    def _make_key(self, asset_type: str, value: str) -> str:
        return f"{asset_type}:{value.strip().lower()}"

    def add(self, asset_type: str, value: str, meta: dict | None = None) -> bool:
        key = self._make_key(asset_type, value)
        if key in self._seen:
            return False
        self._seen.add(key)
        record = {
            "key": key,
            "type": asset_type,
            "value": value.strip(),
            "discovered_at": time.time(),
            **(meta or {}),
        }
        with open(self.path, "a") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
        return True

    def add_many(self, asset_type: str, values: list[str], meta: dict | None = None) -> int:
        count = 0
        for v in values:
            if self.add(asset_type, v, meta):
                count += 1
        return count

    def get_all(self, asset_type: str | None = None) -> list[dict]:
        if not self.path.exists():
            return []
        results = []
        for line in self.path.read_text().splitlines():
            if line.strip():
                rec = json.loads(line)
                if asset_type is None or rec.get("type") == asset_type:
                    results.append(rec)
        return results

    def count(self, asset_type: str | None = None) -> int:
        return len(self.get_all(asset_type))

    def diff(self, other_store_path: Path) -> list[dict]:
        if not other_store_path.exists():
            return self.get_all()
        old_keys = set()
        for line in other_store_path.read_text().splitlines():
            if line.strip():
                rec = json.loads(line)
                old_keys.add(rec.get("key", ""))
        return [a for a in self.get_all() if a["key"] not in old_keys]
