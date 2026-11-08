import yaml
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
PROFILES_DIR = BASE_DIR / "profiles"
OUTPUT_DIR = Path(os.environ.get("WEBKILLER_OUTPUT_DIR", str(BASE_DIR / "output")))
WORDLISTS_DIR = BASE_DIR / "wordlists"
RESOLVERS_DIR = BASE_DIR / "resolvers"

DEFAULT_CONFIG = {
    "concurrency": 20,
    "rate_limit": 50,
    "timeout": 30,
    "user_agent": "WebKiller/2.0 (Recon; +authorized-security-testing)",
    "bug_bounty_header": "",
    "resolvers_file": "",
    "notify": {"enabled": False, "webhook": ""},
    "interactsh": {"enabled": False, "server": ""},
}


def load_profile(name: str) -> dict:
    path = PROFILES_DIR / f"{name}.yaml"
    if not path.exists():
        raise FileNotFoundError(f"Profile not found: {name}")
    with open(path) as f:
        return yaml.safe_load(f)


def list_profiles() -> list[str]:
    return [p.stem for p in PROFILES_DIR.glob("*.yaml")]


def get_config(overrides: dict | None = None) -> dict:
    cfg = dict(DEFAULT_CONFIG)
    if overrides:
        cfg.update(overrides)
    return cfg
