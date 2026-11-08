import shutil
import subprocess


TOOLS = {
    "subfinder": {"check": "subfinder -version", "required_for": ["subdomains_passive"]},
    "httpx": {"check": "httpx -version", "required_for": ["probe"]},
    "dnsx": {"check": "dnsx -version", "required_for": ["subdomains_active"]},
    "naabu": {"check": "naabu -version", "required_for": ["portscan"]},
    "nmap": {"check": "nmap --version", "required_for": ["portscan"]},
    "nuclei": {"check": "nuclei -version", "required_for": ["vuln_signal", "vuln_confirm"]},
    "katana": {"check": "katana -version", "required_for": ["urls"]},
    "gau": {"check": "gau -version", "required_for": ["urls"]},
    "ffuf": {"check": "ffuf -V", "required_for": ["content"]},
    "dalfox": {"check": "dalfox version", "required_for": ["xss_confirm"]},
    "ghauri": {"check": "ghauri --version", "required_for": ["sqli_confirm"]},
    "arjun": {"check": "arjun --help", "required_for": ["params"]},
    "wafw00f": {"check": "wafw00f -V", "required_for": ["fingerprint"]},
    "puredns": {"check": "puredns -h", "required_for": ["subdomains_active"]},
    "gotator": {"check": "gotator -h", "required_for": ["subdomains_active"]},
    "gf": {"check": "gf -h", "required_for": ["tagging"]},
    "trufflehog": {"check": "trufflehog --version", "required_for": ["secret_verify"]},
    "interactsh-client": {"check": "interactsh-client -version", "required_for": ["vuln_confirm"]},
    "gowitness": {"check": "gowitness version", "required_for": ["screenshots"]},
}

_cache: dict[str, bool] = {}


def is_installed(tool: str) -> bool:
    if tool in _cache:
        return _cache[tool]
    found = shutil.which(tool) is not None
    _cache[tool] = found
    return found


def check_all() -> dict[str, bool]:
    return {name: is_installed(name) for name in TOOLS}


def tools_for_module(module_name: str) -> list[dict]:
    result = []
    for name, info in TOOLS.items():
        if module_name in info["required_for"]:
            result.append({"name": name, "installed": is_installed(name)})
    return result


def missing_for_module(module_name: str) -> list[str]:
    return [t["name"] for t in tools_for_module(module_name) if not t["installed"]]


def clear_cache():
    _cache.clear()
