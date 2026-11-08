from dataclasses import dataclass, field
import time


@dataclass
class ModuleResult:
    module: str
    status: str = "success"
    items: list[str] = field(default_factory=list)
    records: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    duration: float = 0.0
    tool_used: str = ""
    fallback: bool = False


class BaseModule:
    name: str = "base"
    phase: str = "unknown"
    tools_needed: list[str] = []

    def __init__(self, workspace, scope, config, event_callback=None):
        self.workspace = workspace
        self.scope = scope
        self.config = config
        self.emit = event_callback or (lambda *a, **k: None)

    def run(self) -> ModuleResult:
        start = time.time()
        self.emit("module_start", module=self.name, phase=self.phase)
        try:
            result = self.execute()
            result.duration = time.time() - start
            self.emit("module_done", module=self.name, items=len(result.items), duration=result.duration)
            return result
        except Exception as e:
            self.emit("module_error", module=self.name, error=str(e))
            return ModuleResult(module=self.name, status="error", errors=[str(e)], duration=time.time() - start)

    def execute(self) -> ModuleResult:
        raise NotImplementedError
