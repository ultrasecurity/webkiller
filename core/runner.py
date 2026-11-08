import subprocess
import shlex
import time
import threading
from dataclasses import dataclass, field


@dataclass
class RunResult:
    command: str
    returncode: int
    stdout: str
    stderr: str
    duration: float
    timed_out: bool = False


def run_tool(cmd: str, timeout: int = 300, cwd: str | None = None) -> RunResult:
    start = time.time()
    try:
        proc = subprocess.run(
            shlex.split(cmd),
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
        )
        return RunResult(
            command=cmd,
            returncode=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            duration=time.time() - start,
        )
    except subprocess.TimeoutExpired:
        return RunResult(
            command=cmd, returncode=-1, stdout="", stderr="timeout",
            duration=time.time() - start, timed_out=True,
        )
    except FileNotFoundError:
        return RunResult(
            command=cmd, returncode=-1, stdout="",
            stderr=f"tool not found: {cmd.split()[0]}",
            duration=time.time() - start,
        )


def run_tool_lines(cmd: str, timeout: int = 300) -> list[str]:
    result = run_tool(cmd, timeout)
    if result.returncode != 0:
        return []
    return [l.strip() for l in result.stdout.splitlines() if l.strip()]


class StreamRunner:
    def __init__(self, cmd: str, on_line=None, timeout: int = 600):
        self.cmd = cmd
        self.on_line = on_line
        self.timeout = timeout
        self.proc = None
        self.lines: list[str] = []

    def start(self):
        self.proc = subprocess.Popen(
            shlex.split(self.cmd),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        thread = threading.Thread(target=self._read, daemon=True)
        thread.start()
        return self

    def _read(self):
        for line in self.proc.stdout:
            line = line.strip()
            if line:
                self.lines.append(line)
                if self.on_line:
                    self.on_line(line)

    def wait(self) -> list[str]:
        if self.proc:
            self.proc.wait(timeout=self.timeout)
        return self.lines

    def kill(self):
        if self.proc:
            self.proc.kill()
