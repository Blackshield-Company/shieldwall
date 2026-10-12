import os
import subprocess
from dataclasses import dataclass

DENY_MARKERS = (
    "permission denied",
    "operation not permitted",
    "must be root",
    "need to be root",
    "you need to be root",
    "access denied",
    "insufficient privileges",
    "not privileged",
    "a password is required",
    "not seeing messages from other users",
)


@dataclass
class CommandResult:
    argv: tuple[str, ...]
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool = False
    not_found: bool = False

    def blob(self) -> str:
        return f"{self.stdout}\n{self.stderr}"


def access_denied(result: CommandResult) -> bool:
    if result.not_found or result.timed_out:
        return False
    low = result.blob().lower()
    return any(marker in low for marker in DENY_MARKERS)


class Runner:
    def __init__(self, timeout: float = 5.0):
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self.timeout = timeout

    def run(self, argv: list[str], timeout: float | None = None) -> CommandResult:
        if not argv or not all(isinstance(part, str) for part in argv):
            raise ValueError("argv must be a non-empty list of strings")
        if any("\x00" in part for part in argv):
            raise ValueError("argv contains NUL")
        limit = self.timeout if timeout is None else timeout
        env = dict(os.environ)
        env["LC_ALL"] = "C"
        env["LANG"] = "C"
        try:
            proc = subprocess.run(
                argv,
                shell=False,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=limit,
                check=False,
                env=env,
            )
        except FileNotFoundError:
            return CommandResult(tuple(argv), None, "", "", not_found=True)
        except PermissionError:
            return CommandResult(tuple(argv), None, "", "permission denied")
        except subprocess.TimeoutExpired as exc:
            out = exc.stdout or ""
            err = exc.stderr or ""
            if isinstance(out, bytes):
                out = out.decode("utf-8", "replace")
            if isinstance(err, bytes):
                err = err.decode("utf-8", "replace")
            return CommandResult(tuple(argv), None, out, err, timed_out=True)
        return CommandResult(tuple(argv), proc.returncode, proc.stdout or "", proc.stderr or "")
