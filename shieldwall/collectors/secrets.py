import json
import os
import re
import shutil
from dataclasses import dataclass
from pathlib import Path

from shieldwall.commands import secretsweep_argv
from shieldwall.model import Plate, unknown_plate

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "venv",
}
SKIP_EXT = {
    ".a",
    ".bz2",
    ".class",
    ".gif",
    ".gz",
    ".jar",
    ".jpeg",
    ".jpg",
    ".mp3",
    ".mp4",
    ".o",
    ".pdf",
    ".png",
    ".pyc",
    ".so",
    ".wasm",
    ".webp",
    ".woff",
    ".woff2",
    ".xz",
    ".zip",
}
MAX_FILES = 5000
MAX_BYTES = 1_000_000

RULES = (
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("private-key", re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("github-pat", re.compile(r"\bghp_[A-Za-z0-9]{36}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    (
        "hardcoded-secret",
        re.compile(
            r"(?i)\b(?:api[_-]?key|secret|passwd|password|token)\b\s*[:=]\s*['\"][^'\"]{8,}['\"]"
        ),
    ),
)

_RULE_KEYS = ("rule_id", "rule", "id", "check_id", "check")
_PATH_KEYS = ("path", "file", "filename")


@dataclass
class SecretHit:
    path: str
    rule_id: str
    line: int | None = None


def load_ignore(root: Path) -> list[str]:
    path = root / ".shieldwallignore"
    if not path.is_file():
        return []
    patterns: list[str] = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        patterns.append(line)
    return patterns


def path_ignored(rel: str, patterns: list[str]) -> bool:
    rel = rel.replace("\\", "/").lstrip("./")
    base = rel.rsplit("/", 1)[-1]
    if not rel or rel == ".shieldwallignore" or base == ".shieldwallignore":
        return True
    for raw in patterns:
        pat = raw.strip()
        if not pat or pat.startswith("#"):
            continue
        dir_only = pat.endswith("/")
        pat = pat.rstrip("/")
        if not pat:
            continue
        if dir_only:
            if rel == pat or rel.startswith(pat + "/") or base == pat:
                return True
            continue
        if fnmatch_path(rel, pat) or fnmatch_path(base, pat) or rel.startswith(pat + "/"):
            return True
    return False


def fnmatch_path(value: str, pat: str) -> bool:
    import fnmatch

    return fnmatch.fnmatch(value, pat)


def scan_file(path: Path, root: Path) -> list[SecretHit]:
    try:
        size = path.stat().st_size
    except OSError:
        return []
    if size > MAX_BYTES or path.suffix.lower() in SKIP_EXT:
        return []
    try:
        with path.open("rb") as handle:
            sample = handle.read(8192)
            if b"\x00" in sample:
                return []
            rest = handle.read(MAX_BYTES)
    except OSError:
        return []
    text = (sample + rest).decode("utf-8", "replace")
    rel = os.path.relpath(path, root).replace("\\", "/")
    hits: list[SecretHit] = []
    seen: set[str] = set()
    for rule_id, pattern in RULES:
        if rule_id in seen:
            continue
        for index, line in enumerate(text.splitlines(), start=1):
            if pattern.search(line):
                hits.append(SecretHit(path=rel, rule_id=rule_id, line=index))
                seen.add(rule_id)
                break
    return hits


def scan_tree(root: Path) -> tuple[list[SecretHit], bool]:
    if not root.exists():
        raise FileNotFoundError(str(root))
    if root.is_file():
        return scan_file(root, root.parent), False
    patterns = load_ignore(root)
    hits: list[SecretHit] = []
    scanned = 0
    truncated = False
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = os.path.relpath(dirpath, root).replace("\\", "/")
        if rel_dir == ".":
            rel_dir = ""
        kept = []
        for name in dirnames:
            rel = f"{rel_dir}/{name}" if rel_dir else name
            if name in SKIP_DIRS or path_ignored(rel, patterns):
                continue
            kept.append(name)
        dirnames[:] = kept
        for name in filenames:
            rel = f"{rel_dir}/{name}" if rel_dir else name
            if path_ignored(rel, patterns):
                continue
            scanned += 1
            if scanned > MAX_FILES:
                truncated = True
                return hits, truncated
            hits.extend(scan_file(Path(dirpath) / name, root))
    return hits, truncated


def parse_secretsweep(text: str) -> list[SecretHit]:
    data = json.loads(text)
    if isinstance(data, dict):
        rows = data.get("findings", data.get("results", data.get("hits", [])))
    elif isinstance(data, list):
        rows = data
    else:
        raise ValueError("secretsweep JSON was not a list or object")
    hits: list[SecretHit] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        path = ""
        for key in _PATH_KEYS:
            if row.get(key):
                path = str(row[key])
                break
        rule_id = ""
        for key in _RULE_KEYS:
            if row.get(key):
                rule_id = str(row[key])
                break
        if not path or not rule_id:
            continue
        line = row.get("line")
        try:
            line_no = int(line) if line is not None else None
        except (TypeError, ValueError):
            line_no = None
        hits.append(SecretHit(path=path, rule_id=rule_id, line=line_no))
    return hits


def secrets_plate(hits: list[SecretHit], root: str, source: str, truncated: bool = False) -> Plate:
    count = len(hits)
    if truncated and count == 0:
        return unknown_plate("secrets", "scan truncated before completion", "truncated")
    status = "intact" if count == 0 else "broken"
    evidence: list[str] = []
    for hit in hits[:50]:
        if hit.line:
            evidence.append(f"{hit.path}:{hit.line} {hit.rule_id}")
        else:
            evidence.append(f"{hit.path} {hit.rule_id}")
    if count > 50:
        evidence.append(f"{count - 50} more hits")
    if count == 0:
        evidence.append(f"no hits in {root}")
    if truncated:
        evidence.append("scan truncated")
    evidence.append(f"scanner: {source}")
    label = Path(root).name or str(root)
    return Plate(
        name="secrets",
        status=status,
        headline=f"{count} hits",
        detail=label[:14] or source,
        evidence=evidence,
    )


def collect_secrets(runner, path: str = ".", which=None) -> Plate:
    root = Path(path)
    lookup = which or shutil.which
    if lookup("secretsweep"):
        try:
            argv = secretsweep_argv(str(root))
        except ValueError as exc:
            return unknown_plate("secrets", str(exc), "bad path")
        result = runner.run(argv)
        if result.not_found:
            pass
        elif result.timed_out:
            return unknown_plate("secrets", "secretsweep timed out", "secretsweep")
        else:
            text = (result.stdout or "").strip()
            if text:
                try:
                    hits = parse_secretsweep(text)
                except (json.JSONDecodeError, ValueError):
                    if result.returncode not in (0, 1):
                        return unknown_plate(
                            "secrets",
                            f"secretsweep exited {result.returncode}",
                            "secretsweep",
                        )
                    return unknown_plate("secrets", "secretsweep JSON unreadable", "secretsweep")
                return secrets_plate(hits, str(root), "secretsweep")
            if result.returncode not in (0, 1):
                return unknown_plate(
                    "secrets",
                    f"secretsweep exited {result.returncode}",
                    "secretsweep",
                )
            return secrets_plate([], str(root), "secretsweep")
    try:
        hits, truncated = scan_tree(root)
    except FileNotFoundError:
        return unknown_plate("secrets", f"scan path not found: {path}", "no path")
    except PermissionError:
        return unknown_plate("secrets", f"permission denied: {path}", "unreadable")
    except OSError as exc:
        return unknown_plate("secrets", str(exc), "unreadable")
    return secrets_plate(hits, str(root), "builtin", truncated=truncated)
