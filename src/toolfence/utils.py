from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


URL_RE = re.compile(r"https?://[^\s\"'<>)]+", re.IGNORECASE)
TEXT_EXTENSIONS = {
    ".cfg",
    ".conf",
    ".env",
    ".json",
    ".jsonl",
    ".md",
    ".mjs",
    ".py",
    ".sh",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".yaml",
    ".yml",
    ".js",
    ".jsx",
}
SENSITIVE_KEY_PARTS = (
    "api_key",
    "apikey",
    "authorization",
    "auth_token",
    "credential",
    "password",
    "private_key",
    "secret",
    "token",
)


def now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def platform_label() -> str:
    return sys.platform


def hostname() -> str:
    return socket.gethostname()


def expand_path(value: str | Path, home: Path | None = None) -> Path:
    text = str(value)
    if home is not None and text.startswith("~/"):
        return home / text[2:]
    return Path(os.path.expandvars(os.path.expanduser(text)))


def sha256_file(path: Path, max_bytes: int | None = None) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        remaining = max_bytes
        while True:
            read_size = 1024 * 1024
            if remaining is not None:
                if remaining <= 0:
                    break
                read_size = min(read_size, remaining)
            chunk = handle.read(read_size)
            if not chunk:
                break
            digest.update(chunk)
            if remaining is not None:
                remaining -= len(chunk)
    return digest.hexdigest()


def stable_json_hash(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(encoded).hexdigest()


def safe_read_text(path: Path, max_bytes: int) -> str:
    data = path.read_bytes()[:max_bytes]
    return data.decode("utf-8", errors="replace")


def is_probably_text(path: Path) -> bool:
    return path.suffix.lower() in TEXT_EXTENSIONS or path.name in {
        "Dockerfile",
        "Makefile",
        "SKILL.md",
        "README",
        "requirements.txt",
    }


def iter_text_files(root: Path, max_files: int = 500) -> list[Path]:
    files: list[Path] = []
    for path in sorted(root.rglob("*")):
        if len(files) >= max_files:
            break
        if path.is_file() and is_probably_text(path):
            files.append(path)
    return files


def extract_urls(text: str) -> list[str]:
    return sorted(set(match.group(0).rstrip(".,") for match in URL_RE.finditer(text)))


def domain_from_url(url: str) -> str | None:
    parsed = urlparse(url)
    return parsed.hostname.lower() if parsed.hostname else None


def redact_sensitive(value: Any) -> Any:
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, nested in value.items():
            lowered = str(key).lower()
            if any(part in lowered for part in SENSITIVE_KEY_PARTS):
                redacted[str(key)] = "<redacted>"
            else:
                redacted[str(key)] = redact_sensitive(nested)
        return redacted
    if isinstance(value, list):
        return [redact_sensitive(item) for item in value]
    return value


def line_matches(text: str, pattern: re.Pattern[str]) -> list[tuple[int, str]]:
    matches: list[tuple[int, str]] = []
    for index, line in enumerate(text.splitlines(), start=1):
        if pattern.search(line):
            matches.append((index, line.strip()[:500]))
    return matches


def command_basename(command: str | None) -> str:
    if not command:
        return ""
    return Path(command.split()[0]).name.lower()

