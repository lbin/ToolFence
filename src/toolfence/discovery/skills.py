from __future__ import annotations

import json
import tomllib
from pathlib import Path
from typing import Any

from toolfence.models import SkillAsset
from toolfence.utils import extract_urls, iter_text_files, safe_read_text, sha256_file


SKILL_ROOT_CANDIDATES: tuple[tuple[str, str], ...] = (
    ("Claude", "~/.claude/skills"),
    ("Claude", "~/Library/Application Support/Claude/skills"),
    ("Codex", "~/.codex/skills"),
    ("Agent", "~/.agents/skills"),
    ("Codex", "~/.config/codex/skills"),
)

PROJECT_SKILL_DIRS = ("skills", ".skills", ".codex/skills", ".claude/skills", "agent/skills")
INSTRUCTION_NAMES = ("SKILL.md", "README.md", "instructions.md", "system.md", "prompt.md")
SCRIPT_SUFFIXES = {".py", ".js", ".mjs", ".ts", ".sh", ".bash", ".zsh"}
DEPENDENCY_NAMES = {
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "requirements.txt",
    "pyproject.toml",
    "uv.lock",
}


def discover_skills(
    home: Path,
    roots: list[Path],
    include_paths: list[Path] | None = None,
    max_file_bytes: int = 250_000,
    use_default_paths: bool = True,
) -> list[SkillAsset]:
    candidates: list[tuple[str, Path]] = []
    if use_default_paths:
        for source, path_text in SKILL_ROOT_CANDIDATES:
            candidates.append((source, Path(str(path_text).replace("~", str(home), 1))))
        for root in roots:
            for relative in PROJECT_SKILL_DIRS:
                candidates.append(("Project", root / relative))

    for include_path in include_paths or []:
        if include_path.is_dir():
            candidates.append(("Included", include_path))

    skills: dict[str, SkillAsset] = {}
    for source, candidate in candidates:
        for skill_path in _skill_dirs(candidate):
            try:
                skill = _build_skill(source, skill_path, max_file_bytes)
            except OSError:
                continue
            skills[skill.path] = skill
    return sorted(skills.values(), key=lambda skill: skill.path)


def _skill_dirs(candidate: Path) -> list[Path]:
    if not candidate.exists() or not candidate.is_dir():
        return []
    if _looks_like_skill(candidate):
        return [candidate]
    skills = []
    for child in sorted(candidate.iterdir()):
        if child.is_dir() and _looks_like_skill(child):
            skills.append(child)
    return skills


def _looks_like_skill(path: Path) -> bool:
    return any((path / name).exists() for name in INSTRUCTION_NAMES) or (path / "skill.json").exists()


def _build_skill(source: str, path: Path, max_file_bytes: int) -> SkillAsset:
    files = iter_text_files(path)
    instruction_files = []
    script_files = []
    dependency_files = []
    dependencies: set[str] = set()
    external_urls: set[str] = set()
    file_hashes = []

    for file_path in files:
        relative = str(file_path.relative_to(path))
        if file_path.name in INSTRUCTION_NAMES or "prompt" in file_path.name.lower():
            instruction_files.append(relative)
        if file_path.suffix.lower() in SCRIPT_SUFFIXES:
            script_files.append(relative)
        if file_path.name in DEPENDENCY_NAMES:
            dependency_files.append(relative)
            dependencies.update(_extract_dependencies(file_path, max_file_bytes))
        try:
            text = safe_read_text(file_path, max_file_bytes)
            external_urls.update(extract_urls(text))
            file_hashes.append(f"{relative}:{sha256_file(file_path, max_file_bytes)}")
        except OSError:
            continue

    fingerprint = sha256_file(path / "SKILL.md", max_file_bytes) if (path / "SKILL.md").exists() else None
    if file_hashes:
        import hashlib

        digest = hashlib.sha256()
        for item in sorted(file_hashes):
            digest.update(item.encode())
        fingerprint = digest.hexdigest()

    return SkillAsset(
        name=path.name,
        path=str(path),
        source=source,
        instruction_files=sorted(instruction_files),
        script_files=sorted(script_files),
        dependency_files=sorted(dependency_files),
        dependencies=sorted(dependencies),
        external_urls=sorted(external_urls),
        file_count=len(files),
        fingerprint=fingerprint,
    )


def _extract_dependencies(path: Path, max_file_bytes: int) -> set[str]:
    dependencies: set[str] = set()
    text = safe_read_text(path, max_file_bytes)
    if path.name == "requirements.txt":
        for line in text.splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                dependencies.add(stripped)
        return dependencies
    if path.name == "package.json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return dependencies
        for key in ("dependencies", "devDependencies", "optionalDependencies"):
            values = data.get(key)
            if isinstance(values, dict):
                dependencies.update(f"{name}@{version}" for name, version in values.items())
        return dependencies
    if path.name == "pyproject.toml":
        try:
            data: dict[str, Any] = tomllib.loads(text)
        except tomllib.TOMLDecodeError:
            return dependencies
        project = data.get("project")
        if isinstance(project, dict):
            values = project.get("dependencies")
            if isinstance(values, list):
                dependencies.update(str(item) for item in values)
    return dependencies

