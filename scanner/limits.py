"""Resource limits for scanning untrusted plugin repositories."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ScanLimits:
    """Bound resource consumption when scanning untrusted source trees."""

    max_file_size: int = 10 * 1024 * 1024
    max_total_size: int = 100 * 1024 * 1024
    max_files: int = 5000

    def __post_init__(self) -> None:
        if self.max_file_size <= 0 or self.max_total_size <= 0 or self.max_files <= 0:
            raise ValueError("scan resource limits must be positive")


def select_files(
    paths: list[Path], root: Path, limits: ScanLimits
) -> tuple[list[Path], list[dict[str, object]]]:
    """Select files without reading oversized content into memory."""
    selected: list[Path] = []
    skipped: list[dict[str, object]] = []
    total = 0
    for path in paths:
        try:
            size = path.stat().st_size
        except OSError:
            skipped.append({"file": str(path), "reason": "stat_failed"})
            continue
        rel = str(path.relative_to(root)).replace("\\", "/")
        if size > limits.max_file_size:
            skipped.append({"file": rel, "reason": "max_file_size", "size": size})
            continue
        if len(selected) >= limits.max_files:
            skipped.append({"file": rel, "reason": "max_files", "size": size})
            continue
        if total + size > limits.max_total_size:
            skipped.append({"file": rel, "reason": "max_total_size", "size": size})
            continue
        selected.append(path)
        total += size
    return selected, skipped
