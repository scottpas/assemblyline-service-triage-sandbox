"""Convert non-configuration ``extracted`` records for behavioral and overview reports alike."""

import json
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ExtractedEvidence:
    """One distinct extracted record plus every place it was reported from."""

    kind: str
    key: str
    details: dict[str, Any]
    paths: list[str] = field(default_factory=list)
    resources: list[str] = field(default_factory=list)
    tasks: list[str] = field(default_factory=list)

    def merge_context(self, other: "ExtractedEvidence") -> None:
        """Retain the provenance of an equivalent record without repeating its evidence."""
        for mine, theirs in ((self.paths, other.paths), (self.resources, other.resources), (self.tasks, other.tasks)):
            mine.extend(value for value in theirs if value not in mine)


def clean_text(value: Any) -> str | None:
    """Return displayable text; Triage note and script dumps can carry NUL padding."""
    if not isinstance(value, str):
        return None
    return value.replace("\x00", "").strip() or None


def _strings(value: Any) -> list[str]:
    """Return the non-empty strings of an untrusted string-or-list field."""
    values = value if isinstance(value, list) else [value]
    return [v for v in values if isinstance(v, str) and v]


def _dropper_details(record: dict[str, Any]) -> dict[str, Any] | None:
    urls: dict[tuple[str, str], dict[str, str]] = {}
    entries = record.get("urls")
    for entry in entries if isinstance(entries, list) else []:
        url = clean_text(entry.get("url")) if isinstance(entry, dict) else None
        if url:
            url_type = clean_text(entry.get("type")) or ""
            urls.setdefault((url_type, url), {"Type": url_type, "URL": url})
    source = clean_text(record.get("source"))
    deobfuscated = clean_text(record.get("deobfuscated"))
    if not (urls or source or deobfuscated):
        return None
    return {
        "language": clean_text(record.get("language")),
        "source": source,
        "deobfuscated": deobfuscated,
        "urls": list(urls.values()),
    }


def convert_extracted(item: Any, stage: str) -> tuple[list[ExtractedEvidence], list[str]]:
    """Convert the non-configuration records of one extracted item.

    Records are untrusted, so one that cannot be converted produces a diagnostic and
    leaves the others intact. Values are never echoed into the diagnostic.
    """
    evidence: list[ExtractedEvidence] = []
    diagnostics: list[str] = []
    if not isinstance(item, dict):
        return evidence, diagnostics
    record = item.get("dropper")
    if record:
        if isinstance(record, dict):
            details = _dropper_details(record)
            if details is not None:
                evidence.append(
                    ExtractedEvidence(
                        kind="dropper",
                        key=json.dumps(["dropper", record], sort_keys=True, default=str),
                        details=details,
                        paths=_strings(item.get("path")),
                        resources=_strings(item.get("resource")),
                        tasks=_strings(item.get("tasks")),
                    )
                )
        else:
            diagnostics.append(f"{stage}: invalid dropper record.")
    return evidence, diagnostics
