"""Convert non-configuration ``extracted`` records for behavioral and overview reports alike."""

import json
from dataclasses import dataclass, field, fields
from typing import Any

from assemblyline.odm.models.ontology.results.malware_config import MalwareConfig

from .models import Ransom, clean_text, string_values


@dataclass
class ExtractedEvidence:
    """One distinct extracted record plus every place it was reported from."""

    kind: str
    key: str
    details: dict[str, Any]
    paths: list[str] = field(default_factory=list)
    resources: list[str] = field(default_factory=list)
    tasks: list[str] = field(default_factory=list)
    malware_config: MalwareConfig | None = None

    def merge_context(self, other: "ExtractedEvidence") -> None:
        """Retain the provenance of an equivalent record without repeating its evidence."""
        for mine, theirs in ((self.paths, other.paths), (self.resources, other.resources), (self.tasks, other.tasks)):
            mine.extend(value for value in theirs if value not in mine)


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


def _ransom_details(record: dict[str, Any]) -> tuple[dict[str, Any], MalwareConfig]:
    accepted = {f.name for f in fields(Ransom)}
    ransom = Ransom(**{k: v for k, v in record.items() if k in accepted})
    malware_config = ransom.create_MalwareConfig()
    emails, urls = ransom.indicators()
    return (
        {
            "family": clean_text(ransom.family),
            "target": clean_text(ransom.target),
            "note": clean_text(ransom.note),
            "rows": ransom.contact_rows(),
            "emails": emails,
            "urls": urls,
        },
        malware_config,
    )


def convert_extracted(item: Any, stage: str) -> tuple[list[ExtractedEvidence], list[str]]:
    """Convert the non-configuration records of one extracted item.

    Records are untrusted, so one that cannot be converted produces a diagnostic and
    leaves the others intact. Values are never echoed into the diagnostic.
    """
    evidence: list[ExtractedEvidence] = []
    diagnostics: list[str] = []
    if not isinstance(item, dict):
        return evidence, diagnostics

    def add(kind: str, record: Any, details: dict[str, Any], malware_config: MalwareConfig | None = None) -> None:
        evidence.append(
            ExtractedEvidence(
                kind=kind,
                key=json.dumps([kind, record], sort_keys=True, default=str),
                details=details,
                paths=string_values(item.get("path")),
                resources=string_values(item.get("resource")),
                tasks=string_values(item.get("tasks")),
                malware_config=malware_config,
            )
        )

    record = item.get("dropper")
    if record:
        if isinstance(record, dict):
            details = _dropper_details(record)
            if details is not None:
                add("dropper", record, details)
        else:
            diagnostics.append(f"{stage}: invalid dropper record.")
    record = item.get("ransom_note")
    if record:
        try:
            details, malware_config = _ransom_details(record)
        except Exception as exc:
            # ODM validation can raise several exception types on untrusted values.
            diagnostics.append(f"{stage}: invalid ransom note ({type(exc).__name__}).")
        else:
            add("ransom_note", record, details, malware_config)
    return evidence, diagnostics
