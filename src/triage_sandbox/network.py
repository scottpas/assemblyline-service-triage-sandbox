from typing import Any

from assemblyline.odm.models.ontology.results.network import LOOKUP_TYPES


def _normalize_dns_lookup_type(raw: Any) -> str | None:
    """Accept a record type, optionally preceded by a recognized DNS class."""
    if not isinstance(raw, str):
        return None
    parts = raw.upper().split()
    if len(parts) == 2 and parts[0] in {"IN", "CS", "CH", "HS", "NONE", "ANY"}:
        parts = parts[1:]
    if len(parts) == 1 and parts[0] in LOOKUP_TYPES:
        return parts[0]
    return None


def _split_addr(addr: str) -> tuple[str, int]:
    """Parse 'ip:port' or '[ipv6]:port' into (ip_str, port_int)."""
    if addr.startswith("["):
        ip = addr[1 : addr.index("]")]
        port = int(addr[addr.index("]") + 2 :])
    else:
        ip, port_str = addr.rsplit(":", 1)
        port = int(port_str)
    return ip, port


def _parse_http_headers(headers: Any) -> dict[str, str]:
    """Parse Triage HTTP headers (list of 'name: value' strings or dicts) into a dict."""
    result: dict[str, str] = {}
    for h in headers or []:
        if isinstance(h, dict):
            result[h.get("name", "")] = h.get("value", "")
        elif isinstance(h, str):
            name, _, value = h.partition(": ")
            if name:
                result[name] = value
    return result
